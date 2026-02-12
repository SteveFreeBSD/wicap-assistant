"""Ingest WiCAP network event contract streams into assistant evidence store."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.db import (
    delete_drift_events_for_source,
    delete_forecast_events_for_source,
    delete_log_events_for_source,
    delete_model_shadow_metrics_for_source,
    get_source,
    insert_drift_event,
    insert_forecast_event,
    insert_log_event,
    insert_model_shadow_metric,
    upsert_source,
)
from wicap_assist.util.redact import sha1_text, to_snippet
from wicap_assist.util.evidence import normalize_signature

NETWORK_EVENT_PATTERNS = (
    "captures/wicap_network_events.jsonl",
    "captures/wicap_anomaly_events.jsonl",
    "captures/wicap_anomaly_events_v2.jsonl",
    "captures/wicap_anomaly_events_v3.jsonl",
    "captures/wicap_anomaly_feedback.jsonl",
    "captures/wicap_predictions.jsonl",
    "captures/suricata_eve_compat.jsonl",
    "captures/zeek_conn_compat.jsonl",
)


@dataclass(slots=True)
class ParsedNetworkEvent:
    ts_text: str | None
    category: str
    fingerprint: str
    snippet: str
    file_path: str
    extra_json: dict[str, Any]


def _is_unchanged_source(row: sqlite3.Row | None, *, mtime: float, size: int) -> bool:
    if row is None:
        return False
    return (
        str(row["kind"]) == "network_event_log"
        and float(row["mtime"]) == float(mtime)
        and int(row["size"]) == int(size)
    )


def scan_network_event_paths(repo_root: Path | None = None) -> list[Path]:
    """Return existing network event artifact paths under the WiCAP repo."""
    root = (repo_root or wicap_repo_root()).resolve()
    out: list[Path] = []
    for pattern in NETWORK_EVENT_PATTERNS:
        path = root / pattern
        if path.exists() and path.is_file():
            out.append(path)
    return out


def _parse_one_record(payload: dict[str, Any], *, file_path: Path, line_number: int) -> ParsedNetworkEvent:
    ts_text = None
    if isinstance(payload.get("ts"), str):
        ts_text = str(payload.get("ts"))
    elif isinstance(payload.get("timestamp"), str):
        ts_text = str(payload.get("timestamp"))

    feedback_version = str(payload.get("feedback_contract_version", "")).strip().lower()
    prediction_version = str(payload.get("prediction_contract_version", "")).strip().lower()
    anomaly_version = str(payload.get("anomaly_contract_version", "")).strip().lower()
    category = str(payload.get("category") or payload.get("event_type") or "network_event").strip().lower()
    if not category:
        category = "network_event"
    if feedback_version == "wicap.feedback.v1":
        category = "network_anomaly_feedback"
    elif prediction_version == "wicap.prediction.v1":
        category = "network_prediction"
    elif "anomaly" in category or category in {"alert", "wids_alert"}:
        category = "network_anomaly"
    elif category in {"flow", "conn"}:
        category = "network_flow"

    signature = str(payload.get("signature") or payload.get("alert_id") or payload.get("event_type") or category).strip()
    normalized_signature = normalize_signature(signature) or sha1_text(signature)[:16]
    snippet = to_snippet(signature or category, max_len=200)
    fingerprint = sha1_text(f"{category}|{normalized_signature}|{snippet}")
    extra_json: dict[str, Any] = {
        "line_number": int(line_number),
        "source_type": "network_event_contract",
    }
    if isinstance(payload.get("flow"), dict):
        extra_json["flow"] = payload.get("flow")
    if "severity" in payload:
        extra_json["severity"] = payload.get("severity")
    if "score" in payload:
        extra_json["score"] = payload.get("score")
    if "confidence" in payload:
        extra_json["confidence"] = payload.get("confidence")
    if "baseline_maturity" in payload:
        extra_json["baseline_maturity"] = payload.get("baseline_maturity")
    if "primary_score" in payload:
        extra_json["primary_score"] = payload.get("primary_score")
    if "fusion_score" in payload:
        extra_json["fusion_score"] = payload.get("fusion_score")
    if "predictive_horizon_sec" in payload:
        extra_json["predictive_horizon_sec"] = payload.get("predictive_horizon_sec")
    if "route_confidence" in payload:
        extra_json["route_confidence"] = payload.get("route_confidence")
    if "drift_guard" in payload:
        extra_json["drift_guard"] = payload.get("drift_guard")
    if "shadow_scores" in payload:
        extra_json["shadow_scores"] = payload.get("shadow_scores")
    if "model_votes" in payload:
        extra_json["model_votes"] = payload.get("model_votes")
    if "vote_agreement" in payload:
        extra_json["vote_agreement"] = payload.get("vote_agreement")
    if "score_components" in payload:
        extra_json["score_components"] = payload.get("score_components")
    if "drift_state" in payload:
        extra_json["drift_state"] = payload.get("drift_state")
    if "explanation" in payload:
        extra_json["explanation"] = payload.get("explanation")
    if "sensor_id" in payload:
        extra_json["sensor_id"] = payload.get("sensor_id")
    if anomaly_version:
        extra_json["anomaly_contract_version"] = anomaly_version
    if "feedback_contract_version" in payload:
        extra_json["feedback_contract_version"] = payload.get("feedback_contract_version")
    if "label" in payload:
        extra_json["feedback_label"] = payload.get("label")
    if "attack_type" in payload:
        extra_json["attack_type"] = payload.get("attack_type")
    if "attack_id" in payload:
        extra_json["attack_id"] = payload.get("attack_id")
    if prediction_version:
        extra_json["prediction_contract_version"] = prediction_version
    if "risk_score" in payload:
        extra_json["risk_score"] = payload.get("risk_score")
    if "horizon_sec" in payload:
        extra_json["horizon_sec"] = payload.get("horizon_sec")
    if "top_contributors" in payload:
        extra_json["top_contributors"] = payload.get("top_contributors")
    if "confidence_band" in payload:
        extra_json["confidence_band"] = payload.get("confidence_band")
    if "evidence_refs" in payload:
        extra_json["evidence_refs"] = payload.get("evidence_refs")
    if isinstance(payload.get("evidence_ref"), dict):
        extra_json["evidence_ref"] = payload.get("evidence_ref")

    return ParsedNetworkEvent(
        ts_text=ts_text,
        category=category,
        fingerprint=fingerprint,
        snippet=snippet,
        file_path=str(file_path),
        extra_json=extra_json,
    )


def parse_network_event_file(path: Path) -> list[ParsedNetworkEvent]:
    """Parse one network event JSONL file into log event rows."""
    out: list[ParsedNetworkEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                continue
            try:
                import json

                payload = json.loads(text)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            out.append(_parse_one_record(payload, file_path=path, line_number=line_number))
    return out


def _as_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _forecast_band(extra_json: dict[str, Any]) -> tuple[float | None, float | None]:
    confidence = extra_json.get("confidence_band")
    if not isinstance(confidence, dict):
        return None, None
    return _as_float(confidence.get("low")), _as_float(confidence.get("high"))


def _insert_specialized_rows(conn: sqlite3.Connection, event: ParsedNetworkEvent) -> None:
    category = str(event.category).strip()
    extra = event.extra_json if isinstance(event.extra_json, dict) else {}
    ts = str(event.ts_text or "")
    source = str(event.file_path)
    if not ts:
        return

    if category == "network_prediction":
        low, high = _forecast_band(extra)
        insert_forecast_event(
            conn,
            ts=ts,
            source=source,
            horizon_sec=int(_as_int(extra.get("horizon_sec")) or 0),
            risk_score=float(_as_float(extra.get("risk_score")) or 0.0),
            confidence_low=low,
            confidence_high=high,
            signature=str(event.snippet).strip() or None,
            summary=str(extra.get("summary", "")).strip() or None,
            payload_json=extra,
        )
        return

    if category != "network_anomaly":
        return

    drift = extra.get("drift_state")
    if isinstance(drift, dict):
        insert_drift_event(
            conn,
            ts=ts,
            source=source,
            status=str(drift.get("status", "stable")).strip() or "stable",
            delta=float(_as_float(drift.get("delta")) or 0.0),
            long_mean=_as_float(drift.get("long_mean")),
            short_mean=_as_float(drift.get("short_mean")),
            sample_count=_as_int(drift.get("sample_count")),
            payload_json=drift,
        )

    shadow_scores = extra.get("shadow_scores")
    if not isinstance(shadow_scores, dict) or not shadow_scores:
        return
    votes = extra.get("model_votes")
    vote_map = votes if isinstance(votes, dict) else {}
    agreement = _as_float(extra.get("vote_agreement"))
    for model_id, raw_score in shadow_scores.items():
        score = _as_float(raw_score)
        vote_value = vote_map.get(model_id, 0)
        insert_model_shadow_metric(
            conn,
            ts=ts,
            source=source,
            decision="network_anomaly_shadow",
            action=None,
            model_id=str(model_id),
            score=score,
            vote=int(_as_int(vote_value) or 0),
            agreement=agreement,
            payload_json={
                "event_fingerprint": event.fingerprint,
                "attack_type": extra.get("attack_type"),
                "drift_state": drift if isinstance(drift, dict) else None,
            },
        )


def ingest_network_events(conn: sqlite3.Connection, repo_root: Path | None = None) -> tuple[int, int]:
    """Ingest network event JSONL artifacts into `log_events`."""
    files = scan_network_event_paths(repo_root=repo_root)
    events_added = 0
    for file_path in files:
        stat = file_path.stat()
        source_row = get_source(conn, str(file_path))
        if _is_unchanged_source(source_row, mtime=stat.st_mtime, size=stat.st_size):
            continue

        source_id = upsert_source(
            conn,
            kind="network_event_log",
            path=str(file_path),
            mtime=stat.st_mtime,
            size=stat.st_size,
        )
        delete_log_events_for_source(conn, source_id)
        delete_forecast_events_for_source(conn, str(file_path))
        delete_drift_events_for_source(conn, str(file_path))
        delete_model_shadow_metrics_for_source(conn, str(file_path))
        for event in parse_network_event_file(file_path):
            inserted = insert_log_event(
                conn,
                source_id=source_id,
                ts_text=event.ts_text,
                category=event.category,
                fingerprint=event.fingerprint,
                snippet=event.snippet,
                file_path=event.file_path,
                extra_json=event.extra_json,
            )
            if inserted:
                events_added += 1
                _insert_specialized_rows(conn, event)
    return len(files), events_added
