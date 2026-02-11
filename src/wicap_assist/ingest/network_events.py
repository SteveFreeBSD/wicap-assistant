"""Ingest WiCAP network event contract streams into assistant evidence store."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.db import delete_log_events_for_source, get_source, insert_log_event, upsert_source
from wicap_assist.util.redact import sha1_text, to_snippet
from wicap_assist.util.evidence import normalize_signature

NETWORK_EVENT_PATTERNS = (
    "captures/wicap_network_events.jsonl",
    "captures/wicap_anomaly_events.jsonl",
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

    category = str(payload.get("category") or payload.get("event_type") or "network_event").strip().lower()
    if not category:
        category = "network_event"
    if "anomaly" in category or category in {"alert", "wids_alert"}:
        category = "network_anomaly"
    elif category in {"flow", "conn"}:
        category = "network_flow"

    signature = str(payload.get("signature") or payload.get("event_type") or category).strip()
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
    if "explanation" in payload:
        extra_json["explanation"] = payload.get("explanation")
    if "sensor_id" in payload:
        extra_json["sensor_id"] = payload.get("sensor_id")
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
    return len(files), events_added
