"""Deterministic semantic retrieval over control episode memory."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any

from wicap_assist.evidence_query import signature_tokens, where_like
from wicap_assist.util.evidence import normalize_signature, parse_utc_datetime


def _json_load_dict(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _text_blob_for_match(row: sqlite3.Row) -> str:
    parts = [
        str(row["decision"] or ""),
        str(row["action"] or ""),
        str(row["status"] or ""),
        str(row["pre_state_json"] or ""),
        str(row["post_state_json"] or ""),
        str(row["metadata_json"] or ""),
        str(row["payload_json"] or ""),
        str(row["outcome"] or ""),
        str(row["outcome_detail_json"] or ""),
    ]
    return " ".join(part for part in parts if part).lower()


def _as_utc_sort_key(ts_text: str | None) -> datetime:
    parsed = parse_utc_datetime(ts_text)
    if parsed is None:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    return parsed


def _extract_primary_service(payload: dict[str, Any], pre_state: dict[str, Any]) -> str | None:
    service = payload.get("service")
    if isinstance(service, str) and service.strip():
        return service.strip()

    down_services = pre_state.get("down_services")
    if isinstance(down_services, list):
        for item in down_services:
            value = str(item).strip()
            if value:
                return value
    return None


def _extract_primary_signature(pre_state: dict[str, Any]) -> str:
    top = pre_state.get("top_signatures")
    if isinstance(top, list):
        for item in top:
            if not isinstance(item, dict):
                continue
            signature = str(item.get("signature", "")).strip()
            if signature:
                return signature
    return ""


def _score_memory_candidate(
    *,
    text_blob: str,
    tokens: list[str],
    target_norm: str,
    status: str,
    outcome: str,
) -> tuple[int, list[str]]:
    matched_tokens = [token for token in tokens if token in text_blob]
    score = len(matched_tokens) * 10

    normalized_blob = normalize_signature(text_blob, max_len=512)
    if target_norm and target_norm in normalized_blob:
        score += 20

    normalized_status = str(status).strip().lower()
    normalized_outcome = str(outcome).strip().lower()
    if normalized_status == "executed_ok" or normalized_outcome in {"executed_ok", "pass"}:
        score += 4
    elif normalized_status in {"executed_fail", "escalated"} or normalized_outcome in {"executed_fail", "fail"}:
        score -= 2

    return int(score), matched_tokens


def retrieve_episode_memories(
    conn: sqlite3.Connection,
    signature: str,
    *,
    limit: int = 3,
    candidate_limit: int = 120,
) -> list[dict[str, Any]]:
    """Return top-k related control episodes for a target signature."""
    target = str(signature).strip()
    if not target:
        return []

    tokens = signature_tokens(target, limit=8)
    if not tokens:
        return []

    where, args = where_like(
        "ep.pre_state_json || ' ' || ep.post_state_json || ' ' || ep.metadata_json || ' ' || "
        "coalesce(ev.payload_json, '') || ' ' || coalesce(eo.detail_json, '') || ' ' || "
        "ep.decision || ' ' || coalesce(ep.action, '') || ' ' || ep.status",
        tokens,
    )
    if not where:
        return []

    rows = conn.execute(
        f"""
        SELECT
            ep.id,
            ep.ts_started,
            ep.decision,
            ep.action,
            ep.status,
            ep.pre_state_json,
            ep.post_state_json,
            ep.metadata_json,
            ev.payload_json,
            eo.outcome,
            eo.detail_json AS outcome_detail_json
        FROM episodes AS ep
        LEFT JOIN episode_events AS ev ON ev.episode_id = ep.id
        LEFT JOIN episode_outcomes AS eo ON eo.episode_id = ep.id
        WHERE ({where})
        ORDER BY coalesce(ep.ts_started, '') DESC, ep.id DESC
        LIMIT ?
        """,
        [*args, max(1, int(candidate_limit))],
    ).fetchall()
    if not rows:
        return []

    target_norm = normalize_signature(target, max_len=160)
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        episode_id = int(row["id"])
        text_blob = _text_blob_for_match(row)
        match_score, matched_tokens = _score_memory_candidate(
            text_blob=text_blob,
            tokens=tokens,
            target_norm=target_norm,
            status=str(row["status"] or ""),
            outcome=str(row["outcome"] or ""),
        )
        if match_score <= 0 or not matched_tokens:
            continue

        existing = out.get(episode_id)
        if existing is not None and int(existing["match_score"]) >= int(match_score):
            continue

        payload = _json_load_dict(row["payload_json"])
        pre_state = _json_load_dict(row["pre_state_json"])
        service = _extract_primary_service(payload, pre_state)
        primary_signature = _extract_primary_signature(pre_state)

        out[episode_id] = {
            "episode_id": episode_id,
            "ts_started": str(row["ts_started"] or ""),
            "decision": str(row["decision"] or ""),
            "action": str(row["action"] or "") if row["action"] is not None else None,
            "status": str(row["status"] or ""),
            "outcome": str(row["outcome"] or ""),
            "service": service,
            "signature": primary_signature,
            "match_score": int(match_score),
            "matched_tokens": matched_tokens,
        }

    ranked = sorted(
        out.values(),
        key=lambda item: (
            int(item["match_score"]),
            _as_utc_sort_key(str(item.get("ts_started", "") or "")),
            int(item["episode_id"]),
        ),
        reverse=True,
    )
    return ranked[: max(1, int(limit))]
