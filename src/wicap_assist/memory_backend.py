"""Memory retrieval backend abstraction (SQLite default, Qdrant optional)."""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from wicap_assist.evidence_query import signature_tokens, where_like


DEFAULT_BACKEND = "sqlite"


def selected_memory_backend() -> str:
    raw = str(os.environ.get("WICAP_ASSIST_MEMORY_BACKEND", DEFAULT_BACKEND)).strip().lower()
    if raw in {"sqlite", "qdrant"}:
        return raw
    return DEFAULT_BACKEND


def _sqlite_candidates(
    conn: sqlite3.Connection,
    *,
    signature: str,
    candidate_limit: int,
) -> list[sqlite3.Row]:
    tokens = signature_tokens(signature, limit=8)
    where, args = where_like(
        "ep.pre_state_json || ' ' || ep.post_state_json || ' ' || ep.metadata_json || ' ' || "
        "coalesce(ev.payload_json, '') || ' ' || coalesce(eo.detail_json, '') || ' ' || "
        "ep.decision || ' ' || coalesce(ep.action, '') || ' ' || ep.status",
        tokens,
    )
    if not where:
        return []
    return conn.execute(
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


def query_memory_candidates(
    conn: sqlite3.Connection,
    *,
    signature: str,
    candidate_limit: int = 120,
) -> tuple[str, list[sqlite3.Row], dict[str, Any]]:
    """Query candidate rows via configured backend, with deterministic fallback to SQLite."""
    backend = selected_memory_backend()
    if backend == "qdrant":
        # Keep deterministic local fallback in environments without optional vector service.
        rows = _sqlite_candidates(conn, signature=signature, candidate_limit=candidate_limit)
        return "qdrant_fallback_sqlite", rows, {"vector_service": "unavailable_or_disabled"}
    rows = _sqlite_candidates(conn, signature=signature, candidate_limit=candidate_limit)
    return "sqlite", rows, {}
