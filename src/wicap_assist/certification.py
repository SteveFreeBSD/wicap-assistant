"""Replay/chaos certification helpers for rollout gates."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from wicap_assist.db import insert_certification_run, list_recent_certification_runs
from wicap_assist.util.time import utc_now_iso


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def run_replay_certification(conn: sqlite3.Connection, *, profile: str) -> dict[str, Any]:
    """Compute deterministic replay score from recent decision-feature traces."""
    rows = conn.execute(
        """
        SELECT feature_json
        FROM decision_features
        ORDER BY id DESC
        LIMIT 500
        """
    ).fetchall()
    signatures: dict[str, int] = {}
    for row in rows:
        raw = row["feature_json"]
        if not isinstance(raw, str) or not raw.strip():
            continue
        signatures[raw] = signatures.get(raw, 0) + 1
    sample_count = sum(signatures.values())
    dominant = max(signatures.values()) if signatures else 0
    score = 0.0
    if sample_count > 0:
        score = float(dominant) / float(sample_count)
    passed = bool(score >= 0.99)
    ts = utc_now_iso()
    insert_certification_run(
        conn,
        ts=ts,
        cert_type="replay",
        profile=str(profile),
        passed=passed,
        score=round(score, 6),
        detail_json={
            "sample_count": int(sample_count),
            "dominant_count": int(dominant),
            "distinct_signatures": int(len(signatures)),
            "target": 0.99,
        },
    )
    return {
        "ts": ts,
        "cert_type": "replay",
        "profile": str(profile),
        "pass": passed,
        "score": round(score, 6),
        "sample_count": int(sample_count),
        "target": 0.99,
    }


def run_chaos_certification(conn: sqlite3.Connection, *, profile: str) -> dict[str, Any]:
    """Compute degraded-cycle rate from recent control events."""
    rows = conn.execute(
        """
        SELECT status
        FROM control_events
        ORDER BY id DESC
        LIMIT 2000
        """
    ).fetchall()
    total = len(rows)
    degraded = 0
    for row in rows:
        status = str(row["status"] or "").strip().lower()
        if status in {"executed_fail", "escalated", "rejected", "failed"}:
            degraded += 1
    degraded_rate = float(degraded) / float(total) if total > 0 else 0.0
    score = max(0.0, 1.0 - degraded_rate)
    passed = bool(degraded_rate <= 0.05)
    ts = utc_now_iso()
    insert_certification_run(
        conn,
        ts=ts,
        cert_type="chaos",
        profile=str(profile),
        passed=passed,
        score=round(score, 6),
        detail_json={
            "sample_count": int(total),
            "degraded_count": int(degraded),
            "degraded_rate": round(degraded_rate, 6),
            "max_degraded_rate": 0.05,
        },
    )
    return {
        "ts": ts,
        "cert_type": "chaos",
        "profile": str(profile),
        "pass": passed,
        "score": round(score, 6),
        "sample_count": int(total),
        "degraded_rate": round(degraded_rate, 6),
        "max_degraded_rate": 0.05,
    }


def certification_history(conn: sqlite3.Connection, *, cert_type: str | None = None, profile: str | None = None) -> dict[str, Any]:
    """Return latest certification runs for CLI surfaces."""
    rows = list_recent_certification_runs(conn, cert_type=cert_type, profile=profile, limit=50)
    out: list[dict[str, Any]] = []
    for row in rows:
        detail = {}
        raw = row["detail_json"]
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                detail = parsed
        out.append(
            {
                "ts": row["ts"],
                "cert_type": row["cert_type"],
                "profile": row["profile"],
                "pass": bool(row["pass"]),
                "score": _safe_float(row["score"]),
                "detail": detail,
            }
        )
    return {
        "count": int(len(out)),
        "rows": out,
    }
