"""Scheduled memory maintenance and reflection summaries."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from wicap_assist.db import insert_memory_compaction, update_control_session
from wicap_assist.util.evidence import parse_utc_datetime
from wicap_assist.util.time import utc_now_iso


def _parse_feature_json(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(value, dict):
        return value
    return {}


def _parse_metadata_json(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(value, dict):
        return value
    return {}


def _safe_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _working_memory_state(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("working_memory")
    if isinstance(value, dict):
        return dict(value)
    return {}


def run_memory_maintenance(
    conn: sqlite3.Connection,
    *,
    lookback_days: int = 14,
    stale_days: int = 7,
    max_decision_rows: int = 5000,
    max_session_rows: int = 500,
    max_recent_transitions: int = 24,
    prune_stale: bool = False,
    now_ts: str | None = None,
) -> dict[str, Any]:
    """Generate deterministic memory reflection report and optional stale pruning."""
    now_text = str(now_ts or utc_now_iso())
    now_dt = parse_utc_datetime(now_text) or datetime.now(timezone.utc)
    lookback_cutoff = now_dt - timedelta(days=max(1, int(lookback_days)))
    stale_cutoff = now_dt - timedelta(days=max(1, int(stale_days)))

    decision_rows = conn.execute(
        """
        SELECT ts, action, status, feature_json
        FROM decision_features
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, int(max_decision_rows)),),
    ).fetchall()

    decision_count = 0
    rewards: list[float] = []
    action_stats: dict[str, dict[str, float]] = defaultdict(
        lambda: {"count": 0.0, "success": 0.0, "reward_sum": 0.0}
    )
    for row in decision_rows:
        ts_dt = parse_utc_datetime(row["ts"])
        if ts_dt is None or ts_dt < lookback_cutoff:
            continue
        decision_count += 1
        action = str(row["action"] or "").strip() or "none"
        status = str(row["status"] or "").strip().lower()
        feature = _parse_feature_json(row["feature_json"])
        reward_value = _safe_float(feature.get("reward_value", 0.0))
        rewards.append(reward_value)
        bucket = action_stats[action]
        bucket["count"] += 1.0
        bucket["reward_sum"] += reward_value
        if status == "executed_ok":
            bucket["success"] += 1.0

    action_health: list[dict[str, Any]] = []
    drift_labels: list[dict[str, Any]] = []
    for action in sorted(action_stats.keys()):
        stats = action_stats[action]
        count = int(stats["count"])
        success_rate = (stats["success"] / stats["count"]) if stats["count"] > 0 else 0.0
        avg_reward = (stats["reward_sum"] / stats["count"]) if stats["count"] > 0 else 0.0
        health = {
            "action": action,
            "count": count,
            "success_rate": round(float(success_rate), 4),
            "avg_reward": round(float(avg_reward), 4),
        }
        action_health.append(health)

        if count < 5:
            label = "insufficient_data"
        elif success_rate < 0.5 or avg_reward < -0.05:
            label = "regressed"
        elif success_rate >= 0.8 and avg_reward >= 0.1:
            label = "stable"
        else:
            label = "watch"
        drift_labels.append({"action": action, "label": label, **health})

    session_rows = conn.execute(
        """
        SELECT id, ended_ts, metadata_json
        FROM control_sessions
        WHERE ended_ts IS NOT NULL
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, int(max_session_rows)),),
    ).fetchall()

    stale_sessions: list[dict[str, Any]] = []
    pruned_ids: list[int] = []
    compacted_session_ids: list[int] = []
    compacted_rows = 0
    for row in session_rows:
        ended_dt = parse_utc_datetime(row["ended_ts"])
        if ended_dt is None or ended_dt >= stale_cutoff:
            continue
        metadata = _parse_metadata_json(row["metadata_json"])
        working_memory = _working_memory_state(metadata)
        unresolved = working_memory.get("unresolved_signatures")
        pending = working_memory.get("pending_actions")
        unresolved_count = len(unresolved) if isinstance(unresolved, list) else 0
        pending_count = len(pending) if isinstance(pending, list) else 0
        if unresolved_count <= 0 and pending_count <= 0:
            recent = working_memory.get("recent_transitions")
            if isinstance(recent, list) and len(recent) > int(max_recent_transitions):
                overflow = len(recent) - int(max_recent_transitions)
                compacted_rows += int(max(0, overflow))
                working_memory["recent_transitions"] = recent[-int(max_recent_transitions) :]
                update_control_session(
                    conn,
                    control_session_id=int(row["id"]),
                    metadata_json={
                        "working_memory": working_memory,
                        "memory_compaction": {
                            "last_compacted_ts": now_text,
                            "compacted_rows": int(max(0, overflow)),
                            "policy": "tail_keep",
                        },
                    },
                )
                compacted_session_ids.append(int(row["id"]))
            continue

        session_id = int(row["id"])
        stale_sessions.append(
            {
                "control_session_id": session_id,
                "ended_ts": str(row["ended_ts"]),
                "unresolved_count": int(unresolved_count),
                "pending_count": int(pending_count),
            }
        )
        if prune_stale:
            working_memory["unresolved_signatures"] = []
            working_memory["pending_actions"] = []
            working_memory["recent_transitions"] = []
            update_control_session(
                conn,
                control_session_id=session_id,
                metadata_json={
                    "working_memory": working_memory,
                    "memory_maintenance": {
                        "last_pruned_ts": now_text,
                        "reason": "stale_working_memory",
                    },
                },
            )
            pruned_ids.append(session_id)

    if compacted_rows > 0:
        insert_memory_compaction(
            conn,
            ts=now_text,
            control_session_id=None,
            compacted_rows=int(compacted_rows),
            summary_json={
                "session_ids": compacted_session_ids[:100],
                "max_recent_transitions": int(max_recent_transitions),
            },
        )

    if prune_stale or compacted_rows > 0:
        conn.commit()

    avg_reward = 0.0 if not rewards else (sum(rewards) / float(len(rewards)))
    return {
        "generated_ts": now_text,
        "lookback_days": int(max(1, int(lookback_days))),
        "stale_days": int(max(1, int(stale_days))),
        "decision_rows_analyzed": int(decision_count),
        "avg_reward": round(float(avg_reward), 4),
        "action_health": action_health,
        "drift_labels": drift_labels,
        "stale_sessions": stale_sessions,
        "stale_session_count": int(len(stale_sessions)),
        "pruned_session_ids": pruned_ids,
        "pruned_session_count": int(len(pruned_ids)),
        "compacted_session_ids": compacted_session_ids,
        "compacted_rows": int(compacted_rows),
        "max_recent_transitions": int(max_recent_transitions),
    }


def write_memory_maintenance_report(report: dict[str, Any], output_path: Path) -> Path:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return target
