"""Deterministic feature extraction for control decisions."""

from __future__ import annotations

import sqlite3
from typing import Any, Mapping


_SUCCESS_STATUSES = {"executed_ok"}
_FAIL_STATUSES = {"executed_fail", "rejected", "missing_script"}


def query_prior_action_stats(conn: sqlite3.Connection, action: str | None) -> dict[str, Any]:
    """Return compact prior outcome stats for one action."""
    normalized_action = str(action or "").strip()
    if not normalized_action:
        return {
            "prior_total": 0,
            "prior_success": 0,
            "prior_fail": 0,
            "prior_escalated": 0,
            "prior_success_rate": 0.0,
        }

    rows = conn.execute(
        """
        SELECT status, count(*) AS count_rows
        FROM episodes
        WHERE action = ?
        GROUP BY status
        """,
        (normalized_action,),
    ).fetchall()
    total = 0
    success = 0
    fail = 0
    escalated = 0
    for row in rows:
        status = str(row["status"]).strip().lower()
        count = int(row["count_rows"] or 0)
        total += count
        if status in _SUCCESS_STATUSES:
            success += count
        elif status == "escalated":
            escalated += count
            fail += count
        elif status in _FAIL_STATUSES:
            fail += count

    success_rate = 0.0 if total <= 0 else float(success) / float(total)
    return {
        "prior_total": int(total),
        "prior_success": int(success),
        "prior_fail": int(fail),
        "prior_escalated": int(escalated),
        "prior_success_rate": round(success_rate, 4),
    }


def _event_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _count_top_signatures(pre_state: Mapping[str, Any]) -> tuple[int, int]:
    top = pre_state.get("top_signatures")
    if not isinstance(top, list):
        return 0, 0
    count = 0
    total_events = 0
    for item in top:
        if not isinstance(item, dict):
            continue
        signature = str(item.get("signature", "")).strip()
        if not signature:
            continue
        count += 1
        try:
            total_events += int(item.get("count", 0) or 0)
        except (TypeError, ValueError):
            total_events += 0
    return count, total_events


def _down_service_count(pre_state: Mapping[str, Any], detail: Mapping[str, Any]) -> int:
    down = pre_state.get("down_services")
    if isinstance(down, list):
        return sum(1 for item in down if str(item).strip())

    detail_down = detail.get("down_services")
    if isinstance(detail_down, list):
        return sum(1 for item in detail_down if str(item).strip())
    return 0


def build_decision_feature_vector(
    *,
    event: Mapping[str, Any],
    mode: str,
    policy_profile: str,
    prior_stats: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic decision feature vector from one control event."""
    pre_state = _event_dict(event.get("pre_state_json"))
    detail = _event_dict(event.get("detail_json"))
    decision = str(event.get("decision", "")).strip()
    action = str(event.get("action", "")).strip() if event.get("action") is not None else None
    status = str(event.get("status", "")).strip()

    signature_count, anomaly_event_total = _count_top_signatures(pre_state)
    down_count = _down_service_count(pre_state, detail)
    prior = dict(prior_stats or {})
    alert_text = str(pre_state.get("alert", "")).strip()

    max_down_streak = 0
    try:
        max_down_streak = int(detail.get("max_down_streak", 0) or 0)
    except (TypeError, ValueError):
        max_down_streak = 0
    cycle = 0
    try:
        cycle = int(pre_state.get("cycle", 0) or 0)
    except (TypeError, ValueError):
        cycle = 0

    shadow_ranker = detail.get("shadow_ranker")
    shadow_top_action = None
    shadow_top_score = 0.0
    shadow_candidate_count = 0
    if isinstance(shadow_ranker, dict):
        top_action_value = shadow_ranker.get("top_action")
        if isinstance(top_action_value, str) and top_action_value.strip():
            shadow_top_action = top_action_value.strip()
        try:
            shadow_top_score = float(shadow_ranker.get("top_score", 0.0) or 0.0)
        except (TypeError, ValueError):
            shadow_top_score = 0.0
        rankings = shadow_ranker.get("rankings")
        if isinstance(rankings, list):
            shadow_candidate_count = len(rankings)

    return {
        "mode": str(mode).strip(),
        "policy_profile": str(policy_profile).strip(),
        "decision": decision,
        "action": action,
        "status": status,
        "cycle": int(cycle),
        "alert_present": bool(alert_text),
        "down_service_count": int(down_count),
        "top_signature_count": int(signature_count),
        "anomaly_event_total": int(anomaly_event_total),
        "max_down_streak": int(max_down_streak),
        "is_executed_action": bool(status.startswith("executed_")),
        "is_escalated": bool(status == "escalated"),
        "prior_action_total": int(prior.get("prior_total", 0) or 0),
        "prior_action_success": int(prior.get("prior_success", 0) or 0),
        "prior_action_fail": int(prior.get("prior_fail", 0) or 0),
        "prior_action_escalated": int(prior.get("prior_escalated", 0) or 0),
        "prior_action_success_rate": float(prior.get("prior_success_rate", 0.0) or 0.0),
        "shadow_ranker_top_action": shadow_top_action,
        "shadow_ranker_top_score": round(shadow_top_score, 4),
        "shadow_ranker_candidate_count": int(shadow_candidate_count),
        "shadow_ranker_agrees": bool(shadow_top_action and action and shadow_top_action == action),
    }
