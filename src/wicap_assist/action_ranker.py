"""Deterministic shadow action ranking for allowlisted control actions."""

from __future__ import annotations

import sqlite3
from typing import Any, Mapping

from wicap_assist.actuators import ALLOWED_RESTART_SERVICES

_BASE_ACTIONS = ("status_check", "compose_up", "shutdown")


def _extract_down_services(observation: Mapping[str, Any]) -> list[str]:
    status = observation.get("service_status")
    if not isinstance(status, dict):
        return []
    docker = status.get("docker")
    if not isinstance(docker, dict):
        return []
    services = docker.get("services")
    if not isinstance(services, dict):
        return []
    out: list[str] = []
    for service_name, info in services.items():
        if not isinstance(info, dict):
            continue
        if str(info.get("state", "unknown")) != "up":
            value = str(service_name).strip()
            if value:
                out.append(value)
    return sorted(set(out))


def _candidate_actions(down_services: list[str]) -> list[str]:
    out = list(_BASE_ACTIONS)
    for service in down_services:
        if service in ALLOWED_RESTART_SERVICES:
            out.append(f"restart_service:{service}")
    return out


def _history_stats(conn: sqlite3.Connection, action: str) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT status, count(*) AS n
        FROM decision_features
        WHERE action = ?
        GROUP BY status
        """,
        (str(action),),
    ).fetchall()
    total = 0
    success = 0
    fail = 0
    escalated = 0
    for row in rows:
        status = str(row["status"]).strip().lower()
        count = int(row["n"] or 0)
        total += count
        if status == "executed_ok":
            success += count
        elif status in {"executed_fail", "missing_script", "rejected"}:
            fail += count
        elif status == "escalated":
            escalated += count
            fail += count
    success_rate = 0.0 if total <= 0 else float(success) / float(total)
    fail_rate = 0.0 if total <= 0 else float(fail) / float(total)
    escalated_rate = 0.0 if total <= 0 else float(escalated) / float(total)
    return {
        "total": int(total),
        "success": int(success),
        "fail": int(fail),
        "escalated": int(escalated),
        "success_rate": success_rate,
        "fail_rate": fail_rate,
        "escalated_rate": escalated_rate,
    }


def _context_boost(action: str, *, down_services: list[str], mode: str) -> float:
    lowered = str(action).strip().lower()
    if lowered.startswith("restart_service:"):
        service = lowered.split(":", 1)[1].strip()
        return 14.0 if service in down_services else 2.0
    if lowered == "compose_up":
        if len(down_services) >= 2:
            return 10.0
        if len(down_services) == 1:
            return 6.0
        return -8.0
    if lowered == "status_check":
        return 6.0 if not down_services else -3.0
    if lowered == "shutdown":
        return -22.0 if mode != "autonomous" else -10.0
    return 0.0


def rank_allowlisted_actions(
    conn: sqlite3.Connection,
    *,
    observation: Mapping[str, Any],
    mode: str,
    policy_profile: str,
    top_n: int = 3,
) -> dict[str, Any]:
    """Return deterministic shadow ranking for allowlisted actions."""
    down_services = _extract_down_services(observation)
    candidates = _candidate_actions(down_services)
    rankings: list[dict[str, Any]] = []
    for action in candidates:
        stats = _history_stats(conn, action)
        history_score = (
            float(stats["success_rate"]) * 100.0
            - float(stats["fail_rate"]) * 35.0
            - float(stats["escalated_rate"]) * 45.0
        )
        context_score = _context_boost(action, down_services=down_services, mode=str(mode))
        cold_start_bonus = 3.0 if int(stats["total"]) == 0 else 0.0
        score = round(history_score + context_score + cold_start_bonus, 4)
        rankings.append(
            {
                "action": action,
                "score": score,
                "history_total": int(stats["total"]),
                "history_success_rate": round(float(stats["success_rate"]), 4),
                "history_escalated": int(stats["escalated"]),
                "context_down_services": list(down_services),
            }
        )

    rankings.sort(key=lambda item: (-float(item["score"]), str(item["action"])))
    top = rankings[: max(1, int(top_n))]
    return {
        "mode": str(mode),
        "policy_profile": str(policy_profile),
        "down_services": down_services,
        "top_action": str(top[0]["action"]) if top else None,
        "top_score": float(top[0]["score"]) if top else 0.0,
        "rankings": top,
    }

