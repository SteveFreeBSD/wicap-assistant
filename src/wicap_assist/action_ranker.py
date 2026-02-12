"""Deterministic shadow action ranking for allowlisted control actions."""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Mapping

from wicap_assist.actuators import ALLOWED_RESTART_SERVICES

_BASE_ACTIONS = ("status_check", "compose_up_core", "shutdown")
_DEFAULT_SHADOW_GATE_WINDOW = 320
_DEFAULT_SHADOW_GATE_MIN_SAMPLES = 20
_DEFAULT_SHADOW_GATE_MIN_AGREEMENT = 0.7
_DEFAULT_SHADOW_GATE_MIN_SUCCESS = 0.6


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
        return 8.0 if service in down_services else 1.0
    if lowered in {"compose_up", "compose_up_core"}:
        if len(down_services) >= 2:
            return 5.0
        if len(down_services) == 1:
            return 2.0
        return -6.0
    if lowered == "status_check":
        return 6.0 if not down_services else 12.0
    if lowered == "shutdown":
        return -22.0 if mode != "autonomous" else -10.0
    return 0.0


def _shadow_gate_thresholds() -> tuple[int, int, float, float]:
    window = _DEFAULT_SHADOW_GATE_WINDOW
    min_samples = _DEFAULT_SHADOW_GATE_MIN_SAMPLES
    min_agreement = _DEFAULT_SHADOW_GATE_MIN_AGREEMENT
    min_success = _DEFAULT_SHADOW_GATE_MIN_SUCCESS
    try:
        window = max(50, int(os.getenv("WICAP_ASSIST_SHADOW_GATE_WINDOW", str(window))))
    except ValueError:
        pass
    try:
        min_samples = max(1, int(os.getenv("WICAP_ASSIST_SHADOW_GATE_MIN_SAMPLES", str(min_samples))))
    except ValueError:
        pass
    try:
        min_agreement = min(1.0, max(0.0, float(os.getenv("WICAP_ASSIST_SHADOW_GATE_MIN_AGREEMENT", str(min_agreement)))))
    except ValueError:
        pass
    try:
        min_success = min(1.0, max(0.0, float(os.getenv("WICAP_ASSIST_SHADOW_GATE_MIN_SUCCESS", str(min_success)))))
    except ValueError:
        pass
    return window, min_samples, min_agreement, min_success


def _shadow_quality_gate(conn: sqlite3.Connection) -> dict[str, Any]:
    (
        sample_window,
        min_samples,
        min_agreement_rate,
        min_success_rate,
    ) = _shadow_gate_thresholds()
    rows = conn.execute(
        """
        SELECT decision, action, status, feature_json
        FROM decision_features
        WHERE feature_json LIKE '%shadow_ranker_top_action%'
          AND COALESCE(TRIM(action), '') != ''
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(sample_window),),
    ).fetchall()
    samples = 0
    agreement_count = 0
    success_count = 0
    for row in rows:
        action = str(row["action"] or "").strip()
        if not action:
            continue
        raw_feature = row["feature_json"]
        if not isinstance(raw_feature, str):
            continue
        try:
            feature = json.loads(raw_feature)
        except json.JSONDecodeError:
            continue
        if not isinstance(feature, dict):
            continue
        shadow_action = str(feature.get("shadow_ranker_top_action") or "").strip()
        if not shadow_action:
            continue
        samples += 1
        if shadow_action == action:
            agreement_count += 1
            if str(row["status"] or "").strip().lower() == "executed_ok":
                success_count += 1

    agreement_rate = float(agreement_count) / float(samples) if samples > 0 else 0.0
    success_rate = float(success_count) / float(agreement_count) if agreement_count > 0 else 0.0
    passes = (
        samples >= int(min_samples)
        and agreement_rate >= float(min_agreement_rate)
        and success_rate >= float(min_success_rate)
    )
    status = "pass" if passes else "insufficient_data" if samples < int(min_samples) else "fail"
    return {
        "enabled": True,
        "status": status,
        "samples": int(samples),
        "agreement_count": int(agreement_count),
        "success_count": int(success_count),
        "agreement_rate": round(float(agreement_rate), 4),
        "success_rate": round(float(success_rate), 4),
        "min_samples": int(min_samples),
        "min_agreement_rate": round(float(min_agreement_rate), 4),
        "min_success_rate": round(float(min_success_rate), 4),
        "passes": bool(passes),
    }


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
    shadow_gate = _shadow_quality_gate(conn)
    return {
        "mode": str(mode),
        "policy_profile": str(policy_profile),
        "down_services": down_services,
        "top_action": str(top[0]["action"]) if top else None,
        "top_score": float(top[0]["score"]) if top else 0.0,
        "rankings": top,
        "shadow_gate": shadow_gate,
    }
