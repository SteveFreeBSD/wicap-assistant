"""Deterministic rollout/canary gate evaluation for autonomous promotion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from wicap_assist.util.evidence import parse_utc_datetime
from wicap_assist.util.time import utc_now_iso


def _feature_payload(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(value, dict):
        return value
    return {}


def _safe_float(value: object, *, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: object, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def evaluate_rollout_gates(
    conn: sqlite3.Connection,
    *,
    lookback_days: int = 14,
    min_shadow_samples: int = 20,
    min_shadow_agreement_rate: float = 0.70,
    min_shadow_success_rate: float = 0.60,
    min_reward_avg: float = 0.00,
    max_autonomous_escalation_rate: float = 0.20,
    min_autonomous_runs: int = 5,
    max_rollback_failures: int = 3,
    now_ts: str | None = None,
) -> dict[str, Any]:
    now_text = str(now_ts or utc_now_iso())
    now_dt = parse_utc_datetime(now_text) or datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(days=max(1, int(lookback_days)))

    feature_rows = conn.execute(
        """
        SELECT ts, mode, status, feature_json
        FROM decision_features
        ORDER BY id DESC
        LIMIT 10000
        """
    ).fetchall()

    latest_shadow: dict[str, Any] | None = None
    reward_values: list[float] = []
    for row in feature_rows:
        ts_dt = parse_utc_datetime(row["ts"])
        if ts_dt is None or ts_dt < cutoff:
            continue
        payload = _feature_payload(row["feature_json"])
        reward_values.append(_safe_float(payload.get("reward_value", 0.0)))
        samples = _safe_int(payload.get("shadow_gate_samples", 0))
        if samples > 0 and latest_shadow is None:
            latest_shadow = {
                "samples": samples,
                "agreement_rate": _safe_float(payload.get("shadow_gate_agreement_rate", 0.0)),
                "success_rate": _safe_float(payload.get("shadow_gate_success_rate", 0.0)),
                "passes": bool(payload.get("shadow_gate_passes", False)),
            }

    if latest_shadow is None:
        latest_shadow = {
            "samples": 0,
            "agreement_rate": 0.0,
            "success_rate": 0.0,
            "passes": False,
        }

    shadow_pass = (
        int(latest_shadow["samples"]) >= int(min_shadow_samples)
        and float(latest_shadow["agreement_rate"]) >= float(min_shadow_agreement_rate)
        and float(latest_shadow["success_rate"]) >= float(min_shadow_success_rate)
    )
    shadow_status = "pass" if shadow_pass else "insufficient_data" if int(latest_shadow["samples"]) < int(min_shadow_samples) else "fail"

    avg_reward = 0.0 if not reward_values else (sum(reward_values) / float(len(reward_values)))
    reward_pass = float(avg_reward) >= float(min_reward_avg)

    session_rows = conn.execute(
        """
        SELECT started_ts, status, mode
        FROM control_sessions
        WHERE mode = 'autonomous'
        ORDER BY id DESC
        LIMIT 5000
        """
    ).fetchall()
    autonomous_runs = 0
    autonomous_escalations = 0
    for row in session_rows:
        ts_dt = parse_utc_datetime(row["started_ts"])
        if ts_dt is None or ts_dt < cutoff:
            continue
        autonomous_runs += 1
        status = str(row["status"] or "").strip().lower()
        if status in {"escalated", "failed"}:
            autonomous_escalations += 1

    escalation_rate = float(autonomous_escalations) / float(autonomous_runs) if autonomous_runs > 0 else 1.0
    autonomous_pass = (
        autonomous_runs >= int(min_autonomous_runs)
        and escalation_rate <= float(max_autonomous_escalation_rate)
    )
    autonomous_status = (
        "pass"
        if autonomous_pass
        else "insufficient_data"
        if autonomous_runs < int(min_autonomous_runs)
        else "fail"
    )

    rollback_rows = conn.execute(
        """
        SELECT ts, status
        FROM control_events
        WHERE decision = 'rollback_rule'
        ORDER BY id DESC
        LIMIT 5000
        """
    ).fetchall()
    rollback_failures = 0
    for row in rollback_rows:
        ts_dt = parse_utc_datetime(row["ts"])
        if ts_dt is None or ts_dt < cutoff:
            continue
        status = str(row["status"] or "").strip().lower()
        if status in {"executed_fail", "escalated"}:
            rollback_failures += 1
    rollback_pass = rollback_failures <= int(max_rollback_failures)

    gates = {
        "shadow_quality": {
            "status": shadow_status,
            "pass": bool(shadow_pass),
            "samples": int(latest_shadow["samples"]),
            "agreement_rate": round(float(latest_shadow["agreement_rate"]), 4),
            "success_rate": round(float(latest_shadow["success_rate"]), 4),
            "min_samples": int(min_shadow_samples),
            "min_agreement_rate": float(min_shadow_agreement_rate),
            "min_success_rate": float(min_shadow_success_rate),
        },
        "reward_stability": {
            "status": "pass" if reward_pass else "fail",
            "pass": bool(reward_pass),
            "avg_reward": round(float(avg_reward), 4),
            "min_avg_reward": float(min_reward_avg),
            "sample_count": int(len(reward_values)),
        },
        "autonomous_escalation": {
            "status": autonomous_status,
            "pass": bool(autonomous_pass),
            "runs": int(autonomous_runs),
            "escalations": int(autonomous_escalations),
            "escalation_rate": round(float(escalation_rate), 4),
            "max_escalation_rate": float(max_autonomous_escalation_rate),
            "min_runs": int(min_autonomous_runs),
        },
        "rollback_budget": {
            "status": "pass" if rollback_pass else "fail",
            "pass": bool(rollback_pass),
            "rollback_failures": int(rollback_failures),
            "max_rollback_failures": int(max_rollback_failures),
        },
    }
    overall_pass = all(bool(item.get("pass")) for item in gates.values())
    return {
        "generated_ts": now_text,
        "lookback_days": int(max(1, int(lookback_days))),
        "overall_pass": bool(overall_pass),
        "gates": gates,
    }


def load_rollout_gate_history(path: Path) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.exists():
        return []
    entries: list[dict[str, Any]] = []
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def append_rollout_gate_history(path: Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return target


def evaluate_promotion_readiness(
    history: list[dict[str, Any]],
    *,
    required_consecutive_passes: int = 2,
) -> dict[str, Any]:
    required = max(1, int(required_consecutive_passes))
    consecutive = 0
    for entry in reversed(history):
        if bool(entry.get("overall_pass", False)):
            consecutive += 1
            if consecutive >= required:
                break
            continue
        break
    ready = consecutive >= required
    return {
        "required_consecutive_passes": int(required),
        "consecutive_passes": int(consecutive),
        "ready": bool(ready),
    }
