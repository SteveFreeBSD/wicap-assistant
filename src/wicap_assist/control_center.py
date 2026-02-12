"""High-signal agent control-center snapshot builder."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from wicap_assist.forecast import summarize_forecasts
from wicap_assist.live import collect_live_cycle
from wicap_assist.policy_explain import collect_policy_explain
from wicap_assist.db import summarize_recent_drift
from wicap_assist.util.time import utc_now_iso


def build_control_center_snapshot(
    conn: sqlite3.Connection,
    *,
    mode: str,
    repo_root: Path | None = None,
    forecast_lookback_hours: int = 6,
) -> dict[str, Any]:
    """Build one command-center snapshot across live + forecast + drift + policy."""
    observation = collect_live_cycle(conn)
    forecast = summarize_forecasts(conn, lookback_hours=max(1, int(forecast_lookback_hours)))
    drift = summarize_recent_drift(conn)
    policy = collect_policy_explain(repo_root=repo_root)
    return {
        "generated_ts": utc_now_iso(),
        "mode": str(mode),
        "policy": policy,
        "forecast": forecast,
        "drift": drift,
        "observation": observation,
    }


def control_center_to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def format_control_center_text(payload: dict[str, Any]) -> str:
    policy = payload.get("policy", {})
    forecast = payload.get("forecast", {})
    drift = payload.get("drift", {})
    observation = payload.get("observation", {})
    control_plane = policy.get("control_plane", {}) if isinstance(policy, dict) else {}
    intel = policy.get("intel_worker", {}) if isinstance(policy, dict) else {}
    lines = [
        (
            "control_center: "
            f"mode={payload.get('mode')} ts={payload.get('generated_ts')} "
            f"policy_source={policy.get('source') if isinstance(policy, dict) else None}"
        ),
        (
            "policy: "
            f"profile={control_plane.get('active_policy_profile')} "
            f"version={control_plane.get('profile_version')} "
            f"runtime={control_plane.get('runtime_plane')} "
            f"tool={control_plane.get('tool_policy_plane')} "
            f"elevated={control_plane.get('elevated_plane')}"
        ),
        (
            "intel: "
            f"anomaly_ts={intel.get('latest_anomaly_ts')} "
            f"prediction_ts={intel.get('latest_prediction_ts')}"
        ),
        (
            "forecast: "
            f"count={forecast.get('count')} "
            f"latest_risk={forecast.get('latest_risk_score')} "
            f"max_risk={forecast.get('max_risk_score')}"
        ),
        (
            "drift: "
            f"count={drift.get('count')} "
            f"drift_count={drift.get('drift_count')} "
            f"drift_rate={drift.get('drift_rate')} "
            f"max_abs_delta={drift.get('max_abs_delta')}"
        ),
    ]

    obs_alert = str(observation.get("alert", "")).strip() if isinstance(observation, dict) else ""
    if obs_alert:
        lines.append(f"alert: {obs_alert}")
    top_signatures = observation.get("top_signatures", []) if isinstance(observation, dict) else []
    if isinstance(top_signatures, list):
        for item in top_signatures[:3]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"signature: [{item.get('category')}] x{item.get('count')} {item.get('signature')}"
            )
    recommendations = observation.get("operator_guidance", []) if isinstance(observation, dict) else []
    if isinstance(recommendations, list):
        for line in recommendations[:3]:
            lines.append(f"next: {line}")
    return "\n".join(lines)
