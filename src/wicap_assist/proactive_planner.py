"""Proactive action planning with strict preventive-action budgets."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from wicap_assist.anomaly_routing import action_to_runbook_step


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def plan_proactive_actions(
    conn: sqlite3.Connection,
    *,
    risk_threshold: float = 75.0,
    min_route_confidence: float = 0.70,
    max_actions: int = 1,
) -> dict[str, Any]:
    """Return bounded preventive actions from forecast + anomaly-v3 context."""
    forecasts = conn.execute(
        """
        SELECT ts, signature, horizon_sec, risk_score, payload_json
        FROM forecast_events
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()
    anomalies = conn.execute(
        """
        SELECT ts_text, snippet, extra_json
        FROM log_events
        WHERE category = 'network_anomaly'
        ORDER BY id DESC
        LIMIT 200
        """
    ).fetchall()

    route_conf_by_sig: dict[str, float] = {}
    horizon_by_sig: dict[str, int] = {}
    for row in anomalies:
        signature = str(row["snippet"] or "").strip()
        raw_extra = row["extra_json"]
        if not isinstance(raw_extra, str) or not raw_extra.strip():
            continue
        try:
            extra = json.loads(raw_extra)
        except json.JSONDecodeError:
            continue
        if not isinstance(extra, dict):
            continue
        route_conf = _safe_float(extra.get("route_confidence"), default=0.0)
        horizon = int(extra.get("predictive_horizon_sec", 0) or 0)
        if signature and signature not in route_conf_by_sig:
            route_conf_by_sig[signature] = route_conf
            horizon_by_sig[signature] = horizon

    planned: list[dict[str, Any]] = []
    for row in forecasts:
        risk = _safe_float(row["risk_score"], default=0.0)
        if risk < float(risk_threshold):
            continue
        signature = str(row["signature"] or "").strip()
        route_conf = route_conf_by_sig.get(signature, 0.0)
        if route_conf < float(min_route_confidence):
            continue
        planned.append(
            {
                "decision": "forecast_preemption",
                "action": "status_check",
                "action_step": action_to_runbook_step("status_check"),
                "risk_score": round(risk, 4),
                "route_confidence": round(float(route_conf), 4),
                "horizon_sec": int(row["horizon_sec"] or horizon_by_sig.get(signature, 0) or 0),
                "signature": signature,
                "ts": str(row["ts"]),
            }
        )
        if len(planned) >= max(1, int(max_actions)):
            break

    return {
        "risk_threshold": float(risk_threshold),
        "min_route_confidence": float(min_route_confidence),
        "max_actions": int(max_actions),
        "planned_actions": planned,
        "planned_count": int(len(planned)),
    }
