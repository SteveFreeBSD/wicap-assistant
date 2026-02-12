"""Forecast summaries from ingested WiCAP prediction artifacts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from typing import Any

from wicap_assist.util.evidence import parse_utc_datetime


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (str(name),),
    ).fetchone()
    return row is not None


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _extra_payload(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def summarize_forecasts(
    conn: sqlite3.Connection,
    *,
    lookback_hours: int = 6,
    limit: int = 200,
) -> dict[str, Any]:
    """Summarize recent prediction rows for CLI and agent control center."""
    now_dt = datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(hours=max(1, int(lookback_hours)))
    entries: list[dict[str, Any]] = []
    if _table_exists(conn, "forecast_events"):
        rows = conn.execute(
            """
            SELECT ts, signature, horizon_sec, risk_score, confidence_low, confidence_high, summary, payload_json
            FROM forecast_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
        for row in rows:
            ts_text = row["ts"]
            ts_dt = parse_utc_datetime(ts_text)
            if ts_dt is not None and ts_dt < cutoff:
                continue
            extra = _extra_payload(row["payload_json"])
            entries.append(
                {
                    "ts": ts_text,
                    "signature": str(row["signature"] or "").strip(),
                    "risk_score": _safe_float(row["risk_score"], 0.0),
                    "horizon_sec": _safe_int(row["horizon_sec"], 0),
                    "confidence_band": {
                        "low": row["confidence_low"],
                        "high": row["confidence_high"],
                    },
                    "top_contributors": extra.get("top_contributors", []),
                    "summary": str(row["summary"] or "").strip(),
                }
            )
    else:
        rows = conn.execute(
            """
            SELECT ts_text, snippet, extra_json
            FROM log_events
            WHERE category = 'network_prediction'
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
        for row in rows:
            ts_text = row["ts_text"]
            ts_dt = parse_utc_datetime(ts_text)
            if ts_dt is not None and ts_dt < cutoff:
                continue
            extra = _extra_payload(row["extra_json"])
            entries.append(
                {
                    "ts": ts_text,
                    "signature": str(row["snippet"] or "").strip(),
                    "risk_score": _safe_float(extra.get("risk_score", 0.0)),
                    "horizon_sec": _safe_int(extra.get("horizon_sec", 0)),
                    "confidence_band": extra.get("confidence_band", {}),
                    "top_contributors": extra.get("top_contributors", []),
                    "summary": str(extra.get("summary", "")).strip(),
                }
            )

    by_horizon: dict[str, dict[str, Any]] = {}
    max_risk = 0.0
    latest_risk = 0.0
    latest_entry = entries[0] if entries else None
    for entry in entries:
        risk = float(entry["risk_score"])
        horizon = str(int(entry["horizon_sec"] or 0))
        max_risk = max(max_risk, risk)
        if horizon not in by_horizon:
            by_horizon[horizon] = {
                "count": 0,
                "latest_risk_score": risk,
                "max_risk_score": risk,
            }
        bucket = by_horizon[horizon]
        bucket["count"] = int(bucket["count"]) + 1
        bucket["latest_risk_score"] = risk
        bucket["max_risk_score"] = max(float(bucket["max_risk_score"]), risk)

    if latest_entry is not None:
        latest_risk = float(latest_entry["risk_score"])

    return {
        "lookback_hours": int(max(1, int(lookback_hours))),
        "count": int(len(entries)),
        "latest_risk_score": round(float(latest_risk), 4),
        "max_risk_score": round(float(max_risk), 4),
        "latest_entry": latest_entry,
        "horizons": by_horizon,
    }


def forecast_to_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def format_forecast_text(payload: dict[str, Any]) -> str:
    lines = [
        (
            "forecast: "
            f"count={payload.get('count')} "
            f"lookback_hours={payload.get('lookback_hours')} "
            f"latest_risk_score={payload.get('latest_risk_score')} "
            f"max_risk_score={payload.get('max_risk_score')}"
        )
    ]
    horizons = payload.get("horizons", {})
    if isinstance(horizons, dict):
        for key in sorted(horizons.keys(), key=lambda item: int(item) if str(item).isdigit() else 0):
            bucket = horizons.get(key, {})
            if not isinstance(bucket, dict):
                continue
            lines.append(
                f"- horizon={key}s count={bucket.get('count')} "
                f"latest_risk={bucket.get('latest_risk_score')} "
                f"max_risk={bucket.get('max_risk_score')}"
            )

    latest = payload.get("latest_entry")
    if isinstance(latest, dict):
        lines.append(
            f"latest: ts={latest.get('ts')} horizon={latest.get('horizon_sec')} "
            f"risk={latest.get('risk_score')}"
        )
        contributors = latest.get("top_contributors", [])
        if isinstance(contributors, list):
            for item in contributors[:3]:
                if not isinstance(item, dict):
                    continue
                lines.append(f"contributor: {item.get('name')} weight={item.get('weight')}")
        summary = str(latest.get("summary", "")).strip()
        if summary:
            lines.append(f"summary: {summary}")
    return "\n".join(lines)
