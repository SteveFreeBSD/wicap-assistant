"""Deterministic anomaly class routing and bounded feedback calibration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3
from typing import Any

from wicap_assist.util.evidence import parse_utc_datetime

_DEFAULT_LOOKBACK_DAYS = 30
_MIN_FEEDBACK_SAMPLES = 5

_CLASS_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("wifi_disruption", ("deauth", "disassoc", "jamm", "rf jam", "beacon flood")),
    ("probe_recon", ("probe", "ssid sweep", "recon", "wardrive")),
    ("dns_drift", ("dns", "resolver", "tunnel", "exfil")),
    ("http_drift", ("http", "uri spike", "user-agent", "beaconing")),
    ("service_runtime", ("runtime", "processor", "queue lag", "backlog")),
)

_ACTION_LADDERS: dict[str, tuple[str, ...]] = {
    "wifi_disruption": ("status_check", "restart_service:wicap-scout", "compose_up"),
    "probe_recon": ("status_check", "restart_service:wicap-scout"),
    "dns_drift": ("status_check", "restart_service:wicap-processor", "compose_up"),
    "http_drift": ("status_check", "restart_service:wicap-ui", "compose_up"),
    "service_runtime": ("status_check", "restart_service:wicap-processor", "compose_up"),
    "generic_network_anomaly": ("status_check", "compose_up"),
}

_VERIFY_LADDERS: dict[str, tuple[str, ...]] = {
    "wifi_disruption": (
        "python scripts/check_wicap_status.py --local-only",
        "python scripts/check_wicap_status.py --json --local-only",
    ),
    "probe_recon": (
        "python scripts/check_wicap_status.py --local-only",
        "python scripts/check_wicap_status.py --sql-only",
    ),
    "dns_drift": (
        "python scripts/check_wicap_status.py --sql-only",
        "python scripts/check_wicap_status.py --json --sql-only",
    ),
    "http_drift": (
        "python scripts/check_wicap_status.py --local-only",
        "python scripts/check_wicap_status.py --json --local-only",
    ),
    "service_runtime": (
        "python scripts/check_wicap_status.py --local-only",
        "python scripts/check_wicap_status.py --sql-only",
    ),
    "generic_network_anomaly": ("python scripts/check_wicap_status.py --local-only",),
}


def classify_anomaly_class(
    *,
    signature: str,
    category: str,
    attack_type: str | None = None,
) -> str:
    text = " ".join(
        value.strip().lower()
        for value in (str(signature or ""), str(category or ""), str(attack_type or ""))
        if value and str(value).strip()
    )
    for class_id, patterns in _CLASS_PATTERNS:
        if any(pattern in text for pattern in patterns):
            return class_id
    return "generic_network_anomaly"


def action_to_runbook_step(action: str) -> str:
    normalized = str(action).strip().lower()
    if normalized == "status_check":
        return "python scripts/check_wicap_status.py --local-only"
    if normalized == "compose_up":
        return "docker compose up -d"
    if normalized == "shutdown":
        return "docker compose down --remove-orphans"
    if normalized.startswith("restart_service:"):
        service = normalized.split(":", 1)[1].strip()
        if service:
            return f"docker compose restart {service}"
    return normalized


def route_for_anomaly(
    *,
    signature: str,
    category: str,
    attack_type: str | None = None,
    feedback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    class_id = classify_anomaly_class(signature=signature, category=category, attack_type=attack_type)
    action_ladder = list(_ACTION_LADDERS.get(class_id, _ACTION_LADDERS["generic_network_anomaly"]))
    verification_ladder = list(_VERIFY_LADDERS.get(class_id, _VERIFY_LADDERS["generic_network_anomaly"]))
    feedback_payload = dict(feedback or {})
    if "confidence_scale" not in feedback_payload:
        feedback_payload["confidence_scale"] = 1.0
    if "status" not in feedback_payload:
        feedback_payload["status"] = "insufficient_data"
    return {
        "class_id": class_id,
        "action_ladder": action_ladder,
        "verification_ladder": verification_ladder,
        "feedback": feedback_payload,
    }


def _safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _confidence_scale_from_counts(
    *,
    confirmed: int,
    benign: int,
    noisy: int,
    min_samples: int = _MIN_FEEDBACK_SAMPLES,
) -> dict[str, Any]:
    total = int(max(0, confirmed) + max(0, benign) + max(0, noisy))
    if total < int(max(1, min_samples)):
        return {
            "status": "insufficient_data",
            "total": total,
            "confirmed": int(max(0, confirmed)),
            "benign": int(max(0, benign)),
            "noisy": int(max(0, noisy)),
            "confidence_scale": 1.0,
        }

    confirmed_rate = float(max(0, confirmed)) / float(total)
    noisy_rate = float(max(0, benign) + max(0, noisy)) / float(total)
    scale = 1.0 + (confirmed_rate * 0.15) - (noisy_rate * 0.25)
    scale = max(0.70, min(1.15, scale))
    return {
        "status": "calibrated",
        "total": total,
        "confirmed": int(max(0, confirmed)),
        "benign": int(max(0, benign)),
        "noisy": int(max(0, noisy)),
        "confirmed_rate": round(confirmed_rate, 4),
        "noisy_rate": round(noisy_rate, 4),
        "confidence_scale": round(float(scale), 4),
    }


def _feedback_label(extra: dict[str, Any]) -> str:
    for key in ("feedback_label", "label"):
        value = extra.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _attack_type(extra: dict[str, Any]) -> str:
    value = extra.get("attack_type")
    if isinstance(value, str):
        return value.strip().lower()
    return ""


def query_feedback_calibration(
    conn: sqlite3.Connection,
    *,
    attack_type: str | None = None,
    lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
    min_samples: int = _MIN_FEEDBACK_SAMPLES,
) -> dict[str, Any]:
    target_attack_type = str(attack_type or "").strip().lower()
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, int(lookback_days)))
    rows = conn.execute(
        """
        SELECT ts_text, extra_json
        FROM log_events
        WHERE category = 'network_anomaly_feedback'
        ORDER BY id DESC
        LIMIT 5000
        """
    ).fetchall()

    confirmed = 0
    benign = 0
    noisy = 0
    for row in rows:
        ts_text = row["ts_text"]
        ts_dt = parse_utc_datetime(ts_text)
        if ts_dt is not None and ts_dt < cutoff:
            continue

        extra_raw = row["extra_json"]
        if not isinstance(extra_raw, str) or not extra_raw.strip():
            continue
        try:
            extra = json.loads(extra_raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(extra, dict):
            continue

        if target_attack_type:
            row_attack_type = _attack_type(extra)
            if row_attack_type and row_attack_type != target_attack_type:
                continue

        label = _feedback_label(extra)
        if label == "confirmed":
            confirmed += 1
        elif label == "benign":
            benign += 1
        elif label == "noisy":
            noisy += 1

    return _confidence_scale_from_counts(
        confirmed=confirmed,
        benign=benign,
        noisy=noisy,
        min_samples=min_samples,
    )
