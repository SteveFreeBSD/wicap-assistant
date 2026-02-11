"""Provider-neutral telemetry payload helpers for control loops."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import request as urllib_request

from wicap_assist.otlp_profile import OtlpProfile, resolve_otlp_profile
from wicap_assist.util.redact import redact_text

TELEMETRY_EVENT_VERSION = "wicap.telemetry.v1"
DEFAULT_SERVICE_NAME = "wicap-assistant"
DEFAULT_SERVICE_VERSION = "1.0.0"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in attributes.items():
        if isinstance(value, str):
            redacted[key] = redact_text(value)
        else:
            redacted[key] = value
    return redacted


def _telemetry_sink_path() -> Path | None:
    raw = os.environ.get("WICAP_ASSIST_TELEMETRY_PATH", "").strip()
    if not raw:
        return None
    return Path(raw).expanduser()


def _post_otlp_payload(
    payload: dict[str, Any],
    *,
    profile: OtlpProfile,
    sender: Callable[..., Any] = urllib_request.urlopen,
) -> None:
    if not profile.is_valid or not profile.endpoint:
        return
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers.update(profile.headers)
    request = urllib_request.Request(
        profile.endpoint,
        data=body,
        headers=headers,
        method="POST",
    )
    response = sender(request, timeout=float(profile.timeout_seconds))
    status = int(getattr(response, "status", 0) or 0)
    if status and status >= 400:
        raise RuntimeError(f"otlp_http_status_{status}")


def build_control_cycle_telemetry(
    *,
    mode: str,
    profile: str,
    decision: str,
    observation_cycle: int,
    actions_executed: int,
    anomaly_events: int,
    message: str,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one telemetry envelope aligned to `wicap.telemetry.v1`."""
    ts = _utc_now_iso()
    attrs = {
        "wicap.control.mode": str(mode),
        "wicap.control.profile": str(profile),
        "wicap.control.decision": str(decision),
        "wicap.control.observation_cycle": int(observation_cycle),
    }
    if attributes:
        attrs.update(attributes)
    redacted_attrs = _redact_attributes(attrs)
    redacted_message = redact_text(message)

    return {
        "telemetry_event_version": TELEMETRY_EVENT_VERSION,
        "resource": {
            "service.name": os.environ.get("WICAP_ASSIST_SERVICE_NAME", DEFAULT_SERVICE_NAME),
            "service.version": os.environ.get("WICAP_ASSIST_SERVICE_VERSION", DEFAULT_SERVICE_VERSION),
            "deployment.environment": os.environ.get("WICAP_ASSIST_DEPLOYMENT_ENV", "local"),
        },
        "traces": [
            {
                "name": "wicap.control.cycle",
                "start_time": ts,
                "end_time": ts,
                "status": "ok",
                "attributes": redacted_attrs,
            }
        ],
        "metrics": [
            {
                "name": "wicap.control.observation.cycles",
                "value": int(observation_cycle),
                "attributes": {"wicap.control.mode": str(mode)},
            },
            {
                "name": "wicap.control.actions.executed",
                "value": int(actions_executed),
                "attributes": {"wicap.control.mode": str(mode)},
            },
            {
                "name": "wicap.anomaly.events.total",
                "value": int(anomaly_events),
                "attributes": {"wicap.control.mode": str(mode)},
            },
        ],
        "logs": [
            {
                "timestamp": ts,
                "severity_text": "INFO",
                "body": redacted_message,
                "attributes": redacted_attrs,
            }
        ],
    }


def emit_control_cycle_telemetry(
    *,
    mode: str,
    profile: str,
    decision: str,
    observation_cycle: int,
    actions_executed: int,
    anomaly_events: int,
    message: str,
    attributes: dict[str, Any] | None = None,
    sink_path: Path | None = None,
    otlp_profile: OtlpProfile | None = None,
    otlp_sender: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Build and optionally persist one control-loop telemetry envelope."""
    payload = build_control_cycle_telemetry(
        mode=mode,
        profile=profile,
        decision=decision,
        observation_cycle=observation_cycle,
        actions_executed=actions_executed,
        anomaly_events=anomaly_events,
        message=message,
        attributes=attributes,
    )
    target = sink_path or _telemetry_sink_path()
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    profile = otlp_profile or resolve_otlp_profile()
    if profile.is_valid:
        sender = otlp_sender or urllib_request.urlopen
        try:
            _post_otlp_payload(payload, profile=profile, sender=sender)
        except (urllib_error.URLError, TimeoutError, RuntimeError, OSError):
            # Telemetry delivery must be fail-open for control loops.
            pass
    return payload
