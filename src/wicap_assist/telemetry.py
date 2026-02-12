"""Provider-neutral telemetry payload helpers for control loops."""

from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Callable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from wicap_assist.otlp_profile import OtlpProfile, resolve_otlp_profile
from wicap_assist.util.redact import redact_text

TELEMETRY_EVENT_VERSION = "wicap.telemetry.v1"
DEFAULT_SERVICE_NAME = "wicap-assistant"
DEFAULT_SERVICE_VERSION = "1.0.0"
_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
_DEFAULT_OTLP_MAX_ATTEMPTS = 2
_DEFAULT_OTLP_MAX_BATCH = 200
_DEFAULT_OTLP_BACKOFF_SECONDS = 1.0
_DEFAULT_OTLP_MAX_BACKOFF_SECONDS = 30.0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _safe_float(value: object, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


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


def _otlp_max_batch() -> int:
    return max(1, _safe_int(os.environ.get("WICAP_ASSIST_OTLP_MAX_BATCH"), _DEFAULT_OTLP_MAX_BATCH))


def _otlp_max_attempts() -> int:
    return max(1, _safe_int(os.environ.get("WICAP_ASSIST_OTLP_MAX_ATTEMPTS"), _DEFAULT_OTLP_MAX_ATTEMPTS))


def _otlp_backoff_seconds() -> float:
    return max(0.0, _safe_float(os.environ.get("WICAP_ASSIST_OTLP_RETRY_BACKOFF_SECONDS"), _DEFAULT_OTLP_BACKOFF_SECONDS))


def _otlp_max_backoff_seconds() -> float:
    return max(0.0, _safe_float(os.environ.get("WICAP_ASSIST_OTLP_MAX_BACKOFF_SECONDS"), _DEFAULT_OTLP_MAX_BACKOFF_SECONDS))


def _otlp_gzip_enabled() -> bool:
    token = str(os.environ.get("WICAP_ASSIST_OTLP_COMPRESSION", "")).strip().lower()
    return token in {"gzip", "true", "1", "yes", "on"}


def _resource_attributes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    resource = payload.get("resource")
    if not isinstance(resource, dict):
        return []
    out: list[dict[str, Any]] = []
    for key, value in resource.items():
        out.append({"key": str(key), "value": {"stringValue": str(value)}})
    return out


def _kv_attributes(mapping: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in sorted(mapping.keys()):
        value = mapping[key]
        typed: dict[str, Any]
        if isinstance(value, bool):
            typed = {"boolValue": bool(value)}
        elif isinstance(value, int):
            typed = {"intValue": str(value)}
        elif isinstance(value, float):
            typed = {"doubleValue": float(value)}
        else:
            typed = {"stringValue": str(value)}
        out.append({"key": str(key), "value": typed})
    return out


def _split_batches(items: list[dict[str, Any]], *, max_batch: int) -> list[list[dict[str, Any]]]:
    if max_batch <= 0:
        return [items]
    out: list[list[dict[str, Any]]] = []
    for start in range(0, len(items), max_batch):
        out.append(items[start : start + max_batch])
    return out


def _hash_hex(value: str, *, length: int) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return digest[: max(2, int(length))]


def _trace_id(seed: str) -> str:
    return _hash_hex(seed, length=32)


def _span_id(seed: str) -> str:
    return _hash_hex(seed, length=16)


def _endpoint_for_signal(base_endpoint: str, signal: str) -> str:
    parsed = urllib_parse.urlsplit(base_endpoint)
    path = parsed.path or ""
    if path.endswith("/v1/logs") or path.endswith("/v1/metrics") or path.endswith("/v1/traces"):
        path = path.rsplit("/", 1)[0] + f"/{signal}"
    elif not path or path == "/":
        path = f"/v1/{signal}"
    elif "/v1/" not in path:
        path = path.rstrip("/") + f"/v1/{signal}"
    rebuilt = urllib_parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))
    return rebuilt


def _compress_body(body: bytes, *, headers: dict[str, str]) -> bytes:
    if not _otlp_gzip_enabled():
        return body
    headers["Content-Encoding"] = "gzip"
    return gzip.compress(body)


def _json_response_body(response: Any) -> str:
    if not hasattr(response, "read"):
        return ""
    try:
        raw = response.read()
    except Exception:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _partial_success_summary(body: str) -> dict[str, Any]:
    if not body.strip():
        return {"partial_success": False, "rejected_count": 0, "error_message": None}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {"partial_success": False, "rejected_count": 0, "error_message": None}
    if not isinstance(payload, dict):
        return {"partial_success": False, "rejected_count": 0, "error_message": None}
    partial = payload.get("partialSuccess")
    if not isinstance(partial, dict):
        return {"partial_success": False, "rejected_count": 0, "error_message": None}
    rejected = 0
    for key in ("rejectedLogRecords", "rejectedSpans", "rejectedDataPoints"):
        rejected += max(0, _safe_int(partial.get(key), 0))
    return {
        "partial_success": rejected > 0,
        "rejected_count": int(rejected),
        "error_message": str(partial.get("errorMessage", "")).strip() or None,
    }


def _post_otlp_with_retries(
    *,
    endpoint: str,
    body: bytes,
    headers: dict[str, str],
    timeout_seconds: float,
    sender: Callable[..., Any],
    sleeper: Callable[[float], None],
) -> dict[str, Any]:
    attempts = _otlp_max_attempts()
    backoff_base = _otlp_backoff_seconds()
    max_backoff = _otlp_max_backoff_seconds()
    last_status = None
    for attempt in range(1, attempts + 1):
        request = urllib_request.Request(
            endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        retryable = False
        try:
            response = sender(request, timeout=float(timeout_seconds))
            status = int(getattr(response, "status", 0) or 0)
            last_status = status
            response_body = _json_response_body(response)
            if status in _RETRYABLE_STATUS_CODES:
                retryable = True
            elif status >= 400:
                return {
                    "delivered": False,
                    "retryable": False,
                    "status": status,
                    "attempts": attempt,
                    "partial": {"partial_success": False, "rejected_count": 0, "error_message": None},
                }
            else:
                return {
                    "delivered": True,
                    "retryable": False,
                    "status": status,
                    "attempts": attempt,
                    "partial": _partial_success_summary(response_body),
                }
        except urllib_error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            last_status = status
            retryable = status in _RETRYABLE_STATUS_CODES
            if not retryable:
                return {
                    "delivered": False,
                    "retryable": False,
                    "status": status,
                    "attempts": attempt,
                    "partial": {"partial_success": False, "rejected_count": 0, "error_message": str(exc)},
                }
        except (urllib_error.URLError, TimeoutError, OSError):
            retryable = True

        if not retryable or attempt >= attempts:
            break
        if backoff_base > 0:
            sleep_seconds = min(max_backoff, backoff_base * (2 ** (attempt - 1)))
            if sleep_seconds > 0:
                sleeper(float(sleep_seconds))

    return {
        "delivered": False,
        "retryable": True,
        "status": int(last_status or 0),
        "attempts": attempts,
        "partial": {"partial_success": False, "rejected_count": 0, "error_message": None},
    }


def _build_otlp_log_batches(payload: dict[str, Any]) -> list[dict[str, Any]]:
    logs = payload.get("logs")
    if not isinstance(logs, list) or not logs:
        return []
    batches: list[dict[str, Any]] = []
    for chunk in _split_batches(logs, max_batch=_otlp_max_batch()):
        records: list[dict[str, Any]] = []
        for entry in chunk:
            if not isinstance(entry, dict):
                continue
            attrs = entry.get("attributes")
            if not isinstance(attrs, dict):
                attrs = {}
            records.append(
                {
                    "timeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)),
                    "severityText": str(entry.get("severity_text", "INFO")),
                    "body": {"stringValue": str(entry.get("body", ""))},
                    "attributes": _kv_attributes(attrs),
                }
            )
        if not records:
            continue
        batches.append(
            {
                "resourceLogs": [
                    {
                        "resource": {"attributes": _resource_attributes(payload)},
                        "scopeLogs": [{"scope": {"name": "wicap_assist"}, "logRecords": records}],
                    }
                ]
            }
        )
    return batches


def _build_otlp_metric_batches(payload: dict[str, Any]) -> list[dict[str, Any]]:
    metrics = payload.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        return []
    batches: list[dict[str, Any]] = []
    now_nano = str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000))
    for chunk in _split_batches(metrics, max_batch=_otlp_max_batch()):
        metric_rows: list[dict[str, Any]] = []
        for entry in chunk:
            if not isinstance(entry, dict):
                continue
            attrs = entry.get("attributes")
            if not isinstance(attrs, dict):
                attrs = {}
            metric_rows.append(
                {
                    "name": str(entry.get("name", "wicap.metric")),
                    "gauge": {
                        "dataPoints": [
                            {
                                "timeUnixNano": now_nano,
                                "asDouble": float(_safe_float(entry.get("value"), 0.0)),
                                "attributes": _kv_attributes(attrs),
                            }
                        ]
                    },
                }
            )
        if not metric_rows:
            continue
        batches.append(
            {
                "resourceMetrics": [
                    {
                        "resource": {"attributes": _resource_attributes(payload)},
                        "scopeMetrics": [{"scope": {"name": "wicap_assist"}, "metrics": metric_rows}],
                    }
                ]
            }
        )
    return batches


def _build_otlp_trace_batches(payload: dict[str, Any]) -> list[dict[str, Any]]:
    traces = payload.get("traces")
    if not isinstance(traces, list) or not traces:
        return []
    batches: list[dict[str, Any]] = []
    for chunk in _split_batches(traces, max_batch=_otlp_max_batch()):
        spans: list[dict[str, Any]] = []
        for entry in chunk:
            if not isinstance(entry, dict):
                continue
            attrs = entry.get("attributes")
            if not isinstance(attrs, dict):
                attrs = {}
            seed = (
                f"{entry.get('name','wicap.control.cycle')}|"
                f"{entry.get('start_time','')}|{entry.get('end_time','')}|{json.dumps(attrs, sort_keys=True)}"
            )
            spans.append(
                {
                    "traceId": _trace_id(seed),
                    "spanId": _span_id(seed),
                    "name": str(entry.get("name", "wicap.control.cycle")),
                    "kind": 1,
                    "startTimeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)),
                    "endTimeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)),
                    "attributes": _kv_attributes(attrs),
                }
            )
        if not spans:
            continue
        batches.append(
            {
                "resourceSpans": [
                    {
                        "resource": {"attributes": _resource_attributes(payload)},
                        "scopeSpans": [{"scope": {"name": "wicap_assist"}, "spans": spans}],
                    }
                ]
            }
        )
    return batches


def _export_otlp_payload(
    payload: dict[str, Any],
    *,
    profile: OtlpProfile,
    sender: Callable[..., Any],
    sleeper: Callable[[float], None],
) -> None:
    if not profile.is_valid or not profile.endpoint:
        return

    signal_batches = {
        "logs": _build_otlp_log_batches(payload),
        "metrics": _build_otlp_metric_batches(payload),
        "traces": _build_otlp_trace_batches(payload),
    }
    base_headers = {"Content-Type": "application/json"}
    base_headers.update(profile.headers)

    for signal, batches in signal_batches.items():
        endpoint = _endpoint_for_signal(str(profile.endpoint), signal)
        for batch in batches:
            raw = json.dumps(batch, sort_keys=True).encode("utf-8")
            headers = dict(base_headers)
            body = _compress_body(raw, headers=headers)
            _post_otlp_with_retries(
                endpoint=endpoint,
                body=body,
                headers=headers,
                timeout_seconds=float(profile.timeout_seconds),
                sender=sender,
                sleeper=sleeper,
            )


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
            _export_otlp_payload(
                payload,
                profile=profile,
                sender=sender,
                sleeper=time.sleep,
            )
        except (urllib_error.URLError, TimeoutError, RuntimeError, OSError):
            # Telemetry delivery must be fail-open for control loops.
            pass
    return payload
