from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.otlp_profile import OtlpProfile
from wicap_assist.telemetry import (
    TELEMETRY_EVENT_VERSION,
    build_control_cycle_telemetry,
    emit_control_cycle_telemetry,
)


def test_build_control_cycle_telemetry_matches_contract_shape() -> None:
    payload = build_control_cycle_telemetry(
        mode="assist",
        profile="assist-v1",
        decision="live_cycle",
        observation_cycle=3,
        actions_executed=1,
        anomaly_events=2,
        message="down services detected",
        attributes={"extra": "value"},
    )
    assert payload["telemetry_event_version"] == TELEMETRY_EVENT_VERSION
    assert {"service.name", "service.version", "deployment.environment"}.issubset(
        set(payload["resource"].keys())
    )
    assert isinstance(payload["traces"], list) and payload["traces"]
    assert isinstance(payload["metrics"], list) and payload["metrics"]
    assert isinstance(payload["logs"], list) and payload["logs"]

    metric_names = {entry["name"] for entry in payload["metrics"]}
    assert {
        "wicap.control.observation.cycles",
        "wicap.control.actions.executed",
        "wicap.anomaly.events.total",
    }.issubset(metric_names)
    span_attrs = payload["traces"][0]["attributes"]
    assert span_attrs["wicap.control.mode"] == "assist"
    assert span_attrs["wicap.control.profile"] == "assist-v1"


def test_emit_control_cycle_telemetry_persists_redacted_payload(tmp_path: Path) -> None:
    sink = tmp_path / "telemetry.jsonl"
    payload = emit_control_cycle_telemetry(
        mode="autonomous",
        profile="autonomous-v1",
        decision="soak_observe_cycle",
        observation_cycle=7,
        actions_executed=2,
        anomaly_events=5,
        message="token=abcd1234 password=secret",
        attributes={"auth": "Bearer abcdefgh"},
        sink_path=sink,
    )
    assert sink.exists()
    persisted = json.loads(sink.read_text(encoding="utf-8").splitlines()[0])
    assert persisted["telemetry_event_version"] == TELEMETRY_EVENT_VERSION
    assert "password=<redacted>" in persisted["logs"][0]["body"]
    assert "Bearer <redacted>" in persisted["logs"][0]["attributes"]["auth"]
    assert payload == persisted


def test_emit_control_cycle_telemetry_posts_to_otlp_when_profile_valid(tmp_path: Path) -> None:
    sink = tmp_path / "telemetry.jsonl"
    seen: dict[str, object] = {}

    class _Response:
        status = 200

    def fake_sender(request, timeout):  # type: ignore[no-untyped-def]
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["headers"] = dict(request.header_items())
        seen["body"] = request.data.decode("utf-8")
        return _Response()

    profile = OtlpProfile(
        profile="self_hosted",
        enabled=True,
        endpoint="http://localhost:4318/v1/logs",
        headers={"X-Token": "abc"},
        timeout_seconds=2.0,
        errors=[],
        warnings=[],
    )
    emit_control_cycle_telemetry(
        mode="assist",
        profile="assist-v1",
        decision="live_cycle",
        observation_cycle=1,
        actions_executed=0,
        anomaly_events=0,
        message="ok",
        sink_path=sink,
        otlp_profile=profile,
        otlp_sender=fake_sender,
    )
    assert seen["url"] == "http://localhost:4318/v1/logs"
    assert float(seen["timeout"]) == 2.0
    lowered_headers = {str(key).lower(): value for key, value in dict(seen["headers"]).items()}
    assert "content-type" in lowered_headers
    assert '"telemetry_event_version": "wicap.telemetry.v1"' in str(seen["body"])


def test_emit_control_cycle_telemetry_otlp_failure_is_fail_open(tmp_path: Path) -> None:
    sink = tmp_path / "telemetry.jsonl"

    def failing_sender(_request, timeout):  # type: ignore[no-untyped-def]
        raise OSError(f"timeout={timeout}")

    profile = OtlpProfile(
        profile="self_hosted",
        enabled=True,
        endpoint="http://localhost:4318/v1/logs",
        headers={},
        timeout_seconds=1.5,
        errors=[],
        warnings=[],
    )
    payload = emit_control_cycle_telemetry(
        mode="assist",
        profile="assist-v1",
        decision="live_cycle",
        observation_cycle=1,
        actions_executed=0,
        anomaly_events=0,
        message="ok",
        sink_path=sink,
        otlp_profile=profile,
        otlp_sender=failing_sender,
    )
    assert payload["telemetry_event_version"] == TELEMETRY_EVENT_VERSION
    assert sink.exists()
