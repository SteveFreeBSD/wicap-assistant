from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


_ASSISTANT_ROOT = Path(__file__).resolve().parents[1]
_ASSISTANT_CONTRACT_DIR = _ASSISTANT_ROOT / "ops" / "contracts"
_ASSISTANT_FIXTURE_DIR = _ASSISTANT_ROOT / "tests" / "fixtures" / "wicap_contracts"
_WICAP_CONTRACT_NAMES = (
    "wicap.event.v1.json",
    "wicap.control.v1.json",
    "wicap.control.v2.json",
    "wicap.anomaly.v1.json",
    "wicap.anomaly.v2.json",
    "wicap.anomaly.v3.json",
    "wicap.feedback.v1.json",
    "wicap.prediction.v1.json",
)


def _read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _wicap_repo_root() -> Path:
    value = os.environ.get("WICAP_REPO_ROOT", "/home/steve/apps/wicap").strip()
    if not value:
        value = "/home/steve/apps/wicap"
    return Path(value).expanduser()


def test_telemetry_contract_shape_is_provider_neutral_otlp() -> None:
    contract = _read_json(_ASSISTANT_CONTRACT_DIR / "wicap.telemetry.v1.json")

    assert contract.get("schema") == "wicap.telemetry.v1"
    assert contract.get("telemetry_event_version") == "wicap.telemetry.v1"
    assert contract.get("protocol") == "otlp"
    assert contract.get("otlp_spec_reference") == "https://opentelemetry.io/docs/specs/otlp/"

    required_signal_types = contract.get("required_signal_types")
    assert isinstance(required_signal_types, list)
    assert {str(item) for item in required_signal_types} == {"traces", "metrics", "logs"}

    required_span_attributes = contract.get("required_span_attributes")
    assert isinstance(required_span_attributes, list)
    assert {str(item) for item in required_span_attributes} >= {
        "wicap.control.mode",
        "wicap.control.profile",
        "wicap.control.decision",
    }

    assert bool(contract.get("redaction_required")) is True


def test_telemetry_v2_contract_declares_new_event_families() -> None:
    contract = _read_json(_ASSISTANT_CONTRACT_DIR / "wicap.telemetry.v2.json")
    assert contract.get("schema") == "wicap.telemetry.v2"
    assert contract.get("telemetry_event_version") == "wicap.telemetry.v2"
    event_families = contract.get("event_families")
    assert isinstance(event_families, list)
    assert {str(item) for item in event_families} >= {
        "policy.decision",
        "failover.transition",
        "memory.compaction",
        "mission.step",
        "certification.result",
    }


def test_assistant_wicap_contract_fixtures_are_present_and_versioned() -> None:
    event_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.event.v1.json")
    control_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.control.v1.json")
    control_v2_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.control.v2.json")
    anomaly_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.anomaly.v1.json")
    anomaly_v2_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.anomaly.v2.json")
    anomaly_v3_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.anomaly.v3.json")
    feedback_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.feedback.v1.json")
    prediction_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.prediction.v1.json")

    assert event_contract.get("schema") == "wicap.event.v1"
    assert event_contract.get("event_contract_version") == "wicap.event.v1"

    assert control_contract.get("schema") == "wicap.control.v1"
    assert control_contract.get("control_intent_version") == "wicap.control.v1"
    assert control_v2_contract.get("schema") == "wicap.control.v2"
    assert control_v2_contract.get("control_intent_version") == "wicap.control.v2"

    assert anomaly_contract.get("schema") == "wicap.anomaly.v1"
    assert anomaly_contract.get("anomaly_contract_version") == "wicap.anomaly.v1"

    assert anomaly_v2_contract.get("schema") == "wicap.anomaly.v2"
    assert anomaly_v2_contract.get("anomaly_contract_version") == "wicap.anomaly.v2"
    assert anomaly_v3_contract.get("schema") == "wicap.anomaly.v3"
    assert anomaly_v3_contract.get("anomaly_contract_version") == "wicap.anomaly.v3"

    assert feedback_contract.get("schema") == "wicap.feedback.v1"
    assert feedback_contract.get("feedback_contract_version") == "wicap.feedback.v1"

    assert prediction_contract.get("schema") == "wicap.prediction.v1"
    assert prediction_contract.get("prediction_contract_version") == "wicap.prediction.v1"


def test_assistant_wicap_fixture_inventory_matches_expected_contract_set() -> None:
    fixtures = {path.name for path in _ASSISTANT_FIXTURE_DIR.glob("wicap.*.json")}
    assert set(_WICAP_CONTRACT_NAMES).issubset(fixtures)


def test_assistant_contract_fixtures_match_wicap_repo_contracts_when_available() -> None:
    repo_root = _wicap_repo_root()
    contract_dir = repo_root / "ops" / "contracts"
    contract_paths = [contract_dir / name for name in _WICAP_CONTRACT_NAMES]
    if any(not path.exists() for path in contract_paths):
        pytest.skip("WiCAP cross-repo contract files are unavailable in this environment")

    for name in _WICAP_CONTRACT_NAMES:
        contract = _read_json(contract_dir / name)
        fixture = _read_json(_ASSISTANT_FIXTURE_DIR / name)
        assert fixture == contract
