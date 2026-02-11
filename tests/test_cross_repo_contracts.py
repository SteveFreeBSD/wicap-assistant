from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


_ASSISTANT_ROOT = Path(__file__).resolve().parents[1]
_ASSISTANT_CONTRACT_DIR = _ASSISTANT_ROOT / "ops" / "contracts"
_ASSISTANT_FIXTURE_DIR = _ASSISTANT_ROOT / "tests" / "fixtures" / "wicap_contracts"


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


def test_assistant_wicap_contract_fixtures_are_present_and_versioned() -> None:
    event_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.event.v1.json")
    control_contract = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.control.v1.json")

    assert event_contract.get("schema") == "wicap.event.v1"
    assert event_contract.get("event_contract_version") == "wicap.event.v1"

    assert control_contract.get("schema") == "wicap.control.v1"
    assert control_contract.get("control_intent_version") == "wicap.control.v1"


def test_assistant_contract_fixtures_match_wicap_repo_contracts_when_available() -> None:
    repo_root = _wicap_repo_root()
    event_contract_path = repo_root / "ops" / "contracts" / "wicap.event.v1.json"
    control_contract_path = repo_root / "ops" / "contracts" / "wicap.control.v1.json"

    if not event_contract_path.exists() or not control_contract_path.exists():
        pytest.skip("WiCAP cross-repo contract files are unavailable in this environment")

    event_contract = _read_json(event_contract_path)
    event_fixture = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.event.v1.json")
    assert event_fixture == event_contract

    control_contract = _read_json(control_contract_path)
    control_fixture = _read_json(_ASSISTANT_FIXTURE_DIR / "wicap.control.v1.json")
    assert control_fixture == control_contract
