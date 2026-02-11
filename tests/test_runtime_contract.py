from __future__ import annotations

from pathlib import Path

from wicap_assist.cli import main
from wicap_assist.runtime_contract import (
    evaluate_runtime_contract,
    run_runtime_contract_check,
)


def test_runtime_contract_check_missing_contract_reports_error(tmp_path: Path) -> None:
    report = run_runtime_contract_check(repo_root=tmp_path)
    assert report["status"] == "missing_contract"
    assert int(report["failures"]) == 1
    assert report["checks"] == []


def test_evaluate_runtime_contract_passes_when_all_checks_green() -> None:
    contract = {
        "services": [
            {"name": "wicap-ui", "required_state": "up", "critical": True},
            {"name": "wicap-redis", "required_state": "up", "critical": True},
        ],
        "ports": [
            {"port": 8080, "required": True},
            {"port": 6379, "required": True},
        ],
        "http_endpoints": [
            {"name": "ui-health", "url": "http://127.0.0.1:8080/health", "required": True, "ok_status": [200]},
        ],
    }
    observation = {
        "service_status": {
            "docker": {
                "services": {
                    "wicap-ui": {"state": "up"},
                    "wicap-redis": {"state": "up"},
                }
            },
            "network": {
                "expected_ports": {"8080": True, "6379": True},
            },
            "http": {
                "ui-health": {"ok": True, "status_code": 200},
            },
        }
    }

    evaluated = evaluate_runtime_contract(contract=contract, observation=observation)
    assert evaluated["status"] == "pass"
    assert int(evaluated["failures"]) == 0


def test_evaluate_runtime_contract_fails_when_service_down() -> None:
    contract = {
        "services": [
            {"name": "wicap-ui", "required_state": "up", "critical": True},
        ],
    }
    observation = {
        "service_status": {
            "docker": {
                "services": {
                    "wicap-ui": {"state": "down"},
                }
            }
        }
    }
    evaluated = evaluate_runtime_contract(contract=contract, observation=observation)
    assert evaluated["status"] == "fail"
    assert int(evaluated["failures"]) == 1


def test_cli_contract_check_enforce_returns_nonzero(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "wicap_assist.cli.run_runtime_contract_check",
        lambda **kwargs: {
            "status": "fail",
            "contract_name": "wicap-default-runtime",
            "contract_version": "1.0.0",
            "contract_path": str(tmp_path / "runtime-contract.v1.json"),
            "failures": 1,
            "warnings": 0,
            "checks": [],
        },
    )

    rc = main(["contract-check", "--enforce"])
    assert rc == 2

    rc_no_enforce = main(["contract-check", "--no-enforce"])
    assert rc_no_enforce == 0


def test_cli_soak_run_blocks_when_runtime_contract_fails(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "wicap_assist.cli.run_runtime_contract_check",
        lambda **kwargs: {
            "status": "fail",
            "contract_name": "wicap-default-runtime",
            "contract_version": "1.0.0",
            "contract_path": str(tmp_path / "runtime-contract.v1.json"),
            "failures": 1,
            "warnings": 0,
            "checks": [],
        },
    )

    called = {"soak": False}

    def fake_run_supervised_soak(*args, **kwargs):  # type: ignore[no-untyped-def]
        called["soak"] = True
        return {}

    monkeypatch.setattr("wicap_assist.cli.run_supervised_soak", fake_run_supervised_soak)

    rc = main(
        [
            "--db",
            str(tmp_path / "assistant.db"),
            "soak-run",
            "--duration-minutes",
            "1",
            "--playwright-interval-minutes",
            "1",
        ]
    )
    assert rc == 2
    assert called["soak"] is False

