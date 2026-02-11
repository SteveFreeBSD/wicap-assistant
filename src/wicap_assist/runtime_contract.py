"""Versioned runtime contract loading and validation for WICAP environments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.probes import probe_docker, probe_http_health, probe_network
from wicap_assist.probes.docker_probe import ALLOWED_SERVICES

DEFAULT_RUNTIME_CONTRACT_REL_PATH = Path("ops/runtime-contract.v1.json")


def resolve_runtime_contract_path(
    *,
    repo_root: Path | None = None,
    contract_path: Path | None = None,
) -> Path:
    if contract_path is not None:
        return contract_path.expanduser().resolve()
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    return (resolved_repo_root / DEFAULT_RUNTIME_CONTRACT_REL_PATH).resolve()


def load_runtime_contract(
    *,
    repo_root: Path | None = None,
    contract_path: Path | None = None,
) -> tuple[dict[str, Any] | None, str | None, Path]:
    """Load runtime contract JSON, returning (payload, error_code, resolved_path)."""
    path = resolve_runtime_contract_path(repo_root=repo_root, contract_path=contract_path)
    if not path.exists():
        return None, "missing_contract", path
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, "invalid_contract_json", path
    if not isinstance(payload, dict):
        return None, "invalid_contract_shape", path
    return payload, None, path


def _service_specs(contract: dict[str, Any]) -> list[dict[str, Any]]:
    raw = contract.get("services", [])
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        out.append(item)
    return out


def _port_specs(contract: dict[str, Any]) -> list[dict[str, Any]]:
    raw = contract.get("ports", [])
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port"))
        except Exception:
            continue
        out.append({"port": port, "required": bool(item.get("required", True))})
    return out


def _endpoint_specs(contract: dict[str, Any]) -> list[dict[str, Any]]:
    raw = contract.get("http_endpoints", [])
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        statuses = item.get("ok_status", [200, 204])
        allowed: list[int] = []
        if isinstance(statuses, list):
            for value in statuses:
                try:
                    allowed.append(int(value))
                except Exception:
                    continue
        out.append(
            {
                "name": name or url,
                "url": url,
                "required": bool(item.get("required", True)),
                "ok_status": allowed or [200, 204],
            }
        )
    return out


def collect_runtime_observation(contract: dict[str, Any]) -> dict[str, Any]:
    """Collect one probe snapshot matching the contract shape."""
    services = [str(item.get("name", "")).strip() for item in _service_specs(contract)]
    service_tuple = tuple(value for value in services if value) or tuple(ALLOWED_SERVICES)

    ports = [int(item["port"]) for item in _port_specs(contract)]
    port_tuple = tuple(ports) or (8080, 6380)

    docker_payload = probe_docker(services=service_tuple)
    network_payload = probe_network(expected_ports=port_tuple)

    endpoint_payload: dict[str, dict[str, object]] = {}
    for spec in _endpoint_specs(contract):
        endpoint_payload[str(spec["name"])] = probe_http_health(url=str(spec["url"]))

    return {
        "service_status": {
            "docker": {
                "services": docker_payload.get("services", {}),
                "docker_ps_ok": bool(docker_payload.get("docker_ps_ok")),
            },
            "network": network_payload,
            "http": endpoint_payload,
        }
    }


def evaluate_runtime_contract(
    *,
    contract: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate one runtime observation against a loaded contract."""
    checks: list[dict[str, Any]] = []
    failures = 0
    warnings = 0

    service_status = observation.get("service_status", {})
    docker = service_status.get("docker", {}) if isinstance(service_status, dict) else {}
    services = docker.get("services", {}) if isinstance(docker, dict) else {}
    if not isinstance(services, dict):
        services = {}

    network = service_status.get("network", {}) if isinstance(service_status, dict) else {}
    expected_ports = network.get("expected_ports", {}) if isinstance(network, dict) else {}
    if not isinstance(expected_ports, dict):
        expected_ports = {}

    http_checks = service_status.get("http", {}) if isinstance(service_status, dict) else {}
    if not isinstance(http_checks, dict):
        http_checks = {}

    for spec in _service_specs(contract):
        name = str(spec.get("name", "")).strip()
        required_state = str(spec.get("required_state", "up")).strip().lower() or "up"
        critical = bool(spec.get("critical", True))
        actual = services.get(name, {}) if isinstance(services.get(name), dict) else {}
        actual_state = str(actual.get("state", "missing")).strip().lower()
        passed = actual_state == required_state
        severity = "fail" if (not passed and critical) else ("warn" if not passed else "pass")
        if severity == "fail":
            failures += 1
        elif severity == "warn":
            warnings += 1
        checks.append(
            {
                "kind": "service_state",
                "name": name,
                "required_state": required_state,
                "actual_state": actual_state,
                "critical": critical,
                "severity": severity,
                "ok": passed,
            }
        )

    for spec in _port_specs(contract):
        port = int(spec["port"])
        required = bool(spec.get("required", True))
        open_value = bool(expected_ports.get(str(port), False))
        passed = open_value if required else True
        severity = "fail" if (not passed and required) else "pass"
        if severity == "fail":
            failures += 1
        checks.append(
            {
                "kind": "network_port",
                "name": str(port),
                "required": required,
                "open": open_value,
                "severity": severity,
                "ok": passed,
            }
        )

    for spec in _endpoint_specs(contract):
        name = str(spec["name"])
        required = bool(spec.get("required", True))
        allowed = [int(value) for value in spec.get("ok_status", [200, 204])]
        result = http_checks.get(name, {}) if isinstance(http_checks.get(name), dict) else {}
        status_code = result.get("status_code")
        ok_by_status = bool(status_code in allowed) if status_code is not None else False
        ok_by_probe = bool(result.get("ok")) if isinstance(result, dict) else False
        passed = bool(ok_by_probe and ok_by_status)
        if not required:
            passed = True if not result else passed
        severity = "fail" if (not passed and required) else ("warn" if not passed else "pass")
        if severity == "fail":
            failures += 1
        elif severity == "warn":
            warnings += 1
        checks.append(
            {
                "kind": "http_endpoint",
                "name": name,
                "url": str(spec.get("url", "")),
                "allowed_statuses": allowed,
                "status_code": status_code,
                "probe_ok": ok_by_probe,
                "required": required,
                "severity": severity,
                "ok": passed,
            }
        )

    status = "pass" if failures == 0 else "fail"
    return {
        "status": status,
        "failures": int(failures),
        "warnings": int(warnings),
        "checks": checks,
    }


def run_runtime_contract_check(
    *,
    repo_root: Path | None = None,
    contract_path: Path | None = None,
) -> dict[str, Any]:
    """Load, probe, and evaluate one runtime contract check."""
    payload, error_code, resolved_path = load_runtime_contract(
        repo_root=repo_root,
        contract_path=contract_path,
    )
    if error_code is not None:
        return {
            "status": error_code,
            "contract_path": str(resolved_path),
            "contract_version": None,
            "contract_name": None,
            "failures": 1,
            "warnings": 0,
            "checks": [],
            "observation": None,
        }

    assert payload is not None
    observation = collect_runtime_observation(payload)
    evaluated = evaluate_runtime_contract(contract=payload, observation=observation)
    return {
        "status": str(evaluated.get("status", "fail")),
        "contract_path": str(resolved_path),
        "contract_version": str(payload.get("version", "")).strip() or None,
        "contract_name": str(payload.get("name", "")).strip() or None,
        "failures": int(evaluated.get("failures", 0)),
        "warnings": int(evaluated.get("warnings", 0)),
        "checks": evaluated.get("checks", []),
        "observation": observation,
    }


def runtime_contract_report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def format_runtime_contract_report_text(report: dict[str, Any]) -> str:
    lines = [
        "Runtime Contract Check",
        f"status={report.get('status')}",
        f"contract_name={report.get('contract_name')}",
        f"contract_version={report.get('contract_version')}",
        f"contract_path={report.get('contract_path')}",
        f"failures={report.get('failures')} warnings={report.get('warnings')}",
        "checks:",
    ]
    checks = report.get("checks", [])
    if isinstance(checks, list) and checks:
        for check in checks[:40]:
            if not isinstance(check, dict):
                continue
            severity = str(check.get("severity", ""))
            kind = str(check.get("kind", ""))
            name = str(check.get("name", ""))
            ok = bool(check.get("ok"))
            lines.append(f"- [{severity}] {kind}:{name} ok={ok}")
    else:
        lines.append("- (none)")
    return "\n".join(lines)
