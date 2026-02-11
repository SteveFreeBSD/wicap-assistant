from __future__ import annotations

import json
import os
from pathlib import Path
import re

import pytest


_REDIS_PORT_RE = re.compile(r"redis-server\s+--port\s+(\d+)")
_CONTAINER_NAME_RE = re.compile(r"^\s*container_name:\s*([A-Za-z0-9._-]+)\s*$", re.MULTILINE)


def _wicap_repo_root() -> Path:
    value = os.environ.get("WICAP_REPO_ROOT", "/home/steve/apps/wicap").strip()
    if not value:
        value = "/home/steve/apps/wicap"
    return Path(value).expanduser()


def test_runtime_contract_matches_compose_services_and_redis_port() -> None:
    repo_root = _wicap_repo_root()
    compose_path = repo_root / "docker-compose.yml"
    contract_path = repo_root / "ops" / "runtime-contract.v1.json"

    if not compose_path.exists() or not contract_path.exists():
        pytest.skip("WICAP compose/contract files are unavailable in this environment")

    compose_text = compose_path.read_text(encoding="utf-8")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    redis_match = _REDIS_PORT_RE.search(compose_text)
    assert redis_match is not None
    redis_port = int(redis_match.group(1))

    ports = contract.get("ports", [])
    assert isinstance(ports, list)
    required_ports = {
        int(item["port"])
        for item in ports
        if isinstance(item, dict) and bool(item.get("required", True))
    }
    assert redis_port in required_ports

    container_names = set(_CONTAINER_NAME_RE.findall(compose_text))
    services = contract.get("services", [])
    assert isinstance(services, list)
    for service in services:
        if not isinstance(service, dict):
            continue
        name = str(service.get("name", "")).strip()
        if not name:
            continue
        assert name in container_names
