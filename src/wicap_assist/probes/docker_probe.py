"""Read-only Docker runtime probes for WICAP services."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Callable

ALLOWED_SERVICES = (
    "wicap-ui",
    "wicap-processor",
    "wicap-scout",
    "wicap-redis",
)

Runner = Callable[..., subprocess.CompletedProcess[str]]


def _service_state(status: str) -> str:
    lowered = status.strip().lower()
    if "restarting" in lowered:
        return "restarting"
    if lowered.startswith("up"):
        return "up"
    if lowered.startswith("exited") or "dead" in lowered:
        return "down"
    if not lowered:
        return "down"
    return "unknown"


def _run_readonly(cmd: list[str], runner: Runner) -> subprocess.CompletedProcess[str]:
    return runner(cmd, capture_output=True, text=True, check=False)


def _probe_docker_sdk(services: tuple[str, ...], log_tail: int) -> dict[str, Any] | None:
    try:
        import docker  # type: ignore[import-untyped]
    except Exception:
        return None

    base_url = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
    try:
        client = docker.DockerClient(base_url=base_url)
        containers = client.containers.list(all=True)
    except Exception:
        return None

    service_status: dict[str, dict[str, str | None]] = {}
    service_logs: dict[str, list[str]] = {}

    for service in services:
        match = None
        for container in containers:
            names = container.attrs.get("Name", "") if isinstance(container.attrs, dict) else ""
            name = str(names).lstrip("/")
            if name == service or name.endswith(service):
                match = container
                break

        if match is None:
            service_status[service] = {
                "state": "down",
                "status": "not running",
                "container": None,
            }
            service_logs[service] = []
            continue

        state = match.attrs.get("State", {}) if isinstance(match.attrs, dict) else {}
        state_status = str(state.get("Status", "unknown"))
        status_text = str(match.status or state_status or "unknown")
        service_status[service] = {
            "state": _service_state(state_status or status_text),
            "status": status_text,
            "container": str(match.id),
            "name": str(match.name),
        }

        try:
            raw = match.logs(tail=max(1, int(log_tail)), stdout=True, stderr=True)
            decoded = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
            lines = [line.strip() for line in decoded.splitlines() if line.strip()]
        except Exception:
            lines = []
        service_logs[service] = lines

    return {
        "services": service_status,
        "logs": service_logs,
        "docker_ps_ok": True,
    }


def probe_docker(
    *,
    services: tuple[str, ...] = ALLOWED_SERVICES,
    log_tail: int = 200,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Probe docker service status and recent logs for a fixed allowlist."""
    if shutil.which("docker") is None:
        sdk_payload = _probe_docker_sdk(services, int(log_tail))
        if sdk_payload is not None:
            return sdk_payload

    try:
        ps_result = _run_readonly(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}\t{{.ID}}"],
            runner,
        )
    except FileNotFoundError:
        sdk_payload = _probe_docker_sdk(services, int(log_tail))
        if sdk_payload is not None:
            return sdk_payload
        return {
            "services": {
                service: {
                    "state": "down",
                    "status": "docker unavailable",
                    "container": None,
                }
                for service in services
            },
            "logs": {service: [] for service in services},
            "docker_ps_ok": False,
        }

    rows: list[tuple[str, str, str]] = []
    if ps_result.returncode == 0:
        for raw in ps_result.stdout.splitlines():
            parts = raw.split("\t")
            if len(parts) < 3:
                continue
            rows.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))

    service_status: dict[str, dict[str, str | None]] = {}
    for service in services:
        match = next((row for row in rows if row[0] == service or row[0].endswith(service)), None)
        if match is None:
            service_status[service] = {
                "state": "down",
                "status": "not running",
                "container": None,
            }
            continue

        name, status_text, container_id = match
        service_status[service] = {
            "state": _service_state(status_text),
            "status": status_text,
            "container": container_id,
            "name": name,
        }

    service_logs: dict[str, list[str]] = {}
    for service in services:
        try:
            log_result = _run_readonly(["docker", "logs", "--tail", str(int(log_tail)), service], runner)
        except FileNotFoundError:
            log_result = subprocess.CompletedProcess(args=["docker", "logs"], returncode=127, stdout="", stderr="")
        merged = "\n".join(part for part in (log_result.stdout, log_result.stderr) if part)
        lines = [line.strip() for line in merged.splitlines() if line.strip()]
        service_logs[service] = lines

    return {
        "services": service_status,
        "logs": service_logs,
        "docker_ps_ok": ps_result.returncode == 0,
    }
