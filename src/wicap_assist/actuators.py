"""Allowlisted deterministic actuator calls for supervised live control."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Callable

from wicap_assist.control_planes import ControlPlanePolicy
from wicap_assist.probes import probe_http_health
from wicap_assist.util.redact import to_snippet

Runner = Callable[..., subprocess.CompletedProcess[str]]
ALLOWED_RESTART_SERVICES = {"wicap-ui", "wicap-processor", "wicap-scout", "wicap-redis"}
RESTART_SERVICE_ALIASES = {
    "ui": "wicap-ui",
    "processor": "wicap-processor",
    "scout": "wicap-scout",
    "redis": "wicap-redis",
}
_STATUS_FALLBACK_URL = "http://127.0.0.1:8080/health"
_STATUS_FALLBACK_COMMAND = ["internal_http_probe", _STATUS_FALLBACK_URL]


@dataclass(slots=True)
class ActuatorResult:
    status: str
    commands: list[list[str]]
    detail: str
    policy_trace: dict[str, object] | None = None


def _status_script_path(repo_root: Path) -> Path | None:
    candidates = (
        repo_root / "check_wicap_status.py",
        repo_root / "scripts" / "check_wicap_status.py",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _execute(
    *,
    command: list[str],
    repo_root: Path,
    runner: Runner,
    timeout_seconds: int,
) -> tuple[int, str]:
    result = runner(
        command,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
        timeout=max(1, int(timeout_seconds)),
    )
    stdout = getattr(result, "stdout", "")
    stderr = getattr(result, "stderr", "")
    merged = "\n".join(part for part in (stdout, stderr) if part)
    return int(result.returncode), to_snippet(merged, max_len=200) if merged else ""


def _internal_status_probe_detail(*, timeout_seconds: int) -> str:
    probe = probe_http_health(
        url=_STATUS_FALLBACK_URL,
        timeout_seconds=max(0.5, min(5.0, float(timeout_seconds))),
    )
    ok = bool(probe.get("ok"))
    status_code = probe.get("status_code")
    error = str(probe.get("error") or "").strip()
    return (
        f"internal_http_probe ok={ok} status_code={status_code} "
        f"error={error or 'none'}"
    )


def run_allowlisted_action(
    *,
    action: str,
    mode: str,
    repo_root: Path,
    runner: Runner,
    plane_policy: ControlPlanePolicy | None = None,
    timeout_seconds: int = 120,
) -> ActuatorResult:
    """Execute one allowlisted action in assist mode or return skip/reject status."""
    action_name = str(action).strip().lower()
    restart_service: str | None = None
    if action_name.startswith("restart_service:"):
        restart_service = action_name.split(":", 1)[1].strip()
        action_name = "restart_service"

    if action_name not in {"status_check", "compose_up", "compose_up_core", "shutdown", "restart_service"}:
        return ActuatorResult(status="rejected", commands=[], detail=f"unknown action: {action}")

    policy = plane_policy or ControlPlanePolicy.from_env()
    plane_decision = policy.evaluate(
        action_name=action_name,
        mode=str(mode),
        record_usage=str(mode).strip().lower() in {"assist", "autonomous"},
    )
    if not plane_decision.allowed:
        detail = plane_decision.reason
        if plane_decision.denied_by:
            detail = f"{plane_decision.denied_by}: {detail}"
        return ActuatorResult(
            status="rejected",
            commands=[],
            detail=detail,
            policy_trace=dict(plane_decision.policy_trace),
        )

    internal_status_fallback = False
    if action_name == "status_check":
        script = _status_script_path(repo_root)
        if script is None:
            internal_status_fallback = True
            commands = [list(_STATUS_FALLBACK_COMMAND)]
        else:
            if script.parent.name == "scripts":
                commands = [[sys.executable, "-m", "scripts.check_wicap_status", "--local-only", "--json"]]
            else:
                commands = [[sys.executable, str(script), "--local-only", "--json"]]
    elif action_name == "compose_up":
        commands = [["docker", "compose", "up", "-d"]]
    elif action_name == "compose_up_core":
        commands = [["docker", "compose", "up", "-d", "redis", "processor", "ui"]]
    elif action_name == "restart_service":
        service = str(restart_service or "").strip().lower()
        service = RESTART_SERVICE_ALIASES.get(service, service)
        if service not in ALLOWED_RESTART_SERVICES:
            return ActuatorResult(
                status="rejected",
                commands=[],
                detail=f"unknown restart service: {service or '<missing>'}",
            )
        # Use container restart here because probes and control ladders operate on
        # deterministic container names (wicap-*) while compose service keys are
        # short aliases (ui/processor/scout/redis).
        commands = [["docker", "restart", service]]
    else:
        stop_script = repo_root / "scripts" / "stop_wicap.py"
        commands = []
        if stop_script.exists():
            commands.append([sys.executable, str(stop_script)])
        commands.append(["docker", "compose", "down", "--remove-orphans"])

    if mode not in {"assist", "autonomous"}:
        return ActuatorResult(
            status="skipped_observe_mode",
            commands=commands,
            detail="observe mode: action not executed",
            policy_trace=dict(plane_decision.policy_trace),
        )

    if internal_status_fallback:
        return ActuatorResult(
            status="executed_ok",
            commands=commands,
            detail=_internal_status_probe_detail(timeout_seconds=timeout_seconds),
            policy_trace=dict(plane_decision.policy_trace),
        )

    details: list[str] = []
    for cmd in commands:
        try:
            rc, detail = _execute(
                command=cmd,
                repo_root=repo_root,
                runner=runner,
                timeout_seconds=timeout_seconds,
            )
        except Exception as exc:  # pragma: no cover - defensive path
            return ActuatorResult(
                status="executed_fail",
                commands=commands,
                detail=f"{type(exc).__name__}: {exc}",
                policy_trace=dict(plane_decision.policy_trace),
            )
        if detail:
            details.append(detail)
        if rc != 0:
            return ActuatorResult(
                status="executed_fail",
                commands=commands,
                detail=" | ".join(details),
                policy_trace=dict(plane_decision.policy_trace),
            )

    return ActuatorResult(
        status="executed_ok",
        commands=commands,
        detail=" | ".join(details),
        policy_trace=dict(plane_decision.policy_trace),
    )
