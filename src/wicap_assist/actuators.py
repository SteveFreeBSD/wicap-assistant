"""Allowlisted deterministic actuator calls for supervised live control."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Callable

from wicap_assist.control_planes import ControlPlanePolicy
from wicap_assist.util.redact import to_snippet

Runner = Callable[..., subprocess.CompletedProcess[str]]
ALLOWED_RESTART_SERVICES = {"wicap-ui", "wicap-processor", "wicap-scout", "wicap-redis"}


@dataclass(slots=True)
class ActuatorResult:
    status: str
    commands: list[list[str]]
    detail: str


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

    if action_name not in {"status_check", "compose_up", "shutdown", "restart_service"}:
        return ActuatorResult(status="rejected", commands=[], detail=f"unknown action: {action}")

    policy = plane_policy or ControlPlanePolicy.from_env()
    plane_decision = policy.evaluate(action_name=action_name)
    if not plane_decision.allowed:
        detail = plane_decision.reason
        if plane_decision.denied_by:
            detail = f"{plane_decision.denied_by}: {detail}"
        return ActuatorResult(status="rejected", commands=[], detail=detail)

    if action_name == "status_check":
        script = _status_script_path(repo_root)
        if script is None:
            return ActuatorResult(status="missing_script", commands=[], detail="status check script not found")
        if script.parent.name == "scripts":
            commands = [[sys.executable, "-m", "scripts.check_wicap_status", "--local-only", "--json"]]
        else:
            commands = [[sys.executable, str(script), "--local-only", "--json"]]
    elif action_name == "compose_up":
        commands = [["docker", "compose", "up", "-d"]]
    elif action_name == "restart_service":
        service = str(restart_service or "").strip()
        if service not in ALLOWED_RESTART_SERVICES:
            return ActuatorResult(
                status="rejected",
                commands=[],
                detail=f"unknown restart service: {service or '<missing>'}",
            )
        commands = [["docker", "compose", "restart", service]]
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
            )
        if detail:
            details.append(detail)
        if rc != 0:
            return ActuatorResult(
                status="executed_fail",
                commands=commands,
                detail=" | ".join(details),
            )

    return ActuatorResult(status="executed_ok", commands=commands, detail=" | ".join(details))
