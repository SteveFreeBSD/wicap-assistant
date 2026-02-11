"""Deterministic managed soak guardrails and phase planning."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Sequence

from wicap_assist.soak_profiles import SoakProfile, SoakRunbook

ALLOWED_RUNNER_RELATIVE_PATHS = (
    Path("tests/soak_test.py"),
    Path("scripts/run_live_soak.py"),
)

ALLOWED_RUNNER_FLAGS = {
    "--duration-minutes",
    "--playwright-interval-minutes",
    "--baseline-path",
    "--baseline-update",
}

_VALUE_FLAGS = {
    "--duration-minutes",
    "--playwright-interval-minutes",
    "--baseline-path",
}
_STARTUP_STEP_RE = re.compile(
    r"(?:docker\s+compose\s+up|start_wicap\.py|soak_test\.py|run_live_soak\.py)",
    re.IGNORECASE,
)
_VERIFY_STEP_RE = re.compile(
    r"(?:check_wicap_status|playwright|pytest|docker\s+logs|journalctl)",
    re.IGNORECASE,
)


def allowed_runner_paths(repo_root: Path) -> tuple[Path, ...]:
    """Return canonical allowlisted soak harness runner paths for one repo root."""
    root = repo_root.resolve()
    return tuple((root / rel).resolve() for rel in ALLOWED_RUNNER_RELATIVE_PATHS)


def validate_runner_path(runner_path: Path, *, repo_root: Path) -> None:
    """Raise when runner path is not one of the canonical soak harness paths."""
    candidate = runner_path.resolve()
    if candidate not in set(allowed_runner_paths(repo_root)):
        raise ValueError(
            "runner_path is not allowlisted. expected one of: "
            + ", ".join(str(path) for path in allowed_runner_paths(repo_root))
        )


def validate_runner_command(command: Sequence[str], *, runner_path: Path) -> None:
    """Raise when command shape includes unexpected executables or flags."""
    if len(command) < 2:
        raise ValueError("runner command must include python executable and runner path")

    py_executable = str(command[0]).strip()
    if "python" not in Path(py_executable).name.lower():
        raise ValueError("runner command must start with a python executable")

    if Path(str(command[1])).resolve() != runner_path.resolve():
        raise ValueError("runner command path does not match resolved runner path")

    idx = 2
    while idx < len(command):
        token = str(command[idx]).strip()
        if token not in ALLOWED_RUNNER_FLAGS:
            raise ValueError(f"unexpected runner flag: {token}")

        if token in _VALUE_FLAGS:
            if idx + 1 >= len(command):
                raise ValueError(f"missing value for flag: {token}")
            value = str(command[idx + 1]).strip()
            if not value or value.startswith("--"):
                raise ValueError(f"invalid value for flag: {token}")
            idx += 2
            continue

        idx += 1


def planned_phases(*, managed_observe: bool) -> list[str]:
    """Return deterministic managed soak phase sequence."""
    phases = [
        "preflight_init",
        "soak_execute",
    ]
    if managed_observe:
        phases.append("observe")
    phases.extend(
        [
            "ingest_soaks",
            "incident_report",
            "finalize",
        ]
    )
    return phases


def evaluate_learning_readiness(
    profile: SoakProfile | None,
    runbook: SoakRunbook | None,
) -> dict[str, object]:
    """Compute deterministic readiness signal for learned soak operations."""
    profile_success_count = int(profile.success_count) if profile is not None else 0
    profile_evidence_count = int(profile.evidence_count) if profile is not None else 0
    runbook_steps = list(runbook.steps) if runbook is not None else []
    runbook_success_sessions = int(runbook.success_session_count) if runbook is not None else 0

    has_startup_step = any(_STARTUP_STEP_RE.search(step) for step in runbook_steps)
    has_verify_step = any(_VERIFY_STEP_RE.search(step) for step in runbook_steps)

    score = 0
    if profile_success_count >= 1:
        score += 1
    if profile_success_count >= 2:
        score += 1
    if profile_evidence_count >= 3:
        score += 1
    if runbook_success_sessions >= 1:
        score += 1
    if runbook_success_sessions >= 2:
        score += 1
    if len(runbook_steps) >= 3:
        score += 1
    if has_startup_step:
        score += 1
    if has_verify_step:
        score += 1

    if score >= 7:
        status = "ready"
    elif score >= 3:
        status = "partial"
    else:
        status = "insufficient"

    return {
        "status": status,
        "score": int(score),
        "max_score": 8,
        "profile_success_count": profile_success_count,
        "profile_evidence_count": profile_evidence_count,
        "runbook_steps_count": len(runbook_steps),
        "runbook_success_sessions": runbook_success_sessions,
        "has_startup_step": bool(has_startup_step),
        "has_verify_step": bool(has_verify_step),
    }


def build_manager_actions(
    *,
    learning_readiness: dict[str, object],
    runbook_steps: list[str],
    dry_run: bool,
    exit_code: int | None,
    runner_log: str | None,
    newest_soak_dir: str | None,
    incident_path: str | None,
) -> list[str]:
    """Build deterministic operator directives from learned evidence and run outcome."""
    actions: list[str] = []
    status = str(learning_readiness.get("status", "")).strip().lower()

    if status == "ready":
        actions.append("Use learned startup runbook as primary execution guide.")
    elif status == "partial":
        actions.append("Use learned runbook with caution and verify each startup step.")
    else:
        actions.append("Learning evidence is insufficient; review dry-run runbook before execution.")

    for step in runbook_steps[:5]:
        actions.append(f"Runbook step: {step}")

    if dry_run:
        actions.append("Dry-run only: no soak process executed.")
        return actions

    if int(exit_code or 0) == 0:
        if newest_soak_dir:
            actions.append(f"Review newest soak artifacts in: {newest_soak_dir}")
        if incident_path:
            actions.append(f"Review generated incident report: {incident_path}")
    else:
        if runner_log:
            actions.append(f"Inspect runner log for failure root cause: {runner_log}")
        if newest_soak_dir:
            actions.append(f"Review soak artifacts for failure evidence: {newest_soak_dir}")
    return actions


def build_operator_guidance(
    *,
    manager_actions: list[str],
    control_events: list[dict[str, object]],
    control_mode: str,
) -> list[str]:
    """Build concise operator-facing guidance from manager actions and control events."""
    lines: list[str] = []
    seen: set[str] = set()

    def add(line: str) -> None:
        value = line.strip()
        if not value or value in seen:
            return
        seen.add(value)
        lines.append(value)

    for action in manager_actions[:3]:
        add(action)

    for event in control_events:
        action = str(event.get("action", "")).strip()
        status = str(event.get("status", "")).strip()
        detail = event.get("detail_json", {})
        service = ""
        if isinstance(detail, dict):
            service = str(detail.get("service", "")).strip()
        service_prefix = f"{service}: " if service else ""
        if not action:
            if status == "escalated":
                reason = str(detail.get("reason", "")).strip() if isinstance(detail, dict) else ""
                if reason == "kill_switch_engaged":
                    add(
                        "Autonomous kill-switch engaged; no further automated actions will run until cleared."
                    )
                else:
                    add(f"{service_prefix}Recovery escalated; manual operator intervention required.")
            continue
        if action == "status_check":
            if status == "executed_ok":
                add(f"{service_prefix}Status check succeeded; continue monitoring service stability.")
            elif status in {"executed_fail", "missing_script", "rejected"}:
                add(f"{service_prefix}Status check failed; inspect check_wicap_status output and runner log.")
            elif status == "skipped_observe_mode":
                add("Observe mode skipped status check; use --control-mode assist/autonomous for active recovery.")
        elif action == "compose_up":
            if status == "executed_ok":
                add(f"{service_prefix}Compose recovery succeeded; verify services remain up for subsequent cycles.")
            elif status in {"executed_fail", "rejected"}:
                add(f"{service_prefix}Compose recovery failed; inspect docker compose logs before retry.")
            elif status == "skipped_observe_mode":
                add("Observe mode skipped compose recovery; use --control-mode assist/autonomous for active recovery.")
        elif action.startswith("restart_service:"):
            if status == "executed_ok":
                add(f"{service_prefix}Service restart succeeded; verify service health in subsequent cycles.")
            elif status in {"executed_fail", "rejected"}:
                add(f"{service_prefix}Service restart failed; inspect docker compose logs before broader recovery.")
            elif status == "skipped_observe_mode":
                add("Observe mode skipped service restart; use --control-mode assist/autonomous for active recovery.")
        elif action == "rollback_sequence":
            if status == "executed_ok":
                add(f"{service_prefix}Rollback sequence completed; verify service stability before continuing.")
            elif status in {"executed_fail", "escalated"}:
                add(f"{service_prefix}Rollback sequence failed or escalated; immediate operator intervention required.")

    if not lines:
        mode = str(control_mode).strip()
        if mode == "assist":
            add("Assist mode active; monitor control decisions and verify successful recovery checks.")
        elif mode == "autonomous":
            add("Autonomous mode active; monitor rollback events and kill-switch state during recovery.")
        else:
            add("Observe mode active; review live alerts and switch to assist mode when active recovery is needed.")
    return lines[:10]
