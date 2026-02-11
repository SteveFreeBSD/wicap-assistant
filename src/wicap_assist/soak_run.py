"""Supervised soak runner orchestration for one-command WICAP soak execution."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from typing import Any, Callable

from wicap_assist.actuators import run_allowlisted_action
from wicap_assist.bundle import build_bundle
from wicap_assist.config import wicap_repo_root
from wicap_assist.db import (
    close_running_control_sessions,
    insert_control_event,
    insert_control_session,
    insert_control_session_event,
    insert_live_observation,
    insert_soak_run,
    update_control_session,
)
from wicap_assist.incident import write_incident_report
from wicap_assist.ingest.soak_logs import ingest_soak_logs
from wicap_assist.live import collect_live_cycle
from wicap_assist.soak_control import ControlPolicy
from wicap_assist.soak_manager import (
    build_manager_actions,
    build_operator_guidance,
    evaluate_learning_readiness,
    planned_phases,
    validate_runner_command,
    validate_runner_path,
)
from wicap_assist.soak_profiles import learn_soak_runbook, select_learned_soak_profile
from wicap_assist.util.time import utc_now_iso

SOAK_RUNS_ROOT = Path("data/soak_runs")


RunnerFn = Callable[..., subprocess.CompletedProcess[str]]
ProcessFactoryFn = Callable[..., subprocess.Popen[str]]
IngestHook = Callable[[sqlite3.Connection, Path], tuple[int, int]]
IncidentHook = Callable[[sqlite3.Connection, str], Path]
ObserveHook = Callable[[sqlite3.Connection], dict[str, Any]]
ProgressHook = Callable[[dict[str, Any]], None]
ControlRunnerFn = Callable[..., subprocess.CompletedProcess[str]]


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,),
    ).fetchone()
    return row is not None


def resolve_runner_path(
    conn: sqlite3.Connection,
    repo_root: Path | None = None,
    *,
    prefer_live_runner: bool = False,
) -> Path:
    """Resolve canonical soak runner path with preferred->fallback ordering."""
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    preferred = resolved_repo_root / "tests" / "soak_test.py"
    fallback = resolved_repo_root / "scripts" / "run_live_soak.py"
    candidates = (fallback, preferred) if bool(prefer_live_runner) else (preferred, fallback)

    if _table_exists(conn, "harness_scripts"):
        rows = conn.execute(
            "SELECT script_path FROM harness_scripts WHERE script_path IN (?, ?)",
            (str(preferred), str(fallback)),
        ).fetchall()
        inventory_paths = {str(row["script_path"]) for row in rows}

        for candidate in candidates:
            if str(candidate) in inventory_paths and candidate.exists():
                return candidate

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "No canonical soak harness found. Expected one of: "
        f"{preferred}, {fallback}"
    )


def _scan_soak_dirs(repo_root: Path) -> list[Path]:
    dirs = [path for path in repo_root.glob("logs_soak_*") if path.is_dir()]
    dirs.sort(
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    return dirs


def _write_cycle_snapshot(
    run_dir: Path,
    *,
    cycle: int,
    observation: dict[str, Any],
    down_services: list[str],
    control_events: list[dict[str, Any]],
) -> Path | None:
    alert = str(observation.get("alert", "")).strip()
    top_signatures = observation.get("top_signatures", [])
    if not down_services and not alert and not top_signatures and not control_events:
        return None

    snapshot_dir = run_dir / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshot_dir / f"cycle-{int(cycle):04d}.json"

    payload = {
        "cycle": int(cycle),
        "ts": str(observation.get("ts", "")),
        "alert": alert,
        "down_services": sorted(str(name) for name in down_services),
        "top_signatures": top_signatures if isinstance(top_signatures, list) else [],
        "service_status": observation.get("service_status", {}),
        "control_events": control_events,
    }
    snapshot_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return snapshot_path


def _terminate_process(proc: subprocess.Popen[str]) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def _build_runner_command(
    runner_path: Path,
    *,
    duration_minutes: int,
    playwright_interval_minutes: int,
    baseline_path: Path | None,
    baseline_update: bool,
) -> list[str]:
    command = [
        sys.executable,
        str(runner_path),
        "--duration-minutes",
        str(int(duration_minutes)),
        "--playwright-interval-minutes",
        str(int(playwright_interval_minutes)),
    ]

    if baseline_path is not None:
        command.extend(["--baseline-path", str(baseline_path)])
    if baseline_update:
        command.append("--baseline-update")

    return command


def ingest_soaks_for_run(conn: sqlite3.Connection, repo_root: Path) -> tuple[int, int]:
    """Hook point for soak ingest after runner completion."""
    return ingest_soak_logs(conn, repo_root=repo_root)


def generate_incident_for_soak(conn: sqlite3.Connection, target: str) -> Path:
    """Hook point for incident generation after soak ingest."""
    bundle = build_bundle(conn, target)
    return write_incident_report(conn, target=target, bundle=bundle, overwrite=True)


def observe_live_cycle_for_soak(conn: sqlite3.Connection) -> dict[str, Any]:
    """Collect+persist one live observation cycle for managed soak babysit."""
    observation = collect_live_cycle(conn)
    row_id = insert_live_observation(
        conn,
        ts=str(observation.get("ts", utc_now_iso())),
        service_status_json=observation.get("service_status", {}),
        top_signatures_json=observation.get("top_signatures", []),
        recommended_json=observation.get("recommended", []),
    )
    observation["observation_id"] = row_id
    conn.commit()
    return observation


def _spawn_runner_process(
    command: list[str],
    *,
    repo_root: Path,
    handle,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        command,
        cwd=str(repo_root),
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )


def run_supervised_soak(
    conn: sqlite3.Connection,
    *,
    duration_minutes: int | None,
    playwright_interval_minutes: int | None,
    baseline_path: Path | None,
    baseline_update: bool | None,
    dry_run: bool,
    managed_observe: bool = False,
    observe_interval_seconds: float = 10.0,
    control_mode: str = "observe",
    control_check_threshold: int | None = None,
    control_recover_threshold: int | None = None,
    control_max_recover_attempts: int | None = None,
    control_action_cooldown_cycles: int | None = None,
    stop_on_escalation: bool = True,
    post_run_cleanup: bool = True,
    repo_root: Path | None = None,
    run_root: Path = SOAK_RUNS_ROOT,
    runner: RunnerFn = subprocess.run,
    control_runner: ControlRunnerFn = subprocess.run,
    process_factory: ProcessFactoryFn = _spawn_runner_process,
    ingest_hook: IngestHook = ingest_soaks_for_run,
    incident_hook: IncidentHook = generate_incident_for_soak,
    observe_hook: ObserveHook = observe_live_cycle_for_soak,
    progress_hook: ProgressHook | None = None,
) -> dict[str, Any]:
    """Run one supervised soak and post-process artifacts.

    Returns a deterministic summary payload. In dry-run mode, no subprocess or DB writes occur.
    """
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    learned_profile = select_learned_soak_profile(conn, repo_root=resolved_repo_root)
    learned_runbook = learn_soak_runbook(conn, max_steps=8)
    learning_readiness = evaluate_learning_readiness(learned_profile, learned_runbook)

    effective_duration = int(duration_minutes) if duration_minutes is not None else (
        learned_profile.duration_minutes if learned_profile and learned_profile.duration_minutes else 30
    )
    effective_interval = int(playwright_interval_minutes) if playwright_interval_minutes is not None else (
        learned_profile.playwright_interval_minutes if learned_profile and learned_profile.playwright_interval_minutes else 15
    )
    effective_baseline_path: Path | None = baseline_path
    if effective_baseline_path is None and learned_profile and learned_profile.baseline_path:
        effective_baseline_path = Path(learned_profile.baseline_path)
    effective_baseline_update = (
        bool(baseline_update)
        if baseline_update is not None
        else bool(learned_profile.baseline_update) if learned_profile and learned_profile.baseline_update is not None else False
    )

    if effective_duration <= 0:
        raise ValueError("duration_minutes must be > 0")
    if effective_interval <= 0:
        raise ValueError("playwright_interval_minutes must be > 0")

    # Keep canonical runner selection deterministic (preferred -> fallback).
    runner_path = resolve_runner_path(
        conn,
        repo_root=resolved_repo_root,
        prefer_live_runner=bool(managed_observe and str(control_mode) in {"assist", "autonomous"}),
    )
    validate_runner_path(runner_path, repo_root=resolved_repo_root)
    command = _build_runner_command(
        runner_path,
        duration_minutes=effective_duration,
        playwright_interval_minutes=effective_interval,
        baseline_path=effective_baseline_path,
        baseline_update=effective_baseline_update,
    )
    validate_runner_command(command, runner_path=runner_path)
    timeout_seconds = int((effective_duration + 5) * 60)
    phase_plan = planned_phases(managed_observe=bool(managed_observe))
    phase_trace: list[dict[str, str]] = []
    control_events: list[dict[str, Any]] = []
    preflight_actions: list[dict[str, Any]] = []
    control_session_id: int | None = None
    control_actions_executed = 0
    control_escalations = 0

    control_policy = ControlPolicy(
        mode=str(control_mode),
        repo_root=resolved_repo_root,
        runner=control_runner,
        check_threshold=control_check_threshold,
        recover_threshold=control_recover_threshold,
        max_recover_attempts=control_max_recover_attempts,
        action_cooldown_cycles=control_action_cooldown_cycles,
    )
    resolved_check_threshold = int(control_policy.check_threshold)
    resolved_recover_threshold = int(control_policy.recover_threshold)
    resolved_max_recover_attempts = int(control_policy.max_recover_attempts)
    resolved_action_cooldown = int(control_policy.action_cooldown_cycles)
    resolved_profile_name = str(control_policy.profile_name)
    resolved_kill_switch_env = str(control_policy.kill_switch_env_var or "")
    resolved_kill_switch_file = (
        str(control_policy.kill_switch_file)
        if control_policy.kill_switch_file is not None
        else None
    )
    resolved_rollback_actions = list(control_policy.rollback_actions or ())
    resolved_control_execution_mode = (
        "assist"
        if str(control_mode) in {"assist", "autonomous"}
        else "observe"
    )

    def emit_progress(payload: dict[str, Any]) -> None:
        if progress_hook is None:
            return
        progress_hook(payload)

    def mark_phase(phase: str, status: str) -> None:
        event = {
            "phase": phase,
            "status": status,
            "ts": utc_now_iso(),
        }
        phase_trace.append(event)
        if control_session_id is not None:
            insert_control_session_event(
                conn,
                control_session_id=int(control_session_id),
                ts=str(event["ts"]),
                phase=str(phase),
                status=str(status),
                detail_json={
                    "mode": str(control_mode),
                    "profile": resolved_profile_name,
                },
            )
            session_status = "running"
            if status == "failed":
                session_status = "failed"
            elif status == "escalated":
                session_status = "escalated"
            elif phase == "finalize" and status == "completed":
                session_status = "completed"
            update_control_session(
                conn,
                control_session_id=int(control_session_id),
                status=session_status,
                current_phase=str(phase),
                handoff_state="active",
                last_heartbeat_ts=str(event["ts"]),
            )
        emit_progress({"event": "phase", **event})

    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir = run_root / run_stamp
    runner_log = run_dir / "runner.log"

    current_dirs = _scan_soak_dirs(resolved_repo_root)
    newest_current = current_dirs[0] if current_dirs else None

    if dry_run:
        emit_progress(
            {
                "event": "dry_run_plan",
                "phase_plan": list(phase_plan),
                "runner_path": str(runner_path),
            }
        )
        manager_actions = build_manager_actions(
            learning_readiness=learning_readiness,
            runbook_steps=list(learned_runbook.steps),
            dry_run=True,
            exit_code=None,
            runner_log=str(runner_log),
            newest_soak_dir=str(newest_current) if newest_current else None,
            incident_path=None,
        )
        operator_guidance = build_operator_guidance(
            manager_actions=manager_actions,
            control_events=[],
            control_mode=str(control_mode),
        )
        return {
            "dry_run": True,
            "run_id": None,
            "control_session_id": None,
            "exit_code": None,
            "runner_path": str(runner_path),
            "command": command,
            "timeout_seconds": timeout_seconds,
            "effective_duration_minutes": effective_duration,
            "effective_playwright_interval_minutes": effective_interval,
            "run_dir": str(run_dir),
            "runner_log": str(runner_log),
            "newest_soak_dir": str(newest_current) if newest_current else None,
            "incident_path": None,
            "detected_soak_dirs": [],
            "managed_observe": bool(managed_observe),
            "observe_interval_seconds": float(observe_interval_seconds),
            "control_mode": str(control_mode),
            "control_policy_profile": resolved_profile_name,
            "control_check_threshold": int(resolved_check_threshold),
            "control_recover_threshold": int(resolved_recover_threshold),
            "control_max_recover_attempts": int(resolved_max_recover_attempts),
            "control_action_cooldown_cycles": int(resolved_action_cooldown),
            "control_kill_switch_env_var": resolved_kill_switch_env or None,
            "control_kill_switch_file": resolved_kill_switch_file,
            "control_rollback_enabled": bool(control_policy.rollback_enabled),
            "control_rollback_actions": resolved_rollback_actions,
            "control_rollback_max_attempts": int(control_policy.rollback_max_attempts or 1),
            "stop_on_escalation": bool(stop_on_escalation),
            "post_run_cleanup": bool(post_run_cleanup),
            "control_actions_executed": 0,
            "control_escalations": 0,
            "control_events_count": 0,
            "escalation_hard_stop": False,
            "escalation_reason": None,
            "snapshot_count": 0,
            "snapshot_dir": str(run_dir / "snapshots"),
            "snapshot_paths": [],
            "preflight_actions": [],
            "cleanup_status": None,
            "cleanup_commands": [],
            "cleanup_detail": None,
            "phase_plan": phase_plan,
            "learning_readiness": learning_readiness,
            "manager_actions": manager_actions,
            "operator_guidance": operator_guidance,
            "learned_profile": (
                {
                    "runner_path": learned_profile.runner_path,
                    "duration_minutes": learned_profile.duration_minutes,
                    "playwright_interval_minutes": learned_profile.playwright_interval_minutes,
                    "baseline_path": learned_profile.baseline_path,
                    "baseline_update": learned_profile.baseline_update,
                    "score": learned_profile.score,
                    "evidence_count": learned_profile.evidence_count,
                    "success_count": learned_profile.success_count,
                    "fail_count": learned_profile.fail_count,
                    "session_ids": learned_profile.session_ids,
                }
                if learned_profile is not None
                else None
            ),
            "learned_runbook": {
                "steps": learned_runbook.steps,
                "success_session_count": learned_runbook.success_session_count,
                "session_ids": learned_runbook.session_ids,
            },
        }

    before_dirs = {str(path.resolve()) for path in _scan_soak_dirs(resolved_repo_root)}

    started_ts = utc_now_iso()
    run_dir.mkdir(parents=True, exist_ok=True)
    interrupted_sessions = close_running_control_sessions(
        conn,
        ended_ts=started_ts,
        reason="superseded_by_new_soak_run",
    )
    control_session_id = insert_control_session(
        conn,
        soak_run_id=None,
        started_ts=started_ts,
        last_heartbeat_ts=started_ts,
        mode=str(control_mode),
        status="running",
        current_phase="preflight_init",
        handoff_state="new",
        metadata_json={
            "managed_observe": bool(managed_observe),
            "observe_interval_seconds": float(observe_interval_seconds),
            "control_policy_profile": resolved_profile_name,
            "control_check_threshold": int(resolved_check_threshold),
            "control_recover_threshold": int(resolved_recover_threshold),
            "control_max_recover_attempts": int(resolved_max_recover_attempts),
            "control_action_cooldown_cycles": int(resolved_action_cooldown),
            "control_kill_switch_env_var": resolved_kill_switch_env or None,
            "control_kill_switch_file": resolved_kill_switch_file,
            "control_rollback_enabled": bool(control_policy.rollback_enabled),
            "control_rollback_actions": resolved_rollback_actions,
            "control_rollback_max_attempts": int(control_policy.rollback_max_attempts or 1),
            "stop_on_escalation": bool(stop_on_escalation),
            "post_run_cleanup": bool(post_run_cleanup),
            "interrupted_sessions_closed": int(interrupted_sessions),
        },
    )
    insert_control_session_event(
        conn,
        control_session_id=int(control_session_id),
        ts=started_ts,
        phase="preflight_init",
        status="started",
        detail_json={
            "mode": str(control_mode),
            "profile": resolved_profile_name,
        },
    )

    preflight_issue_count = 0
    startup_actions = ["compose_up", "status_check"] if bool(managed_observe) else ["status_check"]
    for action in startup_actions:
        action_result = run_allowlisted_action(
            action=action,
            mode=resolved_control_execution_mode,
            repo_root=resolved_repo_root,
            runner=control_runner,
            timeout_seconds=120,
        )
        action_commands = list(action_result.commands)
        action_status = str(action_result.status)
        action_detail = str(action_result.detail or "")
        preflight_event = {
            "ts": utc_now_iso(),
            "decision": "preflight_startup",
            "action": str(action),
            "status": action_status,
            "detail_json": {
                "commands": action_commands,
                "detail": action_detail,
            },
        }
        preflight_actions.append(preflight_event)
        control_events.append(preflight_event)
        if action_status.startswith("executed_"):
            control_actions_executed += 1
        if action_status in {"executed_fail", "missing_script", "rejected"}:
            preflight_issue_count += 1
        if control_session_id is not None:
            insert_control_session_event(
                conn,
                control_session_id=int(control_session_id),
                ts=str(preflight_event["ts"]),
                phase="preflight_init",
                status=f"startup_{action_status}",
                detail_json=preflight_event["detail_json"],
            )
        emit_progress(
            {
                "event": "control_event",
                "decision": preflight_event["decision"],
                "action": str(action),
                "status": action_status,
                "service": "preflight",
            }
        )

    preflight_status = "completed"
    if str(learning_readiness.get("status", "")) != "ready":
        preflight_status = "warning"
    if preflight_issue_count > 0:
        preflight_status = "warning"
    mark_phase("preflight_init", preflight_status)
    exit_code = 1
    observation_cycles = 0
    alert_cycles = 0
    down_service_cycles = 0
    signature_counts: Counter[str] = Counter()
    snapshot_paths: list[str] = []
    escalation_hard_stop = False
    escalation_reason: str | None = None
    cleanup_status: str | None = None
    cleanup_commands: list[list[str]] = []
    cleanup_detail: str | None = None
    with runner_log.open("w", encoding="utf-8") as handle:
        handle.write(f"[soak-run] started_ts={started_ts}\n")
        handle.write(f"[soak-run] command={' '.join(command)}\n")
        handle.write(f"[soak-run] managed_observe={bool(managed_observe)}\n")
        handle.flush()
        emit_progress(
            {
                "event": "runner_start",
                "ts": started_ts,
                "timeout_seconds": timeout_seconds,
                "command": list(command),
                "managed_observe": bool(managed_observe),
            }
        )

        if not managed_observe:
            try:
                result = runner(
                    command,
                    cwd=str(resolved_repo_root),
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                    timeout=timeout_seconds,
                )
                exit_code = int(result.returncode)
            except subprocess.TimeoutExpired:
                exit_code = 124
                handle.write(f"\n[soak-run] timeout after {timeout_seconds} seconds\n")
            mark_phase("soak_execute", "completed" if exit_code == 0 else "failed")
        else:
            proc = process_factory(command, repo_root=resolved_repo_root, handle=handle)
            start_monotonic = time.monotonic()
            next_observe_at = start_monotonic
            sleep_seconds = max(0.1, float(observe_interval_seconds))

            timed_out = False
            while True:
                now = time.monotonic()
                if now >= next_observe_at:
                    observation = observe_hook(conn)
                    observation_cycles += 1
                    alert_value = str(observation.get("alert", "")).strip()
                    if alert_value:
                        alert_cycles += 1

                    service_status = observation.get("service_status", {})
                    docker = service_status.get("docker", {}) if isinstance(service_status, dict) else {}
                    services = docker.get("services", {}) if isinstance(docker, dict) else {}
                    down_services: list[str] = []
                    if isinstance(services, dict):
                        for service_name, info in services.items():
                            if not isinstance(info, dict):
                                continue
                            if str(info.get("state", "unknown")) != "up":
                                down_services.append(str(service_name))
                        if down_services:
                            down_service_cycles += 1

                    top_signatures = observation.get("top_signatures", [])
                    top_signature = ""
                    if isinstance(top_signatures, list):
                        for item in top_signatures:
                            if not isinstance(item, dict):
                                continue
                            signature = str(item.get("signature", "")).strip()
                            if not signature:
                                continue
                            if not top_signature:
                                top_signature = signature
                            signature_counts[signature] += int(item.get("count", 0) or 0)
                    emit_progress(
                        {
                            "event": "observe_cycle",
                            "cycle": int(observation_cycles),
                            "alert": bool(alert_value),
                            "alert_text": alert_value,
                            "down_services": down_services,
                            "top_signature": top_signature,
                            "top_signature_count": int(signature_counts.get(top_signature, 0)) if top_signature else 0,
                        }
                    )

                    cycle_control_events = control_policy.process_observation(observation)
                    for event in cycle_control_events:
                        control_events.append(event)
                        status = str(event.get("status", ""))
                        if status.startswith("executed_"):
                            control_actions_executed += 1
                        if status == "escalated":
                            control_escalations += 1
                        detail = event.get("detail_json", {})
                        service = detail.get("service") if isinstance(detail, dict) else None
                        emit_progress(
                            {
                                "event": "control_event",
                                "decision": event.get("decision"),
                                "action": event.get("action"),
                                "status": status,
                                "service": service,
                            }
                        )

                    snapshot_path = _write_cycle_snapshot(
                        run_dir,
                        cycle=observation_cycles,
                        observation=observation,
                        down_services=down_services,
                        control_events=cycle_control_events,
                    )
                    if snapshot_path is not None:
                        snapshot_paths.append(str(snapshot_path))

                    if stop_on_escalation:
                        escalated = next(
                            (
                                event
                                for event in cycle_control_events
                                if str(event.get("status", "")) == "escalated"
                            ),
                            None,
                        )
                        if escalated is not None:
                            escalation_hard_stop = True
                            detail = escalated.get("detail_json", {})
                            if isinstance(detail, dict):
                                service_name = str(detail.get("service", "")).strip()
                                reason = str(detail.get("reason", "")).strip()
                                if service_name and reason:
                                    escalation_reason = f"{service_name}:{reason}"
                                elif service_name:
                                    escalation_reason = service_name
                            if not escalation_reason:
                                escalation_reason = "control_escalated"
                            emit_progress(
                                {
                                    "event": "escalation_stop",
                                    "reason": escalation_reason,
                                    "cycle": int(observation_cycles),
                                }
                            )
                            handle.write(
                                f"[soak-run] escalation_stop cycle={observation_cycles} reason={escalation_reason}\n"
                            )
                            _terminate_process(proc)
                            rc = proc.poll()
                            exit_code = int(rc) if rc is not None and int(rc) != 0 else 86
                            if control_session_id is not None:
                                update_control_session(
                                    conn,
                                    control_session_id=int(control_session_id),
                                    status="escalated",
                                    current_phase="observe",
                                    handoff_state="escalated",
                                    last_heartbeat_ts=utc_now_iso(),
                                    metadata_json={"escalation_reason": escalation_reason},
                                )
                                insert_control_session_event(
                                    conn,
                                    control_session_id=int(control_session_id),
                                    ts=utc_now_iso(),
                                    phase="observe",
                                    status="escalation_stop",
                                    detail_json={"reason": escalation_reason},
                                )
                            break

                    next_observe_at = now + sleep_seconds

                rc = proc.poll()
                if rc is not None:
                    exit_code = int(rc)
                    break

                if (now - start_monotonic) > timeout_seconds:
                    timed_out = True
                    break

                time.sleep(0.25)

            if timed_out:
                exit_code = 124
                handle.write(f"\n[soak-run] timeout after {timeout_seconds} seconds\n")
                _terminate_process(proc)

            # Always capture a final observation cycle on managed runs.
            observation = observe_hook(conn)
            observation_cycles += 1
            alert_value = str(observation.get("alert", "")).strip()
            if alert_value:
                alert_cycles += 1
            final_down_services: list[str] = []
            final_service_status = observation.get("service_status", {})
            final_docker = final_service_status.get("docker", {}) if isinstance(final_service_status, dict) else {}
            final_services = final_docker.get("services", {}) if isinstance(final_docker, dict) else {}
            if isinstance(final_services, dict):
                for service_name, info in final_services.items():
                    if not isinstance(info, dict):
                        continue
                    if str(info.get("state", "unknown")) != "up":
                        final_down_services.append(str(service_name))

            top_signatures = observation.get("top_signatures", [])
            if isinstance(top_signatures, list):
                for item in top_signatures:
                    if not isinstance(item, dict):
                        continue
                    signature = str(item.get("signature", "")).strip()
                    if not signature:
                        continue
                    signature_counts[signature] += int(item.get("count", 0) or 0)
            emit_progress(
                {
                    "event": "observe_cycle",
                    "cycle": int(observation_cycles),
                    "alert": bool(alert_value),
                    "alert_text": alert_value,
                    "down_services": final_down_services,
                    "top_signature": "",
                    "top_signature_count": 0,
                    "final_cycle": True,
                }
            )
            cycle_control_events = control_policy.process_observation(observation)
            for event in cycle_control_events:
                control_events.append(event)
                status = str(event.get("status", ""))
                if status.startswith("executed_"):
                    control_actions_executed += 1
                if status == "escalated":
                    control_escalations += 1
                detail = event.get("detail_json", {})
                service = detail.get("service") if isinstance(detail, dict) else None
                emit_progress(
                    {
                        "event": "control_event",
                        "decision": event.get("decision"),
                        "action": event.get("action"),
                        "status": status,
                        "service": service,
                    }
                )

            snapshot_path = _write_cycle_snapshot(
                run_dir,
                cycle=observation_cycles,
                observation=observation,
                down_services=final_down_services,
                control_events=cycle_control_events,
            )
            if snapshot_path is not None:
                snapshot_paths.append(str(snapshot_path))

            mark_phase("soak_execute", "completed" if exit_code == 0 else "failed")
            mark_phase("observe", "completed")

    if post_run_cleanup:
        cleanup_result = run_allowlisted_action(
            action="shutdown",
            mode=resolved_control_execution_mode,
            repo_root=resolved_repo_root,
            runner=control_runner,
            timeout_seconds=120,
        )
        cleanup_status = str(cleanup_result.status)
        cleanup_commands = list(cleanup_result.commands)
        cleanup_detail = str(cleanup_result.detail or "")
        if cleanup_status.startswith("executed_"):
            control_actions_executed += 1
        cleanup_event = {
            "ts": utc_now_iso(),
            "decision": "post_run_cleanup",
            "action": "shutdown",
            "status": cleanup_status,
            "detail_json": {
                "commands": cleanup_commands,
                "detail": cleanup_detail,
            },
        }
        control_events.append(cleanup_event)
        if control_session_id is not None:
            insert_control_session_event(
                conn,
                control_session_id=int(control_session_id),
                ts=str(cleanup_event["ts"]),
                phase="finalize",
                status=f"cleanup_{cleanup_status}",
                detail_json=cleanup_event["detail_json"],
            )

    ended_ts = utc_now_iso()

    all_dirs = _scan_soak_dirs(resolved_repo_root)
    detected_dirs = [path for path in all_dirs if str(path.resolve()) not in before_dirs]
    newest = detected_dirs[0] if detected_dirs else (all_dirs[0] if all_dirs else None)
    newest_name = newest.name if newest is not None else None

    with runner_log.open("a", encoding="utf-8") as handle:
        handle.write(f"[soak-run] ended_ts={ended_ts}\n")
        handle.write(f"[soak-run] exit_code={exit_code}\n")
        handle.write(
            "[soak-run] detected_soak_dirs="
            + ",".join(str(path) for path in detected_dirs)
            + "\n"
        )
        handle.write(f"[soak-run] newest_soak_dir={str(newest) if newest is not None else ''}\n")
        if managed_observe:
            handle.write(f"[soak-run] observation_cycles={observation_cycles}\n")
            handle.write(f"[soak-run] alert_cycles={alert_cycles}\n")
            handle.write(f"[soak-run] down_service_cycles={down_service_cycles}\n")
            handle.write(f"[soak-run] escalation_hard_stop={escalation_hard_stop}\n")
            handle.write(f"[soak-run] escalation_reason={escalation_reason or ''}\n")
            handle.write(f"[soak-run] snapshots={len(snapshot_paths)}\n")
            top = ", ".join(
                f"{sig}:{cnt}"
                for sig, cnt in sorted(signature_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
            )
            handle.write(f"[soak-run] top_signatures={top}\n")
        handle.write(f"[soak-run] cleanup_status={cleanup_status or ''}\n")

    ingest_hook(conn, resolved_repo_root)
    mark_phase("ingest_soaks", "completed")

    incident_path: Path | None = None
    if newest_name:
        incident_path = incident_hook(conn, newest_name)
        mark_phase("incident_report", "completed")
    else:
        mark_phase("incident_report", "skipped")

    mark_phase("finalize", "completed")

    manager_actions_for_store = build_manager_actions(
        learning_readiness=learning_readiness,
        runbook_steps=list(learned_runbook.steps),
        dry_run=False,
        exit_code=exit_code,
        runner_log=str(runner_log),
        newest_soak_dir=str(newest) if newest is not None else None,
        incident_path=str(incident_path) if incident_path is not None else None,
    )
    operator_guidance_for_store = build_operator_guidance(
        manager_actions=manager_actions_for_store,
        control_events=control_events,
        control_mode=str(control_mode),
    )

    run_id = insert_soak_run(
        conn,
        started_ts=started_ts,
        ended_ts=ended_ts,
        exit_code=exit_code,
        runner_path=str(runner_path),
        args_json={
            "duration_minutes": int(effective_duration),
            "playwright_interval_minutes": int(effective_interval),
            "baseline_path": str(effective_baseline_path) if effective_baseline_path else None,
            "baseline_update": bool(effective_baseline_update),
            "used_learned_profile": bool(learned_profile is not None),
            "managed_observe": bool(managed_observe),
            "observe_interval_seconds": float(observe_interval_seconds),
            "control_mode": str(control_mode),
            "control_policy_profile": resolved_profile_name,
            "control_check_threshold": int(resolved_check_threshold),
            "control_recover_threshold": int(resolved_recover_threshold),
            "control_max_recover_attempts": int(resolved_max_recover_attempts),
            "control_action_cooldown_cycles": int(resolved_action_cooldown),
            "control_kill_switch_env_var": resolved_kill_switch_env or None,
            "control_kill_switch_file": resolved_kill_switch_file,
            "control_rollback_enabled": bool(control_policy.rollback_enabled),
            "control_rollback_actions": resolved_rollback_actions,
            "control_rollback_max_attempts": int(control_policy.rollback_max_attempts or 1),
            "stop_on_escalation": bool(stop_on_escalation),
            "post_run_cleanup": bool(post_run_cleanup),
            "control_actions_executed": int(control_actions_executed),
            "control_escalations": int(control_escalations),
            "observation_cycles": int(observation_cycles),
            "alert_cycles": int(alert_cycles),
            "down_service_cycles": int(down_service_cycles),
            "escalation_hard_stop": bool(escalation_hard_stop),
            "escalation_reason": escalation_reason,
            "snapshot_count": len(snapshot_paths),
            "snapshot_paths": snapshot_paths[:20],
            "preflight_actions": [
                {
                    "action": str(item.get("action", "")),
                    "status": str(item.get("status", "")),
                }
                for item in preflight_actions[:10]
            ],
            "cleanup_status": cleanup_status,
            "cleanup_commands": cleanup_commands,
            "cleanup_detail": cleanup_detail,
            "top_signatures": [
                {"signature": sig, "count": cnt}
                for sig, cnt in sorted(signature_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
            ],
            "phase_plan": phase_plan,
            "phase_trace": phase_trace,
            "learning_readiness": learning_readiness,
            "manager_actions": manager_actions_for_store,
            "operator_guidance": operator_guidance_for_store,
        },
        run_dir=str(run_dir),
        newest_soak_dir=str(newest) if newest is not None else None,
        incident_path=str(incident_path) if incident_path is not None else None,
    )
    for event in control_events:
        insert_control_event(
            conn,
            soak_run_id=int(run_id),
            ts=str(event.get("ts", utc_now_iso())),
            decision=str(event.get("decision", "")),
            action=str(event.get("action")) if event.get("action") is not None else None,
            status=str(event.get("status", "")),
            detail_json=event.get("detail_json", {}) if isinstance(event.get("detail_json"), dict) else {},
        )

    if control_session_id is not None:
        final_control_status = "completed"
        if bool(escalation_hard_stop):
            final_control_status = "escalated"
        elif int(exit_code) != 0:
            final_control_status = "failed"
        update_control_session(
            conn,
            control_session_id=int(control_session_id),
            soak_run_id=int(run_id),
            ended_ts=ended_ts,
            status=final_control_status,
            current_phase="finalize",
            handoff_state=final_control_status,
            last_heartbeat_ts=ended_ts,
            metadata_json={
                "exit_code": int(exit_code),
                "control_actions_executed": int(control_actions_executed),
                "control_escalations": int(control_escalations),
                "snapshot_count": len(snapshot_paths),
                "control_policy_profile": resolved_profile_name,
                "control_kill_switch_env_var": resolved_kill_switch_env or None,
                "control_kill_switch_file": resolved_kill_switch_file,
                "control_rollback_enabled": bool(control_policy.rollback_enabled),
                "control_rollback_actions": resolved_rollback_actions,
                "control_rollback_max_attempts": int(control_policy.rollback_max_attempts or 1),
            },
        )
        insert_control_session_event(
            conn,
            control_session_id=int(control_session_id),
            ts=ended_ts,
            phase="finalize",
            status=final_control_status,
            detail_json={
                "run_id": int(run_id),
                "incident_path": str(incident_path) if incident_path is not None else None,
            },
        )

    manager_actions = build_manager_actions(
        learning_readiness=learning_readiness,
        runbook_steps=list(learned_runbook.steps),
        dry_run=False,
        exit_code=exit_code,
        runner_log=str(runner_log),
        newest_soak_dir=str(newest) if newest is not None else None,
        incident_path=str(incident_path) if incident_path is not None else None,
    )
    operator_guidance = build_operator_guidance(
        manager_actions=manager_actions,
        control_events=control_events,
        control_mode=str(control_mode),
    )
    emit_progress(
        {
            "event": "run_complete",
            "run_id": int(run_id),
            "control_session_id": int(control_session_id) if control_session_id is not None else None,
            "exit_code": int(exit_code),
            "newest_soak_dir": str(newest) if newest is not None else None,
            "incident_path": str(incident_path) if incident_path is not None else None,
            "observation_cycles": int(observation_cycles),
            "alert_cycles": int(alert_cycles),
            "down_service_cycles": int(down_service_cycles),
            "control_mode": str(control_mode),
            "control_policy_profile": resolved_profile_name,
            "control_actions_executed": int(control_actions_executed),
            "control_escalations": int(control_escalations),
            "escalation_hard_stop": bool(escalation_hard_stop),
            "escalation_reason": escalation_reason,
            "snapshot_count": len(snapshot_paths),
            "cleanup_status": cleanup_status,
        }
    )

    return {
        "dry_run": False,
        "run_id": run_id,
        "control_session_id": int(control_session_id) if control_session_id is not None else None,
        "exit_code": exit_code,
        "runner_path": str(runner_path),
        "command": command,
        "timeout_seconds": timeout_seconds,
        "effective_duration_minutes": effective_duration,
        "effective_playwright_interval_minutes": effective_interval,
        "run_dir": str(run_dir),
        "runner_log": str(runner_log),
        "newest_soak_dir": str(newest) if newest is not None else None,
        "incident_path": str(incident_path) if incident_path is not None else None,
        "detected_soak_dirs": [str(path) for path in detected_dirs],
        "managed_observe": bool(managed_observe),
        "observe_interval_seconds": float(observe_interval_seconds),
        "control_mode": str(control_mode),
        "control_policy_profile": resolved_profile_name,
        "control_check_threshold": int(resolved_check_threshold),
        "control_recover_threshold": int(resolved_recover_threshold),
        "control_max_recover_attempts": int(resolved_max_recover_attempts),
        "control_action_cooldown_cycles": int(resolved_action_cooldown),
        "control_kill_switch_env_var": resolved_kill_switch_env or None,
        "control_kill_switch_file": resolved_kill_switch_file,
        "control_rollback_enabled": bool(control_policy.rollback_enabled),
        "control_rollback_actions": resolved_rollback_actions,
        "control_rollback_max_attempts": int(control_policy.rollback_max_attempts or 1),
        "stop_on_escalation": bool(stop_on_escalation),
        "post_run_cleanup": bool(post_run_cleanup),
        "control_actions_executed": int(control_actions_executed),
        "control_escalations": int(control_escalations),
        "control_events_count": len(control_events),
        "escalation_hard_stop": bool(escalation_hard_stop),
        "escalation_reason": escalation_reason,
        "snapshot_count": len(snapshot_paths),
        "snapshot_dir": str(run_dir / "snapshots") if snapshot_paths else None,
        "snapshot_paths": snapshot_paths[:20],
        "preflight_actions": [
            {
                "action": str(item.get("action", "")),
                "status": str(item.get("status", "")),
            }
            for item in preflight_actions[:10]
        ],
        "cleanup_status": cleanup_status,
        "cleanup_commands": cleanup_commands,
        "cleanup_detail": cleanup_detail,
        "phase_plan": phase_plan,
        "phase_trace": phase_trace,
        "learning_readiness": learning_readiness,
        "manager_actions": manager_actions,
        "operator_guidance": operator_guidance,
        "observation_cycles": int(observation_cycles),
        "alert_cycles": int(alert_cycles),
        "down_service_cycles": int(down_service_cycles),
        "top_signatures": [
            {"signature": sig, "count": cnt}
            for sig, cnt in sorted(signature_counts.items(), key=lambda item: (-item[1], item[0]))[:3]
        ],
        "learned_profile": (
            {
                "runner_path": learned_profile.runner_path,
                "duration_minutes": learned_profile.duration_minutes,
                "playwright_interval_minutes": learned_profile.playwright_interval_minutes,
                "baseline_path": learned_profile.baseline_path,
                "baseline_update": learned_profile.baseline_update,
                "score": learned_profile.score,
                "evidence_count": learned_profile.evidence_count,
                "success_count": learned_profile.success_count,
                "fail_count": learned_profile.fail_count,
                "session_ids": learned_profile.session_ids,
            }
            if learned_profile is not None
            else None
        ),
        "learned_runbook": {
            "steps": learned_runbook.steps,
            "success_session_count": learned_runbook.success_session_count,
            "session_ids": learned_runbook.session_ids,
        },
    }
