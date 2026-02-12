"""Autopilot supervisor mode for fully automated live-control operations."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
from typing import Any, Callable

from wicap_assist.actuators import run_allowlisted_action
from wicap_assist.certification import run_chaos_certification, run_replay_certification
from wicap_assist.config import wicap_repo_root
from wicap_assist.db import (
    insert_autopilot_run,
    insert_autopilot_step,
    update_autopilot_run,
    update_autopilot_step,
)
from wicap_assist.live import run_live_monitor
from wicap_assist.rollout_gates import (
    append_rollout_gate_history,
    evaluate_promotion_readiness,
    evaluate_rollout_gates,
    load_rollout_gate_history,
)
from wicap_assist.runtime_contract import run_runtime_contract_check
from wicap_assist.util.time import utc_now_iso

_PHASE_SEQUENCE = (
    "preflight",
    "start",
    "operate",
    "verify",
    "promote_or_rollback",
    "report",
)


def _normalize_control_mode(mode: str) -> str:
    value = str(mode or "").strip().lower()
    if value == "monitor":
        return "observe"
    if value in {"observe", "assist", "autonomous"}:
        return value
    raise ValueError(f"invalid control mode: {mode}")


def _latest_control_session(conn: sqlite3.Connection) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT id, status, mode, started_ts, ended_ts
        FROM control_sessions
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()


def _run_id_stamp(now_text: str) -> str:
    value = str(now_text or "").strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        compact = "".join(ch for ch in value if ch.isdigit())
        return compact[:14] or "unknown"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%Y%m%d%H%M%SZ")


def _runtime_contract_ok(
    report: dict[str, Any],
    *,
    require_scout: bool,
) -> tuple[bool, dict[str, Any]]:
    status = str(report.get("status", "")).strip().lower()
    checks = report.get("checks", [])
    if status == "pass":
        return True, {"ignored_checks": []}
    if not isinstance(checks, list):
        return False, {"ignored_checks": [], "reason": "invalid_contract_report_shape"}

    failed = [
        check
        for check in checks
        if isinstance(check, dict) and str(check.get("severity", "")).strip().lower() == "fail"
    ]
    if not failed:
        return False, {"ignored_checks": [], "reason": "contract_status_fail_without_failed_checks"}

    ignored: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for check in failed:
        kind = str(check.get("kind", "")).strip().lower()
        name = str(check.get("name", "")).strip().lower()
        if not require_scout and kind == "service_state" and name == "wicap-scout":
            ignored.append(check)
            continue
        kept.append(check)

    if not kept and ignored:
        return True, {
            "ignored_checks": ignored,
            "reason": "only_wicap_scout_failed",
        }
    return False, {
        "ignored_checks": ignored,
        "failed_checks": kept,
        "reason": "non_ignored_failures_present",
    }


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return target


def _run_live_runner_quiet(
    live_runner: Callable[..., int],
    *args: Any,
    **kwargs: Any,
) -> int:
    """Invoke the live runner while suppressing stdout chatter for supervisor flows."""
    with contextlib.redirect_stdout(io.StringIO()):
        return int(live_runner(*args, **kwargs))


def _phase_start(
    conn: sqlite3.Connection,
    *,
    autopilot_run_id: int,
    phase: str,
    now_ts: str,
    detail: dict[str, Any] | None = None,
) -> int:
    step_id = insert_autopilot_step(
        conn,
        autopilot_run_id=int(autopilot_run_id),
        phase=str(phase),
        ts_started=str(now_ts),
        status="running",
        detail_json=detail or {},
    )
    conn.commit()
    return int(step_id)


def _phase_end(
    conn: sqlite3.Connection,
    *,
    autopilot_step_id: int,
    status: str,
    now_ts: str,
    detail: dict[str, Any] | None = None,
) -> None:
    update_autopilot_step(
        conn,
        autopilot_step_id=int(autopilot_step_id),
        status=str(status),
        ts_ended=str(now_ts),
        detail_json=detail or {},
    )
    conn.commit()


def run_autopilot_supervisor(
    conn: sqlite3.Connection,
    *,
    mode: str = "assist",
    repo_root: Path | None = None,
    contract_path: Path | None = None,
    require_runtime_contract: bool = True,
    require_scout: bool = False,
    startup_actions: tuple[str, ...] = ("compose_up_core",),
    perform_startup: bool = True,
    operate_cycles: int = 6,
    operate_interval_seconds: float = 5.0,
    stop_on_escalation: bool = True,
    verify_replay: bool = False,
    verify_chaos: bool = False,
    certification_profile: str = "default",
    gate_history_file: Path = Path("data/reports/rollout_gates_history.jsonl"),
    required_consecutive_passes: int = 2,
    rollback_on_verify_failure: bool = True,
    rollback_actions: tuple[str, ...] = ("shutdown", "compose_up_core"),
    report_path: Path | None = Path("data/reports/autopilot_latest.json"),
    max_runs: int = 1,
    pause_seconds_between_runs: float = 10.0,
    action_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    now_fn: Callable[[], str] = utc_now_iso,
    sleep_fn: Callable[[float], None] = time.sleep,
    live_runner: Callable[..., int] = run_live_monitor,
    contract_runner: Callable[..., dict[str, Any]] = run_runtime_contract_check,
    rollout_runner: Callable[..., dict[str, Any]] = evaluate_rollout_gates,
    replay_runner: Callable[..., dict[str, Any]] = run_replay_certification,
    chaos_runner: Callable[..., dict[str, Any]] = run_chaos_certification,
) -> dict[str, Any]:
    """Run one or more autopilot supervisor cycles and return aggregated summary."""
    resolved_mode = _normalize_control_mode(str(mode))
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    startup_plan = tuple(str(item).strip().lower() for item in startup_actions if str(item).strip())
    rollback_plan = tuple(str(item).strip().lower() for item in rollback_actions if str(item).strip())
    cycle_limit = int(max_runs)
    infinite = cycle_limit <= 0

    runs: list[dict[str, Any]] = []
    run_index = 0
    while infinite or run_index < cycle_limit:
        run_index += 1
        started_ts = str(now_fn())
        run_id = f"autopilot-{_run_id_stamp(started_ts)}-{run_index}"
        run_row_id = insert_autopilot_run(
            conn,
            run_id=run_id,
            ts_started=started_ts,
            mode=resolved_mode,
            status="running",
            config_json={
                "mode": resolved_mode,
                "repo_root": str(resolved_repo_root),
                "require_runtime_contract": bool(require_runtime_contract),
                "require_scout": bool(require_scout),
                "perform_startup": bool(perform_startup),
                "startup_actions": list(startup_plan),
                "operate_cycles": int(max(1, int(operate_cycles))),
                "operate_interval_seconds": float(max(0.1, float(operate_interval_seconds))),
                "stop_on_escalation": bool(stop_on_escalation),
                "verify_replay": bool(verify_replay),
                "verify_chaos": bool(verify_chaos),
                "certification_profile": str(certification_profile),
                "gate_history_file": str(Path(gate_history_file)),
                "required_consecutive_passes": int(max(1, int(required_consecutive_passes))),
                "rollback_on_verify_failure": bool(rollback_on_verify_failure),
                "rollback_actions": list(rollback_plan),
            },
            summary_json={},
        )
        conn.commit()

        phase_results: list[dict[str, Any]] = []
        overall_status = "completed"
        promotion_decision = "hold"
        report_payload: dict[str, Any] = {}

        try:
            # -----------------------------------------------------------------
            # preflight
            # -----------------------------------------------------------------
            phase_name = "preflight"
            step_id = _phase_start(
                conn,
                autopilot_run_id=run_row_id,
                phase=phase_name,
                now_ts=started_ts,
                detail={"phase_index": 1},
            )
            docker_available = bool(shutil.which("docker"))
            python3_available = bool(shutil.which("python3"))
            compose_exists = (resolved_repo_root / "docker-compose.yml").exists()
            runtime_report = contract_runner(
                repo_root=resolved_repo_root,
                contract_path=contract_path,
            )
            contract_ok, contract_detail = _runtime_contract_ok(runtime_report, require_scout=bool(require_scout))
            preflight_ok = bool(
                docker_available
                and python3_available
                and compose_exists
                and (contract_ok or not bool(require_runtime_contract))
            )
            preflight_detail = {
                "docker_available": docker_available,
                "python3_available": python3_available,
                "compose_exists": bool(compose_exists),
                "runtime_contract_required": bool(require_runtime_contract),
                "runtime_contract_require_scout": bool(require_scout),
                "runtime_contract_status": str(runtime_report.get("status")),
                "runtime_contract_eval": contract_detail,
                "runtime_contract_report": runtime_report,
                "repo_root": str(resolved_repo_root),
            }
            _phase_end(
                conn,
                autopilot_step_id=step_id,
                status="pass" if preflight_ok else "fail",
                now_ts=str(now_fn()),
                detail=preflight_detail,
            )
            phase_results.append({"phase": phase_name, "status": "pass" if preflight_ok else "fail", "detail": preflight_detail})
            if not preflight_ok:
                overall_status = "failed_preflight"
                raise RuntimeError("autopilot preflight failed")

            # -----------------------------------------------------------------
            # start
            # -----------------------------------------------------------------
            phase_name = "start"
            step_id = _phase_start(
                conn,
                autopilot_run_id=run_row_id,
                phase=phase_name,
                now_ts=str(now_fn()),
                detail={"phase_index": 2},
            )
            startup_results: list[dict[str, Any]] = []
            startup_ok = True
            if bool(perform_startup):
                for action in startup_plan:
                    result = run_allowlisted_action(
                        action=action,
                        mode="assist",
                        repo_root=resolved_repo_root,
                        runner=action_runner,
                    )
                    startup_results.append(
                        {
                            "action": action,
                            "status": result.status,
                            "detail": result.detail,
                            "commands": result.commands,
                            "policy_trace": result.policy_trace or {},
                        }
                    )
                    if str(result.status) != "executed_ok":
                        startup_ok = False
                        break

            start_live_rc = _run_live_runner_quiet(
                live_runner,
                conn,
                interval=max(0.1, float(operate_interval_seconds)),
                once=True,
                control_mode="observe",
            )
            post_start_contract = contract_runner(repo_root=resolved_repo_root, contract_path=contract_path)
            post_start_ok, post_start_eval = _runtime_contract_ok(
                post_start_contract,
                require_scout=bool(require_scout),
            )
            start_ok = bool(startup_ok and start_live_rc == 0 and (post_start_ok or not bool(require_runtime_contract)))
            start_detail = {
                "startup_performed": bool(perform_startup),
                "startup_results": startup_results,
                "start_live_return_code": int(start_live_rc),
                "post_start_contract_status": str(post_start_contract.get("status")),
                "post_start_contract_eval": post_start_eval,
                "post_start_contract_report": post_start_contract,
            }
            _phase_end(
                conn,
                autopilot_step_id=step_id,
                status="pass" if start_ok else "fail",
                now_ts=str(now_fn()),
                detail=start_detail,
            )
            phase_results.append({"phase": phase_name, "status": "pass" if start_ok else "fail", "detail": start_detail})
            if not start_ok:
                overall_status = "failed_start"
                raise RuntimeError("autopilot start phase failed")

            # -----------------------------------------------------------------
            # operate
            # -----------------------------------------------------------------
            phase_name = "operate"
            step_id = _phase_start(
                conn,
                autopilot_run_id=run_row_id,
                phase=phase_name,
                now_ts=str(now_fn()),
                detail={"phase_index": 3},
            )
            operation_rows: list[dict[str, Any]] = []
            operate_ok = True
            for _ in range(max(1, int(operate_cycles))):
                rc = _run_live_runner_quiet(
                    live_runner,
                    conn,
                    interval=max(0.1, float(operate_interval_seconds)),
                    once=True,
                    control_mode=resolved_mode,
                    stop_on_escalation=bool(stop_on_escalation),
                )
                latest_session = _latest_control_session(conn)
                latest_status = str(latest_session["status"]) if latest_session is not None else "unknown"
                operation_rows.append(
                    {
                        "return_code": int(rc),
                        "control_session_id": int(latest_session["id"]) if latest_session is not None else None,
                        "control_status": latest_status,
                    }
                )
                if int(rc) != 0:
                    operate_ok = False
                    break
                if bool(stop_on_escalation) and latest_status == "escalated":
                    operate_ok = False
                    break
            operate_detail = {
                "mode": resolved_mode,
                "cycles_requested": int(max(1, int(operate_cycles))),
                "cycles_completed": int(len(operation_rows)),
                "stop_on_escalation": bool(stop_on_escalation),
                "operation_rows": operation_rows,
            }
            _phase_end(
                conn,
                autopilot_step_id=step_id,
                status="pass" if operate_ok else "fail",
                now_ts=str(now_fn()),
                detail=operate_detail,
            )
            phase_results.append({"phase": phase_name, "status": "pass" if operate_ok else "fail", "detail": operate_detail})
            if not operate_ok:
                overall_status = "failed_operate"
                raise RuntimeError("autopilot operate phase failed")

            # -----------------------------------------------------------------
            # verify
            # -----------------------------------------------------------------
            phase_name = "verify"
            step_id = _phase_start(
                conn,
                autopilot_run_id=run_row_id,
                phase=phase_name,
                now_ts=str(now_fn()),
                detail={"phase_index": 4},
            )
            gates = rollout_runner(conn)
            append_rollout_gate_history(Path(gate_history_file), gates)
            gate_history = load_rollout_gate_history(Path(gate_history_file))
            promotion = evaluate_promotion_readiness(
                gate_history,
                required_consecutive_passes=max(1, int(required_consecutive_passes)),
            )
            replay = replay_runner(conn, profile=str(certification_profile)) if bool(verify_replay) else None
            chaos = chaos_runner(conn, profile=str(certification_profile)) if bool(verify_chaos) else None
            gates_ok = bool(gates.get("overall_pass", False))
            replay_ok = bool(replay.get("pass", False)) if isinstance(replay, dict) else True
            chaos_ok = bool(chaos.get("pass", False)) if isinstance(chaos, dict) else True
            verify_ok = bool(gates_ok and replay_ok and chaos_ok)
            verify_detail = {
                "rollout_gates": gates,
                "promotion": promotion,
                "verify_replay": bool(verify_replay),
                "verify_chaos": bool(verify_chaos),
                "replay": replay,
                "chaos": chaos,
                "pass": bool(verify_ok),
            }
            _phase_end(
                conn,
                autopilot_step_id=step_id,
                status="pass" if verify_ok else "fail",
                now_ts=str(now_fn()),
                detail=verify_detail,
            )
            phase_results.append({"phase": phase_name, "status": "pass" if verify_ok else "fail", "detail": verify_detail})

            # -----------------------------------------------------------------
            # promote_or_rollback
            # -----------------------------------------------------------------
            phase_name = "promote_or_rollback"
            step_id = _phase_start(
                conn,
                autopilot_run_id=run_row_id,
                phase=phase_name,
                now_ts=str(now_fn()),
                detail={"phase_index": 5},
            )
            rollback_results: list[dict[str, Any]] = []
            phase_ok = True
            if verify_ok and bool(promotion.get("ready", False)):
                promotion_decision = "promote"
                overall_status = "promoted"
            elif verify_ok:
                promotion_decision = "hold"
                overall_status = "hold"
            else:
                promotion_decision = "rollback"
                if bool(rollback_on_verify_failure):
                    for action in rollback_plan:
                        result = run_allowlisted_action(
                            action=action,
                            mode="assist",
                            repo_root=resolved_repo_root,
                            runner=action_runner,
                        )
                        rollback_results.append(
                            {
                                "action": action,
                                "status": result.status,
                                "detail": result.detail,
                                "commands": result.commands,
                                "policy_trace": result.policy_trace or {},
                            }
                        )
                        if str(result.status) != "executed_ok":
                            phase_ok = False
                            break
                    overall_status = "rolled_back" if phase_ok else "rollback_failed"
                else:
                    phase_ok = False
                    overall_status = "failed_verify"

            promotion_detail = {
                "decision": promotion_decision,
                "rollback_on_verify_failure": bool(rollback_on_verify_failure),
                "rollback_actions": list(rollback_plan),
                "rollback_results": rollback_results,
                "overall_status_after_decision": overall_status,
            }
            _phase_end(
                conn,
                autopilot_step_id=step_id,
                status="pass" if phase_ok else "fail",
                now_ts=str(now_fn()),
                detail=promotion_detail,
            )
            phase_results.append({"phase": phase_name, "status": "pass" if phase_ok else "fail", "detail": promotion_detail})
            if not phase_ok:
                raise RuntimeError("autopilot promote_or_rollback phase failed")

        except Exception as exc:
            if overall_status == "completed":
                overall_status = "failed"
            report_payload["error"] = f"{type(exc).__name__}: {exc}"

        # ---------------------------------------------------------------------
        # report
        # ---------------------------------------------------------------------
        report_phase_id = _phase_start(
            conn,
            autopilot_run_id=run_row_id,
            phase="report",
            now_ts=str(now_fn()),
            detail={"phase_index": 6},
        )
        ended_ts = str(now_fn())
        report_payload.update(
            {
                "run_id": run_id,
                "status": overall_status,
                "mode": resolved_mode,
                "started_ts": started_ts,
                "ended_ts": ended_ts,
                "repo_root": str(resolved_repo_root),
                "phase_order": list(_PHASE_SEQUENCE),
                "phase_results": phase_results,
                "promotion_decision": promotion_decision,
            }
        )
        written_report = None
        if report_path is not None:
            written_report = str(_write_json(Path(report_path), report_payload))
            report_payload["report_path"] = written_report
        _phase_end(
            conn,
            autopilot_step_id=report_phase_id,
            status="pass",
            now_ts=ended_ts,
            detail={"report_path": written_report},
        )
        update_autopilot_run(
            conn,
            autopilot_run_id=run_row_id,
            status=overall_status,
            ts_ended=ended_ts,
            summary_json=report_payload,
        )
        conn.commit()

        runs.append(report_payload)
        if not infinite and run_index >= cycle_limit:
            break
        sleep_fn(max(0.1, float(pause_seconds_between_runs)))

    latest = runs[-1] if runs else {}
    return {
        "runs": runs,
        "run_count": int(len(runs)),
        "latest": latest,
    }
