"""Operational scheduler loop: heartbeat control + cron maintenance jobs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sqlite3
import time
from typing import Any, Callable

from wicap_assist.live import run_live_monitor
from wicap_assist.memory_maintenance import run_memory_maintenance, write_memory_maintenance_report
from wicap_assist.rollout_gates import append_rollout_gate_history, evaluate_rollout_gates
from wicap_assist.scheduler import run_cron_job, run_heartbeat_loop
from wicap_assist.util.time import utc_now_iso


def _default_owner() -> str:
    host = socket.gethostname().strip() or "localhost"
    return f"{host}:{os.getpid()}"


def _parse_utc(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _job_due(
    state: dict[str, Any],
    *,
    name: str,
    now_ts: str,
    interval_seconds: int,
) -> bool:
    if int(interval_seconds) <= 0:
        return True
    cron_state = state.get("cron", {})
    if not isinstance(cron_state, dict):
        return True
    job_state = cron_state.get(name, {})
    if not isinstance(job_state, dict):
        return True
    last_ts = _parse_utc(str(job_state.get("last_run_ts", "")))
    now_dt = _parse_utc(str(now_ts))
    if last_ts is None or now_dt is None:
        return True
    elapsed = (now_dt - last_ts).total_seconds()
    return elapsed >= float(max(1, int(interval_seconds)))


def run_scheduler_loop(
    conn: sqlite3.Connection,
    *,
    owner: str | None = None,
    lock_dir: Path = Path("data/locks"),
    state_path: Path | None = None,
    control_mode: str = "observe",
    heartbeat_interval_seconds: float = 10.0,
    heartbeat_lease_seconds: int = 20,
    memory_maintenance_interval_seconds: int = 900,
    rollout_gates_interval_seconds: int = 300,
    rollout_history_file: Path = Path("data/reports/rollout_gates_history.jsonl"),
    memory_report_output: Path = Path("data/reports/memory_maintenance_latest.json"),
    memory_prune_stale: bool = True,
    once: bool = False,
    max_iterations: int | None = None,
    stop_on_escalation: bool = False,
    sleep_fn: Callable[[float], None] = time.sleep,
    now_fn: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Run scheduler loop with lease-guarded heartbeat and cron jobs."""
    loop_owner = str(owner or _default_owner())
    resolved_lock_dir = Path(lock_dir)
    resolved_state_path = Path(state_path or (resolved_lock_dir / "scheduler_state.json"))
    state = _load_state(resolved_state_path)
    state.setdefault("cron", {})
    if not isinstance(state.get("cron"), dict):
        state["cron"] = {}

    heartbeat_executed = 0
    heartbeat_skipped = 0
    heartbeat_escalations = 0
    cron_executed: dict[str, int] = {"memory-maintenance": 0, "rollout-gates": 0}
    cron_skipped: dict[str, int] = {"memory-maintenance": 0, "rollout-gates": 0}

    iteration = 0
    while True:
        iteration += 1
        now_ts = str(now_fn())

        def _heartbeat_fn() -> dict[str, Any]:
            rc = run_live_monitor(
                conn,
                interval=max(0.1, float(heartbeat_interval_seconds)),
                once=True,
                control_mode=str(control_mode),
                stop_on_escalation=bool(stop_on_escalation),
            )
            latest = conn.execute(
                """
                SELECT status, id
                FROM control_sessions
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
            status = str(latest["status"]) if latest is not None else "unknown"
            return {
                "return_code": int(rc),
                "control_session_status": status,
                "control_session_id": int(latest["id"]) if latest is not None else None,
                "ts": now_ts,
            }

        heartbeat_rows = run_heartbeat_loop(
            owner=loop_owner,
            heartbeat_fn=_heartbeat_fn,
            lock_dir=resolved_lock_dir,
            iterations=1,
            lease_seconds=max(1, int(heartbeat_lease_seconds)),
        )
        heartbeat_payload = heartbeat_rows[0] if heartbeat_rows else {}
        if bool(heartbeat_payload.get("executed")):
            heartbeat_executed += 1
            payload = heartbeat_payload.get("payload", {})
            if isinstance(payload, dict):
                session_status = str(payload.get("control_session_status", "")).strip().lower()
                if session_status == "escalated":
                    heartbeat_escalations += 1
        else:
            heartbeat_skipped += 1

        if _job_due(
            state,
            name="memory-maintenance",
            now_ts=now_ts,
            interval_seconds=max(0, int(memory_maintenance_interval_seconds)),
        ):
            memory_result = run_cron_job(
                job_name="memory-maintenance",
                owner=loop_owner,
                lock_dir=resolved_lock_dir,
                lease_seconds=max(10, int(memory_maintenance_interval_seconds) or 60),
                job_fn=lambda: run_memory_maintenance(
                    conn,
                    prune_stale=bool(memory_prune_stale),
                    now_ts=now_ts,
                ),
            )
            if memory_result.executed:
                cron_executed["memory-maintenance"] += 1
                payload = dict(memory_result.payload)
                write_memory_maintenance_report(payload, Path(memory_report_output))
                state["cron"]["memory-maintenance"] = {
                    "last_run_ts": now_ts,
                    "last_payload": {
                        "stale_session_count": int(payload.get("stale_session_count", 0) or 0),
                        "pruned_session_count": int(payload.get("pruned_session_count", 0) or 0),
                        "compacted_rows": int(payload.get("compacted_rows", 0) or 0),
                    },
                }
            else:
                cron_skipped["memory-maintenance"] += 1
        else:
            cron_skipped["memory-maintenance"] += 1

        if _job_due(
            state,
            name="rollout-gates",
            now_ts=now_ts,
            interval_seconds=max(0, int(rollout_gates_interval_seconds)),
        ):
            rollout_result = run_cron_job(
                job_name="rollout-gates",
                owner=loop_owner,
                lock_dir=resolved_lock_dir,
                lease_seconds=max(10, int(rollout_gates_interval_seconds) or 60),
                job_fn=lambda: evaluate_rollout_gates(conn, now_ts=now_ts),
            )
            if rollout_result.executed:
                cron_executed["rollout-gates"] += 1
                payload = dict(rollout_result.payload)
                append_rollout_gate_history(Path(rollout_history_file), payload)
                state["cron"]["rollout-gates"] = {
                    "last_run_ts": now_ts,
                    "last_payload": {
                        "overall_pass": bool(payload.get("overall_pass", False)),
                    },
                }
            else:
                cron_skipped["rollout-gates"] += 1
        else:
            cron_skipped["rollout-gates"] += 1

        state["updated_ts"] = now_ts
        state["owner"] = loop_owner
        _write_state(resolved_state_path, state)
        conn.commit()

        if bool(once):
            break
        if max_iterations is not None and iteration >= max(1, int(max_iterations)):
            break
        sleep_fn(max(0.1, float(heartbeat_interval_seconds)))

    return {
        "owner": loop_owner,
        "iterations": int(iteration),
        "heartbeat_executed": int(heartbeat_executed),
        "heartbeat_skipped": int(heartbeat_skipped),
        "heartbeat_escalations": int(heartbeat_escalations),
        "cron_executed": cron_executed,
        "cron_skipped": cron_skipped,
        "state_path": str(resolved_state_path),
        "lock_dir": str(resolved_lock_dir),
    }
