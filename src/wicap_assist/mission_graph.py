"""Deterministic mission graph decomposition for control runs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from wicap_assist.db import (
    fetch_mission_run,
    insert_mission_run,
    insert_mission_step,
    list_mission_steps,
    update_mission_run,
)
from wicap_assist.util.time import utc_now_iso


_PHASE_TO_STEP = {
    "preflight": "observe",
    "runner": "execute",
    "observe": "diagnose",
    "ingest": "verify",
    "incident": "reflect",
    "finalize": "reward",
    "live_monitor": "observe",
    "live_cycle": "execute",
}

_STEP_ORDER = ("observe", "diagnose", "plan", "execute", "verify", "reward", "reflect")
_STEP_INDEX = {name: idx for idx, name in enumerate(_STEP_ORDER)}
_TERMINAL_STATES = {"completed", "failed", "escalated", "interrupted"}

_LIVE_DECISION_TO_STEP = {
    "service_health": "observe",
    "health_probe": "observe",
    "anomaly_route": "plan",
    "anomaly_verify": "verify",
    "threshold_check": "verify",
    "threshold_recover": "execute",
    "rollback_rule": "execute",
    "kill_switch": "reflect",
    "escalate": "reflect",
}

_TRANSITION_EDGES: dict[str, set[str]] = {
    # Cycle start and stable loops.
    "observe": {"observe", "diagnose", "plan"},
    # Detection can move into planning or immediate action/verification paths.
    "diagnose": {"diagnose", "plan", "execute", "verify", "reflect"},
    "plan": {"plan", "execute", "verify", "reflect"},
    "execute": {"execute", "verify", "reflect", "observe"},
    "verify": {"verify", "reward", "execute", "reflect", "observe"},
    "reward": {"reward", "reflect", "observe"},
    "reflect": {"reflect", "observe"},
}


def _step_type_for_phase(phase: str | None) -> str:
    key = str(phase or "").strip().lower()
    if key in _PHASE_TO_STEP:
        return _PHASE_TO_STEP[key]
    return "plan"


def _handoff_token(run_id: str, step_id: str, ts: str) -> str:
    seed = f"{run_id}|{step_id}|{ts}"
    return hashlib.sha1(seed.encode("utf-8", errors="replace")).hexdigest()[:16]


def step_type_for_live_event(*, decision: str, status: str, action: str | None = None) -> str:
    """Map one live-control event into a mission step type."""
    normalized_decision = str(decision or "").strip().lower()
    normalized_status = str(status or "").strip().lower()
    normalized_action = str(action or "").strip().lower()

    if normalized_status in {"escalated", "interrupted"}:
        return "reflect"
    if normalized_status in {"completed"}:
        return "reward"

    if normalized_decision in _LIVE_DECISION_TO_STEP:
        mapped = str(_LIVE_DECISION_TO_STEP[normalized_decision]).strip()
        if normalized_decision == "service_health":
            if normalized_status == "stable":
                return "observe"
            if normalized_status == "down_detected":
                return "diagnose"
        return mapped

    if normalized_decision.startswith("anomaly_"):
        return "plan"
    if normalized_action:
        return "execute"
    if normalized_status == "stable":
        return "observe"
    return "plan"


def is_legal_transition(previous_step: str | None, next_step: str) -> bool:
    """Return whether mission graph step transition is legal."""
    previous = str(previous_step or "").strip().lower()
    nxt = str(next_step or "").strip().lower()
    if not nxt:
        return False
    if nxt not in _STEP_INDEX:
        return False
    if not previous:
        return nxt == "observe"
    if previous not in _STEP_INDEX:
        return False
    allowed = _TRANSITION_EDGES.get(previous, set())
    return nxt in allowed


def _latest_live_step(conn: sqlite3.Connection, mission_run_id: int) -> str | None:
    row = conn.execute(
        """
        SELECT step_type
        FROM mission_steps
        WHERE mission_run_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (int(mission_run_id),),
    ).fetchone()
    if row is None:
        return None
    value = row["step_type"]
    if not isinstance(value, str):
        return None
    return value.strip().lower() or None


def _live_step_count(conn: sqlite3.Connection, mission_run_id: int) -> int:
    row = conn.execute(
        """
        SELECT count(*) AS count
        FROM mission_steps
        WHERE mission_run_id = ?
        """,
        (int(mission_run_id),),
    ).fetchone()
    if row is None:
        return 0
    try:
        return max(0, int(row["count"]))
    except (KeyError, TypeError, ValueError):
        return 0


def start_live_mission_run(
    conn: sqlite3.Connection,
    *,
    control_session_id: int,
    mode: str,
    started_ts: str,
    metadata_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create or resume mission run state for one live control session."""
    run_id = f"live-{int(control_session_id)}"
    existing = fetch_mission_run(conn, run_id)
    if existing is not None:
        last_step = _latest_live_step(conn, int(existing["id"])) or "observe"
        return {
            "run_id": run_id,
            "mission_run_id": int(existing["id"]),
            "last_step": last_step,
            "next_step_index": _live_step_count(conn, int(existing["id"])),
            "resumed": True,
        }

    mission_run_id = insert_mission_run(
        conn,
        run_id=run_id,
        ts_started=str(started_ts),
        mode=str(mode),
        status="running",
        graph_id="wicap-live-control-v1",
        metadata_json={
            "control_session_id": int(control_session_id),
            **(metadata_json or {}),
        },
    )
    return {
        "run_id": run_id,
        "mission_run_id": int(mission_run_id),
        "last_step": "observe",
        "next_step_index": 0,
        "resumed": False,
    }


def record_live_mission_step(
    conn: sqlite3.Connection,
    *,
    mission_run_id: int,
    run_id: str,
    last_step: str | None,
    ts: str,
    decision: str,
    action: str | None,
    status: str,
    detail_json: dict[str, Any] | None = None,
    step_index: int = 0,
) -> dict[str, Any]:
    """Record one live mission step and return transition metadata."""
    step_type = step_type_for_live_event(
        decision=str(decision),
        status=str(status),
        action=action,
    )
    transition_ok = is_legal_transition(last_step, step_type)
    terminal = str(status or "").strip().lower() in _TERMINAL_STATES
    step_status = str(status).strip() or "unknown"
    if not transition_ok:
        step_status = "illegal_transition"

    step_id = f"live:{int(step_index)}:{str(decision).strip() or 'unknown'}"
    insert_mission_step(
        conn,
        mission_run_id=int(mission_run_id),
        ts=str(ts),
        step_id=step_id,
        step_type=str(step_type),
        status=step_status,
        handoff_token=_handoff_token(str(run_id), step_id, str(ts)),
        detail_json={
            "decision": str(decision).strip(),
            "action": str(action).strip() if action is not None else None,
            "status": str(status).strip(),
            "previous_step": str(last_step).strip() if last_step is not None else None,
            "transition_ok": bool(transition_ok),
            "terminal_state": bool(terminal),
            **(detail_json or {}),
        },
    )
    return {
        "step_type": str(step_type),
        "transition_ok": bool(transition_ok),
        "terminal_state": bool(terminal),
        "next_step": str(step_type),
    }


def finalize_live_mission_run(
    conn: sqlite3.Connection,
    *,
    mission_run_id: int,
    status: str,
    ended_ts: str,
    metadata_json: dict[str, Any] | None = None,
) -> None:
    """Finalize one live mission run."""
    update_mission_run(
        conn,
        mission_run_id=int(mission_run_id),
        status=str(status),
        ts_ended=str(ended_ts),
        metadata_json=metadata_json or {},
    )


def record_mission_graph(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    mode: str,
    phase_trace: list[dict[str, Any]],
    status: str,
    graph_id: str = "wicap-control-v1",
    metadata_json: dict[str, Any] | None = None,
) -> int:
    """Persist one mission graph run and decomposed steps from a phase trace."""
    started_ts = utc_now_iso()
    if phase_trace and isinstance(phase_trace[0], dict):
        started_ts = str(phase_trace[0].get("ts") or started_ts)
    mission_run_id = insert_mission_run(
        conn,
        run_id=str(run_id),
        ts_started=started_ts,
        mode=str(mode),
        status="running",
        graph_id=str(graph_id),
        metadata_json=metadata_json or {},
    )
    for idx, item in enumerate(phase_trace):
        if not isinstance(item, dict):
            continue
        ts = str(item.get("ts") or started_ts)
        phase = str(item.get("phase") or f"phase-{idx}")
        step_type = _step_type_for_phase(phase)
        step_status = str(item.get("status") or "unknown")
        step_id = f"{phase}:{idx}"
        insert_mission_step(
            conn,
            mission_run_id=int(mission_run_id),
            ts=ts,
            step_id=step_id,
            step_type=step_type,
            status=step_status,
            handoff_token=_handoff_token(str(run_id), step_id, ts),
            detail_json={
                "phase": phase,
                "raw": item,
            },
        )
    ended_ts = utc_now_iso()
    if phase_trace and isinstance(phase_trace[-1], dict):
        ended_ts = str(phase_trace[-1].get("ts") or ended_ts)
    update_mission_run(
        conn,
        mission_run_id=int(mission_run_id),
        status=str(status),
        ts_ended=ended_ts,
    )
    return int(mission_run_id)


def mission_graph_snapshot(conn: sqlite3.Connection, *, run_id: str) -> dict[str, Any]:
    """Return mission graph snapshot by run id."""
    run = fetch_mission_run(conn, str(run_id))
    if run is None:
        return {
            "run_id": str(run_id),
            "found": False,
            "graph": None,
            "steps": [],
        }
    steps = list_mission_steps(conn, int(run["id"]))
    graph = {
        "run_id": run["run_id"],
        "mode": run["mode"],
        "status": run["status"],
        "graph_id": run["graph_id"],
        "ts_started": run["ts_started"],
        "ts_ended": run["ts_ended"],
    }
    step_rows: list[dict[str, Any]] = []
    for row in steps:
        detail = {}
        raw_detail = row["detail_json"]
        if isinstance(raw_detail, str) and raw_detail.strip():
            try:
                parsed = json.loads(raw_detail)
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                detail = parsed
        step_rows.append(
            {
                "ts": row["ts"],
                "step_id": row["step_id"],
                "step_type": row["step_type"],
                "status": row["status"],
                "handoff_token": row["handoff_token"],
                "detail": detail,
            }
        )
    return {
        "run_id": str(run_id),
        "found": True,
        "graph": graph,
        "steps": step_rows,
    }
