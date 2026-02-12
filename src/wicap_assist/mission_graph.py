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


def _step_type_for_phase(phase: str | None) -> str:
    key = str(phase or "").strip().lower()
    if key in _PHASE_TO_STEP:
        return _PHASE_TO_STEP[key]
    return "plan"


def _handoff_token(run_id: str, step_id: str, ts: str) -> str:
    seed = f"{run_id}|{step_id}|{ts}"
    return hashlib.sha1(seed.encode("utf-8", errors="replace")).hexdigest()[:16]


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
