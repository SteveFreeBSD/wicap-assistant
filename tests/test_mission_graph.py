from __future__ import annotations

from wicap_assist.db import connect_db
from wicap_assist.mission_graph import (
    is_legal_transition,
    mission_graph_snapshot,
    record_live_mission_step,
    record_mission_graph,
    start_live_mission_run,
    step_type_for_live_event,
)


def test_record_mission_graph_and_snapshot(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        mission_run_id = record_mission_graph(
            conn,
            run_id="soak-11",
            mode="assist",
            phase_trace=[
                {"phase": "preflight", "status": "started", "ts": "2026-02-12T00:00:00Z"},
                {"phase": "finalize", "status": "completed", "ts": "2026-02-12T00:05:00Z"},
            ],
            status="completed",
            metadata_json={"k": "v"},
        )
        conn.commit()
        assert int(mission_run_id) > 0

        payload = mission_graph_snapshot(conn, run_id="soak-11")
        assert payload["found"] is True
        assert payload["graph"]["status"] == "completed"
        assert len(payload["steps"]) == 2
        assert payload["steps"][0]["handoff_token"]
    finally:
        conn.close()


def test_live_step_type_and_transition_matrix() -> None:
    assert step_type_for_live_event(decision="service_health", status="stable") == "observe"
    assert step_type_for_live_event(decision="health_probe", status="executed_ok", action="status_check") == "observe"
    assert step_type_for_live_event(decision="service_health", status="down_detected") == "diagnose"
    assert step_type_for_live_event(decision="threshold_recover", status="executed_ok") == "execute"
    assert step_type_for_live_event(decision="escalate", status="escalated") == "reflect"
    assert step_type_for_live_event(decision="custom", status="unknown", action="restart_service:wicap-ui") == "execute"

    assert is_legal_transition("observe", "diagnose") is True
    assert is_legal_transition("diagnose", "verify") is True
    assert is_legal_transition("verify", "execute") is True
    assert is_legal_transition("reflect", "observe") is True
    assert is_legal_transition("observe", "reward") is False
    assert is_legal_transition("execute", "plan") is False


def test_live_mission_run_records_legal_steps(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        mission = start_live_mission_run(
            conn,
            control_session_id=42,
            mode="assist",
            started_ts="2026-02-12T00:00:00Z",
        )
        assert mission["run_id"] == "live-42"
        assert mission["resumed"] is False

        first = record_live_mission_step(
            conn,
            mission_run_id=int(mission["mission_run_id"]),
            run_id=str(mission["run_id"]),
            last_step="observe",
            ts="2026-02-12T00:00:01Z",
            decision="service_health",
            action=None,
            status="down_detected",
            step_index=0,
        )
        second = record_live_mission_step(
            conn,
            mission_run_id=int(mission["mission_run_id"]),
            run_id=str(mission["run_id"]),
            last_step=str(first["next_step"]),
            ts="2026-02-12T00:00:02Z",
            decision="threshold_check",
            action="status_check",
            status="executed_ok",
            step_index=1,
        )
        third = record_live_mission_step(
            conn,
            mission_run_id=int(mission["mission_run_id"]),
            run_id=str(mission["run_id"]),
            last_step=str(second["next_step"]),
            ts="2026-02-12T00:00:03Z",
            decision="threshold_recover",
            action="restart_service:wicap-ui",
            status="executed_ok",
            step_index=2,
        )
        conn.commit()

        assert first["transition_ok"] is True
        assert second["transition_ok"] is True
        assert third["transition_ok"] is True

        rows = conn.execute(
            "SELECT status FROM mission_steps WHERE mission_run_id = ? ORDER BY id ASC",
            (int(mission["mission_run_id"]),),
        ).fetchall()
        assert rows
        assert all(str(row["status"]) != "illegal_transition" for row in rows)

        resumed = start_live_mission_run(
            conn,
            control_session_id=42,
            mode="assist",
            started_ts="2026-02-12T00:01:00Z",
        )
        assert resumed["resumed"] is True
        assert int(resumed["next_step_index"]) == 3
    finally:
        conn.close()
