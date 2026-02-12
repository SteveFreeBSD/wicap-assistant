from __future__ import annotations

from wicap_assist.db import connect_db
from wicap_assist.mission_graph import mission_graph_snapshot, record_mission_graph


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
