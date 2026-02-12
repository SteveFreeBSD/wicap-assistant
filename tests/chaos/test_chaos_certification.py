from __future__ import annotations

from wicap_assist.certification import run_chaos_certification
from wicap_assist.db import connect_db, insert_control_event


def test_chaos_certification_writes_result(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        insert_control_event(
            conn,
            soak_run_id=None,
            ts="2026-02-12T05:10:00Z",
            decision="threshold_check",
            action="status_check",
            status="executed_ok",
            detail_json={},
        )
        insert_control_event(
            conn,
            soak_run_id=None,
            ts="2026-02-12T05:10:30Z",
            decision="threshold_recover",
            action="compose_up",
            status="executed_fail",
            detail_json={},
        )
        conn.commit()

        payload = run_chaos_certification(conn, profile="test")
        conn.commit()
        assert payload["cert_type"] == "chaos"
        assert payload["sample_count"] >= 2
        rows = conn.execute("SELECT count(*) AS n FROM certification_runs WHERE cert_type = 'chaos'").fetchone()
        assert rows is not None
        assert int(rows["n"]) >= 1
    finally:
        conn.close()
