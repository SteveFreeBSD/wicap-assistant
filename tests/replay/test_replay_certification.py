from __future__ import annotations

from wicap_assist.certification import run_replay_certification
from wicap_assist.db import connect_db, insert_decision_feature


def test_replay_certification_writes_result(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        for _ in range(5):
            insert_decision_feature(
                conn,
                control_session_id=None,
                soak_run_id=None,
                episode_id=None,
                ts="2026-02-12T05:00:00Z",
                mode="assist",
                policy_profile="assist-v1",
                decision="threshold_check",
                action="status_check",
                status="executed_ok",
                feature_json={"stable": True},
            )
        conn.commit()

        payload = run_replay_certification(conn, profile="test")
        conn.commit()
        assert payload["cert_type"] == "replay"
        assert payload["sample_count"] >= 1
        rows = conn.execute("SELECT count(*) AS n FROM certification_runs WHERE cert_type = 'replay'").fetchone()
        assert rows is not None
        assert int(rows["n"]) >= 1
    finally:
        conn.close()
