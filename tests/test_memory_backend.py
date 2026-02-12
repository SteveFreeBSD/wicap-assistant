from __future__ import annotations

from pathlib import Path

from wicap_assist.db import connect_db, insert_episode
from wicap_assist.memory_backend import query_memory_candidates


def test_query_memory_candidates_sqlite_backend(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        insert_episode(
            conn,
            control_session_id=None,
            soak_run_id=None,
            ts_started="2026-02-12T00:00:00Z",
            ts_ended="2026-02-12T00:00:01Z",
            decision="threshold_recover",
            action="compose_up",
            status="executed_ok",
            pre_state_json={"top_signatures": [{"signature": "deauth|lab-net"}]},
            post_state_json={"control": "ok"},
            metadata_json={"note": "sample"},
        )
        conn.commit()

        backend, rows, meta = query_memory_candidates(conn, signature="deauth|lab-net", candidate_limit=10)
        assert backend in {"sqlite", "qdrant_fallback_sqlite"}
        assert rows
        assert isinstance(meta, dict)
    finally:
        conn.close()
