from __future__ import annotations

from wicap_assist.certification import run_replay_certification
from wicap_assist.db import connect_db


def test_replay_certification_writes_result(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        payload = run_replay_certification(conn, profile="default")
        conn.commit()
        assert payload["cert_type"] == "replay"
        assert bool(payload["pass"]) is True
        assert payload["sample_count"] >= 1
        rows = conn.execute("SELECT count(*) AS n FROM certification_runs WHERE cert_type = 'replay'").fetchone()
        assert rows is not None
        assert int(rows["n"]) >= 1
    finally:
        conn.close()
