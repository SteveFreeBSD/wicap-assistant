from __future__ import annotations

from pathlib import Path

from wicap_assist.db import connect_db


def test_schema_migrations_and_indexes_are_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    try:
        row = conn.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert int(row["version"]) >= 1
        assert str(row["name"]).strip()

        index_names: set[str] = set()
        for table in ("signals", "log_events", "sessions", "verification_outcomes"):
            rows = conn.execute(f"PRAGMA index_list({table})").fetchall()
            for entry in rows:
                index_names.add(str(entry["name"]))

        expected = {
            "idx_signals_category_fingerprint_session",
            "idx_log_events_category_ts_fingerprint",
            "idx_sessions_ts_last_is_wicap",
            "idx_verification_outcomes_signature_ts",
        }
        assert expected.issubset(index_names)
    finally:
        conn.close()


def test_connect_db_sets_busy_timeout(tmp_path: Path) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    try:
        row = conn.execute("PRAGMA busy_timeout").fetchone()
        assert row is not None
        timeout_value = int(row[0])
        assert timeout_value >= 5000
    finally:
        conn.close()
