from __future__ import annotations

from pathlib import Path
import sqlite3

from wicap_assist.db import connect_db, insert_control_episode


def test_schema_migrations_and_indexes_are_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    try:
        row = conn.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert int(row["version"]) >= 2
        assert str(row["name"]).strip()

        index_names: set[str] = set()
        for table in (
            "signals",
            "log_events",
            "sessions",
            "verification_outcomes",
            "episodes",
            "episode_events",
            "episode_outcomes",
        ):
            rows = conn.execute(f"PRAGMA index_list({table})").fetchall()
            for entry in rows:
                index_names.add(str(entry["name"]))

        expected = {
            "idx_signals_category_fingerprint_session",
            "idx_log_events_category_ts_fingerprint",
            "idx_sessions_ts_last_is_wicap",
            "idx_verification_outcomes_signature_ts",
            "idx_episodes_control_session_ts",
            "idx_episode_events_episode_ts",
            "idx_episode_outcomes_episode_ts",
        }
        assert expected.issubset(index_names)

        table_names = {
            str(row["name"])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        assert {"episodes", "episode_events", "episode_outcomes"}.issubset(table_names)
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


def test_connect_db_upgrades_legacy_db_with_episode_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(db_path)
    try:
        legacy.executescript(
            """
            CREATE TABLE IF NOT EXISTS soak_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_ts TEXT NOT NULL,
                ended_ts TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                runner_path TEXT NOT NULL,
                args_json TEXT NOT NULL,
                run_dir TEXT NOT NULL,
                newest_soak_dir TEXT,
                incident_path TEXT
            );
            CREATE TABLE IF NOT EXISTS control_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                soak_run_id INTEGER,
                started_ts TEXT NOT NULL,
                ended_ts TEXT,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                current_phase TEXT,
                metadata_json TEXT NOT NULL,
                FOREIGN KEY(soak_run_id) REFERENCES soak_runs(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_ts TEXT NOT NULL
            );
            INSERT INTO schema_migrations(version, name, applied_ts)
            VALUES(1, 'core_index_hardening', '2026-02-11T00:00:00+00:00');
            """
        )
        legacy.commit()
    finally:
        legacy.close()

    conn = connect_db(db_path)
    try:
        rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        versions = {int(row["version"]) for row in rows}
        assert 2 in versions
        table_names = {
            str(row["name"])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        assert {"episodes", "episode_events", "episode_outcomes"}.issubset(table_names)
    finally:
        conn.close()


def test_insert_control_episode_writes_related_rows(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        episode_id = insert_control_episode(
            conn,
            control_session_id=None,
            soak_run_id=None,
            ts="2026-02-11T08:30:00+00:00",
            decision="status_check",
            action="status_check",
            status="executed_ok",
            pre_state_json={"alert": ""},
            post_state_json={"status": "executed_ok"},
            detail_json={"detail": "ok"},
        )
        conn.commit()

        episode_row = conn.execute("SELECT * FROM episodes WHERE id = ?", (episode_id,)).fetchone()
        event_row = conn.execute("SELECT * FROM episode_events WHERE episode_id = ?", (episode_id,)).fetchone()
        outcome_row = conn.execute("SELECT * FROM episode_outcomes WHERE episode_id = ?", (episode_id,)).fetchone()
        assert episode_row is not None
        assert event_row is not None
        assert outcome_row is not None
        assert str(episode_row["status"]) == "executed_ok"
        assert str(event_row["event_type"]) == "control_event"
        assert str(outcome_row["outcome"]) == "executed_ok"
    finally:
        conn.close()
