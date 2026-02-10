from __future__ import annotations

from pathlib import Path

from wicap_assist.bundle import build_bundle
from wicap_assist.db import connect_db


def _seed_bundle_fixture(conn, tmp_path: Path) -> None:
    soak_path = "/home/steve/apps/wicap/logs_soak_123/pytest_iter_1.log"
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", soak_path, 1.0, 100),
    )
    soak_source_id = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            soak_source_id,
            "2026-02-10 10:00:00",
            "pytest_fail",
            "fp-log-1",
            "AssertionError: pyodbc setinputsizes failure in soak run",
            soak_path,
            "{}",
        ),
    )
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            soak_source_id,
            "2026-02-10 10:00:01",
            "error",
            "fp-log-2",
            "Traceback (most recent call last): pyodbc ETIMEDOUT in db check",
            soak_path,
            "{}",
        ),
    )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-a.jsonl", 2.0, 200),
    )
    codex_source_id = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            codex_source_id,
            "session-match",
            "/home/steve/apps/wicap",
            "2026-02-10T10:00:00+00:00",
            "2026-02-10T10:05:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "deadbeef",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-a.jsonl",
        ),
    )
    session_pk = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            session_pk,
            "2026-02-10T10:00:30+00:00",
            "errors",
            "sig-1",
            "Error: pyodbc setinputsizes timeout on SQL write path",
            "{}",
        ),
    )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-b.jsonl", 3.0, 200),
    )
    other_source_id = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            other_source_id,
            "session-other",
            "/home/steve/apps/wicap",
            "2026-02-10T10:00:00+00:00",
            "2026-02-10T10:02:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "beadfeed",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-b.jsonl",
        ),
    )

    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            int(cur.lastrowid),
            "2026-02-10T10:01:00+00:00",
            "errors",
            "sig-2",
            "Unrelated wifi scan line",
            "{}",
        ),
    )

    conn.commit()


def test_bundle_correlates_soak_to_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wicap_assist.bundle.compute_window_from_mtimes", lambda _: (None, None))

    conn = connect_db(tmp_path / "assistant.db")
    _seed_bundle_fixture(conn, tmp_path)

    bundle = build_bundle(conn, "logs_soak_123")

    assert bundle["log_summary"]["error"]
    assert bundle["log_summary"]["pytest_fail"]
    assert bundle["related_sessions"]
    assert bundle["related_sessions"][0]["session_id"] == "session-match"
    assert bundle["git_commits"] == []

    conn.close()


def test_bundle_output_is_deterministic_for_same_fixture(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wicap_assist.bundle.compute_window_from_mtimes", lambda _: (None, None))

    conn = connect_db(tmp_path / "assistant.db")
    _seed_bundle_fixture(conn, tmp_path)

    first = build_bundle(conn, "logs_soak_123")
    second = build_bundle(conn, "logs_soak_123")

    assert first == second

    conn.close()
