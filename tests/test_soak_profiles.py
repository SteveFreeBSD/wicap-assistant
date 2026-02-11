from __future__ import annotations

from pathlib import Path

from wicap_assist.db import connect_db
from wicap_assist.soak_profiles import (
    learn_soak_runbook,
    parse_soak_command_profile,
    select_learned_soak_profile,
)


def _insert_session(conn, session_id: str, ts_last: str) -> int:
    src = conn.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", f"/tmp/{session_id}.jsonl", 1.0, 100),
    )
    source_id = int(src.lastrowid)
    cur = conn.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            session_id,
            "/home/steve/apps/wicap",
            ts_last,
            ts_last,
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "deadbeef",
            1,
            f"/tmp/{session_id}.jsonl",
        ),
    )
    return int(cur.lastrowid)


def _insert_signal(conn, session_pk: int, category: str, snippet: str, fp: str) -> None:
    conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, ?, ?, ?, '{}')
        """,
        (session_pk, "2026-02-11T00:00:00+00:00", category, fp, snippet),
    )


def test_parse_soak_command_profile_extracts_flags() -> None:
    cmd = "python /home/steve/apps/wicap/tests/soak_test.py --duration-minutes 12 --playwright-interval-minutes 3 --baseline-path /tmp/base.json --baseline-update"
    parsed = parse_soak_command_profile(cmd)
    assert parsed is not None
    assert parsed["runner_path"] == "/home/steve/apps/wicap/tests/soak_test.py"
    assert parsed["duration_minutes"] == 12
    assert parsed["playwright_interval_minutes"] == 3
    assert parsed["baseline_path"] == "/tmp/base.json"
    assert parsed["baseline_update"] is True


def test_select_learned_soak_profile_prefers_successful_history(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")

    s1 = _insert_session(conn, "session-good-1", "2026-02-11T00:10:00+00:00")
    _insert_signal(
        conn,
        s1,
        "commands",
        "python /home/steve/apps/wicap/tests/soak_test.py --duration-minutes 18 --playwright-interval-minutes 4",
        "fp-1",
    )
    _insert_signal(conn, s1, "outcomes", "fixed soak startup and verified", "fp-2")

    s2 = _insert_session(conn, "session-good-2", "2026-02-11T00:20:00+00:00")
    _insert_signal(
        conn,
        s2,
        "commands",
        "wicap-assist soak-run --duration-minutes 18 --playwright-interval-minutes 4",
        "fp-3",
    )
    _insert_signal(conn, s2, "outcomes", "resolved soak regression", "fp-4")

    s3 = _insert_session(conn, "session-bad", "2026-02-11T00:30:00+00:00")
    _insert_signal(
        conn,
        s3,
        "commands",
        "python /home/steve/apps/wicap/tests/soak_test.py --duration-minutes 7 --playwright-interval-minutes 1",
        "fp-5",
    )
    _insert_signal(conn, s3, "outcomes", "still broken after run", "fp-6")

    conn.commit()

    profile = select_learned_soak_profile(conn)
    assert profile is not None
    assert profile.duration_minutes == 18
    assert profile.playwright_interval_minutes == 4
    assert profile.success_count >= 2
    assert profile.fail_count == 0
    assert profile.score > 0
    assert "session-good-1" in profile.session_ids or "session-good-2" in profile.session_ids

    conn.close()


def test_learn_soak_runbook_extracts_steps_from_success_sessions(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")

    s1 = _insert_session(conn, "session-rb-1", "2026-02-11T00:10:00+00:00")
    _insert_signal(conn, s1, "commands", "python /home/steve/apps/wicap/scripts/soak_preflight.py --print-env [deadbeefcaf0]", "rb-1")
    _insert_signal(conn, s1, "commands", "docker compose up -d --build", "rb-2")
    _insert_signal(conn, s1, "commands", "python /home/steve/apps/wicap/tests/soak_test.py --duration-minutes 30", "rb-3")
    _insert_signal(conn, s1, "outcomes", "fixed and verified soak startup", "rb-4")

    s2 = _insert_session(conn, "session-rb-2", "2026-02-11T00:20:00+00:00")
    _insert_signal(conn, s2, "commands", "wicap-assist soak-run --duration-minutes 30 --playwright-interval-minutes 5", "rb-5")
    _insert_signal(conn, s2, "commands", "python /home/steve/apps/wicap/scripts/stop_wicap.py", "rb-5b")
    _insert_signal(conn, s2, "outcomes", "resolved soak regression", "rb-6")

    s2b = _insert_session(conn, "session-rb-mixed", "2026-02-11T00:25:00+00:00")
    _insert_signal(conn, s2b, "commands", "python /home/steve/apps/wicap/start_wicap.py", "rb-6b")
    _insert_signal(conn, s2b, "outcomes", "failed initial launch then fixed after restart", "rb-6c")

    s3 = _insert_session(conn, "session-rb-fail", "2026-02-11T00:30:00+00:00")
    _insert_signal(conn, s3, "commands", "docker compose down", "rb-7")
    _insert_signal(conn, s3, "outcomes", "still broken after retry", "rb-8")
    conn.commit()

    runbook = learn_soak_runbook(conn, max_steps=8)
    assert runbook.success_session_count >= 2
    assert runbook.steps
    assert any("soak_test.py" in step for step in runbook.steps)
    assert any("docker compose up" in step.lower() for step in runbook.steps)
    assert any("start_wicap.py" in step for step in runbook.steps)
    assert all("docker compose down" not in step.lower() for step in runbook.steps)
    assert all("stop_wicap.py" not in step for step in runbook.steps)
    assert all("[" not in step and "]" not in step for step in runbook.steps)

    conn.close()
