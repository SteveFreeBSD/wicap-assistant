from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from wicap_assist.db import connect_db, insert_verification_outcome
from wicap_assist.playbooks import normalize_signature
from wicap_assist.rollup import format_rollup_text, generate_rollup


def _insert_source(conn, kind: str, path: str, mtime: float, size: int = 100) -> int:
    cur = conn.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        (kind, path, mtime, size),
    )
    return int(cur.lastrowid)


def _seed_rollup_fixture(conn, tmp_path: Path) -> tuple[Path, Path]:
    now = datetime(2026, 2, 5, tzinfo=timezone.utc)
    log_source_id = _insert_source(
        conn,
        "soak_log",
        str(tmp_path / "logs_soak_1" / "run.log"),
        now.timestamp(),
    )

    sig_error = "Error: pyodbc timeout on sql write path"
    sig_docker = "docker service exited with code 1"

    for idx, ts in enumerate(
        (
            "2026-02-01 10:00:00",
            "2026-02-03 10:00:00",
            "2026-02-04 10:00:00",
        ),
        start=1,
    ):
        conn.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (
                log_source_id,
                ts,
                f"error-fp-{idx}",
                sig_error,
                str(tmp_path / "logs_soak_1" / "run.log"),
            ),
        )

    for idx, ts in enumerate(("2026-02-02 09:00:00", "2026-02-02 10:00:00"), start=1):
        conn.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'docker_fail', ?, ?, ?, '{}')
            """,
            (
                log_source_id,
                ts,
                f"docker-fp-{idx}",
                sig_docker,
                str(tmp_path / "logs_soak_1" / "run.log"),
            ),
        )

    session_source = _insert_source(
        conn,
        "session",
        "/home/steve/.codex/sessions/2026/02/04/rollout-rollup.jsonl",
        now.timestamp(),
    )
    conn.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_source,
            "session-rollup-1",
            "/home/steve/apps/wicap",
            "2026-02-04T09:00:00+00:00",
            "2026-02-04T10:00:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "abc123",
            1,
            "/home/steve/.codex/sessions/2026/02/04/rollout-rollup.jsonl",
        ),
    )
    session_pk = int(conn.execute("SELECT id FROM sessions WHERE session_id = 'session-rollup-1'").fetchone()[0])
    conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'errors', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-04T10:00:00+00:00",
            "sig-fp-1",
            "Error: pyodbc timeout on sql write path",
        ),
    )

    playbooks_dir = tmp_path / "docs" / "playbooks"
    playbooks_dir.mkdir(parents=True)
    playbook_signature = normalize_signature(sig_error)
    (playbooks_dir / "error-pyodbc-timeout.md").write_text(
        "\n".join(
            [
                "# Playbook: pyodbc timeout",
                "",
                "## Trigger",
                "- Category: error",
                f"- Signature: {playbook_signature}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    incidents_dir = tmp_path / "docs" / "incidents"
    incidents_dir.mkdir(parents=True)
    (incidents_dir / "2026-02-04-sample.md").write_text(
        "\n".join(
            [
                "# WICAP Incident Report",
                "",
                "## Failure Signatures",
                "### error",
                f"- Example snippet: {sig_error}",
                "### docker_fail",
                f"- Example snippet: {sig_docker}",
            ]
        ),
        encoding="utf-8",
    )

    conn.commit()
    return playbooks_dir, incidents_dir


def test_rollup_sorts_spans_and_git_context(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    playbooks_dir, incidents_dir = _seed_rollup_fixture(conn, tmp_path)

    report = generate_rollup(
        conn,
        days=30,
        top=10,
        now=datetime(2026, 2, 5, tzinfo=timezone.utc),
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )

    items = report["items"]
    assert len(items) == 2
    assert items[0]["category"] == "error"
    assert items[0]["occurrence_count"] == 3
    assert items[0]["span_days"] == 3.0
    assert items[0]["playbook"]["path"] == "error-pyodbc-timeout.md"
    assert items[0]["git_context"]["most_common_commit_hash"] == "abc123"
    assert items[0]["git_context"]["commit_spread"] >= 1

    assert items[1]["category"] == "docker_fail"
    assert items[1]["occurrence_count"] == 2

    conn.close()


def test_rollup_output_is_deterministic_for_same_inputs(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    playbooks_dir, incidents_dir = _seed_rollup_fixture(conn, tmp_path)
    now = datetime(2026, 2, 5, tzinfo=timezone.utc)

    first = generate_rollup(
        conn,
        days=30,
        top=10,
        now=now,
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )
    second = generate_rollup(
        conn,
        days=30,
        top=10,
        now=now,
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )

    assert first == second
    conn.close()


def test_rollup_uses_event_timestamp_over_old_source_mtime(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    old_mtime = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    src = _insert_source(conn, "soak_log", str(tmp_path / "logs_soak_2" / "legacy.log"), old_mtime)

    snippet = "Error: redis timeout while checking health"
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, 'error', ?, ?, ?, '{}')
        """,
        (
            src,
            "2026-02-04 08:00:00",
            "legacy-fp-1",
            snippet,
            str(tmp_path / "logs_soak_2" / "legacy.log"),
        ),
    )

    incidents_dir = tmp_path / "docs" / "incidents"
    incidents_dir.mkdir(parents=True)
    (incidents_dir / "2026-02-04-legacy.md").write_text(
        "\n".join(
            [
                "# WICAP Incident Report",
                "",
                "## Failure Signatures",
                "### error",
                f"- Example snippet: {snippet}",
            ]
        ),
        encoding="utf-8",
    )

    conn.commit()
    report = generate_rollup(
        conn,
        days=30,
        top=10,
        now=datetime(2026, 2, 5, tzinfo=timezone.utc),
        incidents_dir=incidents_dir,
        playbooks_dir=tmp_path / "docs" / "playbooks",
    )

    assert report["items"]
    assert report["items"][0]["signature"] == normalize_signature(snippet)
    assert report["items"][0]["occurrence_count"] == 1
    conn.close()


def test_rollup_no_verification_outcomes_returns_null_track_record(tmp_path: Path) -> None:
    """Rollup items with no verification outcomes should have null track record."""
    conn = connect_db(tmp_path / "assistant.db")
    playbooks_dir, incidents_dir = _seed_rollup_fixture(conn, tmp_path)

    report = generate_rollup(
        conn,
        days=30,
        top=10,
        now=datetime(2026, 2, 5, tzinfo=timezone.utc),
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )

    for item in report["items"]:
        assert item["verification_track_record"] is None

    text = format_rollup_text(report)
    assert "(no verification data)" in text

    conn.close()


def test_rollup_verification_track_record_counts(tmp_path: Path) -> None:
    """Verification track record should count pass/fail/unknown outcomes."""
    conn = connect_db(tmp_path / "assistant.db")
    playbooks_dir, incidents_dir = _seed_rollup_fixture(conn, tmp_path)

    # Add verification outcomes matching the error signature
    for i in range(3):
        insert_verification_outcome(
            conn,
            conversation_pk=None,
            signature="error: pyodbc timeout on sql write path",
            outcome="pass",
            evidence_snippet=f"fix verified run {i}",
            ts=f"2026-02-04T11:0{i}:00+00:00",
        )
    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="error: pyodbc timeout on sql write path",
        outcome="unknown",
        evidence_snippet="pending verification",
        ts="2026-02-04T12:00:00+00:00",
    )
    conn.commit()

    report = generate_rollup(
        conn,
        days=30,
        top=10,
        now=datetime(2026, 2, 5, tzinfo=timezone.utc),
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )

    error_item = next(item for item in report["items"] if item["category"] == "error")
    vtr = error_item["verification_track_record"]
    assert vtr is not None
    assert vtr["passes"] == 3
    assert vtr["fails"] == 0
    assert vtr["unknowns"] == 1
    assert vtr["relapse_detected"] is False
    assert vtr["net_confidence_effect"] == 2  # min(2, 3) - 0

    text = format_rollup_text(report)
    assert "pass=3" in text
    assert "RELAPSE" not in text

    conn.close()


def test_rollup_verification_track_record_relapse_detection(tmp_path: Path) -> None:
    """A fail after a pass should set relapse_detected and show warning in text."""
    conn = connect_db(tmp_path / "assistant.db")
    playbooks_dir, incidents_dir = _seed_rollup_fixture(conn, tmp_path)

    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="error: pyodbc timeout on sql write path",
        outcome="pass",
        evidence_snippet="fix confirmed",
        ts="2026-02-03T10:00:00+00:00",
    )
    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="error: pyodbc timeout on sql write path",
        outcome="fail",
        evidence_snippet="regression after fix",
        ts="2026-02-04T10:00:00+00:00",
    )
    conn.commit()

    report = generate_rollup(
        conn,
        days=30,
        top=10,
        now=datetime(2026, 2, 5, tzinfo=timezone.utc),
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )

    error_item = next(item for item in report["items"] if item["category"] == "error")
    vtr = error_item["verification_track_record"]
    assert vtr is not None
    assert vtr["passes"] == 1
    assert vtr["fails"] == 1
    assert vtr["relapse_detected"] is True
    assert vtr["net_confidence_effect"] == -1  # min(2,1) - min(4,2) = 1 - 2

    text = format_rollup_text(report)
    assert "RELAPSE RISK" in text

    conn.close()
