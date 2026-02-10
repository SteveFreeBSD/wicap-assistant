"""Tests for backfill validation report."""

from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.backfill_report import (
    backfill_report_to_json,
    format_backfill_report_text,
    generate_backfill_report,
)
from wicap_assist.db import connect_db, insert_verification_outcome


def test_empty_database_reports_zero_totals(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")
    report = generate_backfill_report(conn)

    assert report["sources"]["total"] == 0
    assert report["sessions"]["total"] == 0
    assert report["log_events"]["total"] == 0
    assert report["conversations"]["total"] == 0
    assert report["verification_outcomes"]["total"] == 0
    assert report["changelog_entries"]["total"] == 0
    assert len(report["coverage_gaps"]) > 0
    assert any("changelog" in gap.lower() for gap in report["coverage_gaps"])

    conn.close()


def test_seeded_database_reports_correct_counts(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")

    # Add a source and session
    conn.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES('session', '/test/s1', 1.0, 100)"
    )
    conn.execute(
        """
        INSERT INTO sessions(source_id, session_id, cwd, ts_first, ts_last,
                             repo_url, branch, commit_hash, is_wicap, raw_path)
        VALUES(1, 'sess-1', '/test', '2026-01-01T00:00:00', '2026-01-02T00:00:00',
               'https://github.com/test/repo.git', 'main', 'abc123', 1, '/test/s1')
        """
    )
    conn.execute(
        """
        INSERT INTO sessions(source_id, session_id, cwd, ts_first, ts_last,
                             is_wicap, raw_path)
        VALUES(1, 'sess-2', '/test', '2026-01-03T00:00:00', '2026-01-04T00:00:00',
               1, '/test/s2')
        """
    )

    # Add verification outcome
    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="test error",
        outcome="pass",
        evidence_snippet="fixed",
        ts="2026-01-02T00:00:00",
    )
    conn.commit()

    report = generate_backfill_report(conn)

    assert report["sources"]["total"] == 1
    assert report["sessions"]["total"] == 2
    assert report["sessions"]["with_git_metadata"] == 1
    assert report["sessions"]["missing_git_metadata"] == 1
    assert report["verification_outcomes"]["total"] == 1
    assert any("1 sessions missing git metadata" in gap for gap in report["coverage_gaps"])

    conn.close()


def test_text_output_includes_coverage_gaps(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")
    report = generate_backfill_report(conn)
    text = format_backfill_report_text(report)

    assert "Backfill Validation Report" in text
    assert "Coverage gaps:" in text
    assert "changelog" in text.lower()

    conn.close()


def test_json_output_is_valid(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")
    report = generate_backfill_report(conn)
    output = backfill_report_to_json(report)

    data = json.loads(output)
    assert "sources" in data
    assert "sessions" in data
    assert "coverage_gaps" in data

    conn.close()


def test_cli_backfill_report(tmp_path: Path) -> None:
    from wicap_assist.cli import main

    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)
    conn.close()

    rc = main(["--db", str(db_path), "backfill-report"])
    assert rc == 0
