"""Tests for Antigravity conversation ingestion adapter."""

import json
from pathlib import Path

import pytest

from wicap_assist.db import connect_db
from wicap_assist.ingest.antigravity_logs import (
    ParsedConversation,
    ingest_antigravity_logs,
    parse_conversation_dir,
    scan_antigravity_paths,
)


def _make_conversation(tmp_path: Path, conv_id: str, artifacts: dict[str, str]) -> Path:
    """Create a synthetic conversation directory with given artifacts."""
    conv_dir = tmp_path / conv_id
    conv_dir.mkdir()

    for name, content in artifacts.items():
        (conv_dir / name).write_text(content, encoding="utf-8")

    return conv_dir


def _make_metadata(
    conv_dir: Path,
    artifact_name: str,
    updated_at: str,
    *,
    extras: dict[str, object] | None = None,
) -> None:
    """Create a metadata.json file for an artifact."""
    meta = {
        "artifactType": "ARTIFACT_TYPE_TASK",
        "summary": "Test summary.",
        "updatedAt": updated_at,
        "version": "1",
    }
    if extras:
        meta.update(extras)
    (conv_dir / f"{artifact_name}.metadata.json").write_text(
        json.dumps(meta), encoding="utf-8"
    )


# ── Scan Tests ──


def test_scan_finds_uuid_dirs_with_artifacts(tmp_path: Path) -> None:
    """Scanner should find UUID dirs containing markdown artifacts."""
    _make_conversation(tmp_path, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", {"task.md": "# Test"})
    _make_conversation(tmp_path, "11111111-2222-3333-4444-555555555555", {"walkthrough.md": "# Walk"})
    # Non-UUID dir should be ignored
    _make_conversation(tmp_path, "not-a-uuid", {"task.md": "# X"})
    # UUID dir without artifacts should be ignored
    (tmp_path / "22222222-3333-4444-5555-666666666666").mkdir()

    results = scan_antigravity_paths(root=tmp_path)
    ids = [p.name for p in results]

    assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" in ids
    assert "11111111-2222-3333-4444-555555555555" in ids
    assert "not-a-uuid" not in ids
    assert "22222222-3333-4444-5555-666666666666" not in ids


def test_scan_empty_root(tmp_path: Path) -> None:
    """Scanner should return empty list for non-existent root."""
    results = scan_antigravity_paths(root=tmp_path / "nonexistent")
    assert results == []


# ── Parser Tests ──


def test_parser_extracts_title_and_metadata(tmp_path: Path) -> None:
    """Parser should extract title from H1 and timestamps from metadata."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {"task.md": "# WICAP Code Improvements\n\n- [x] Phase 1 done\n- [ ] Phase 2 pending"},
    )
    _make_metadata(conv_dir, "task.md", "2026-02-07T14:17:36.394354725Z")

    result = parse_conversation_dir(conv_dir)
    assert result is not None
    assert result.title == "WICAP Code Improvements"
    assert result.ts_last == "2026-02-07T14:17:36.394354725Z"
    assert result.conversation_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_parser_extracts_checklist_signals(tmp_path: Path) -> None:
    """Parser should extract completed and pending task signals."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "task.md": (
                "# WICAP Test\n\n"
                "- [x] Add unit tests for wicap ghost_hunter\n"
                "- [/] Structured logging in progress\n"
                "- [ ] Run soak test\n"
            ),
        },
    )

    result = parse_conversation_dir(conv_dir)
    assert result is not None

    categories = {s.category for s in result.signals}
    assert "completed_task" in categories
    assert "in_progress_task" in categories
    assert "pending_task" in categories


def test_parser_extracts_test_result_signals(tmp_path: Path) -> None:
    """Parser should extract test result lines."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "walkthrough.md": (
                "# WICAP Walkthrough\n\n"
                "```\n424 passed, 21 skipped\n```\n"
            ),
        },
    )

    result = parse_conversation_dir(conv_dir)
    assert result is not None

    test_signals = [s for s in result.signals if s.category == "test_result"]
    assert len(test_signals) >= 1
    assert "424" in test_signals[0].snippet


def test_parser_extracts_file_changed_signals(tmp_path: Path) -> None:
    """Parser should extract render_diffs references."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "walkthrough.md": (
                "# WICAP changes\n\n"
                "render_diffs(file:///home/steve/apps/wicap/parser.py)\n"
            ),
        },
    )

    result = parse_conversation_dir(conv_dir)
    assert result is not None

    file_signals = [s for s in result.signals if s.category == "file_changed"]
    assert len(file_signals) >= 1
    assert "parser.py" in file_signals[0].snippet


def test_parser_filters_non_wicap_conversations(tmp_path: Path) -> None:
    """Parser should return None for non-WICAP conversations."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {"task.md": "# Some Other Project\n\n- [x] Unrelated task"},
    )

    result = parse_conversation_dir(conv_dir)
    assert result is None


def test_parser_extracts_verification_outcomes(tmp_path: Path) -> None:
    """Parser should extract verification outcomes from walkthroughs."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "walkthrough.md": (
                "# WICAP walkthrough\n\n"
                "All tests passed. Soak clean.\n"
                "Still failing on Docker restart.\n"
            ),
        },
    )

    result = parse_conversation_dir(conv_dir)
    assert result is not None
    assert len(result.verification_outcomes) >= 2

    outcomes = {o.outcome for o in result.verification_outcomes}
    assert "pass" in outcomes
    assert "fail" in outcomes


# ── Full Ingestion Round-Trip ──


def test_ingest_round_trip(tmp_path: Path) -> None:
    """Full ingestion should store conversations and signals in SQLite."""
    # Create a WICAP-related conversation
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "task.md": (
                "# WICAP Phase 2 Tests\n\n"
                "- [x] Add ghost_hunter tests\n"
                "- [ ] Run soak test\n"
            ),
            "walkthrough.md": (
                "# WICAP walkthrough\n\n"
                "52 passed, 0 failed\n"
            ),
        },
    )
    _make_metadata(conv_dir, "task.md", "2026-02-07T14:00:00Z")

    # Create a non-WICAP conversation (should be filtered)
    _make_conversation(
        tmp_path, "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
        {"task.md": "# Unrelated Project\n\n- [x] Done"},
    )

    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    dirs_seen, conversations_added, signals_added, outcomes_added = ingest_antigravity_logs(conn, root=tmp_path)

    conn.commit()

    assert dirs_seen == 2  # Both dirs scanned
    assert conversations_added == 1  # Only WICAP conv inserted
    assert signals_added >= 3  # completed_task + pending_task + test_result at minimum
    assert outcomes_added >= 1

    # Verify data in DB
    row = conn.execute(
        "SELECT * FROM conversations WHERE conversation_id = ?",
        ("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",),
    ).fetchone()
    assert row is not None
    assert row["title"] == "WICAP Phase 2 Tests"

    signal_count = conn.execute("SELECT count(*) as cnt FROM conversation_signals").fetchone()["cnt"]
    assert signal_count >= 3

    conn.close()


def test_non_wicap_gate_blocks_ingestion_rows(tmp_path: Path) -> None:
    """Non-WICAP conversations must not create conversation or signal rows."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "task.md": "# Unrelated project\n\nNo matching project tag here.",
            "walkthrough.md": "PASS but unrelated workflow",
        },
    )
    _make_metadata(
        conv_dir,
        "task.md",
        "2026-02-07T14:00:00Z",
        extras={
            "cwd": "/home/steve/apps/other-project",
            "git": {"repository_url": "https://github.com/example/other-project.git"},
        },
    )

    conn = connect_db(tmp_path / "test.db")
    _, conversations_added, signals_added, outcomes_added = ingest_antigravity_logs(conn, root=tmp_path)
    conn.commit()

    assert conversations_added == 0
    assert signals_added == 0
    assert outcomes_added == 0
    assert conn.execute("SELECT count(*) as cnt FROM conversations").fetchone()["cnt"] == 0
    assert conn.execute("SELECT count(*) as cnt FROM conversation_signals").fetchone()["cnt"] == 0
    assert conn.execute("SELECT count(*) as cnt FROM verification_outcomes").fetchone()["cnt"] == 0
    conn.close()


def test_wicap_metadata_gate_allows_ingestion(tmp_path: Path) -> None:
    """WICAP gate should pass when metadata cwd/repo indicates WICAP."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {"task.md": "# Project task\n\nNo explicit project tag in body."},
    )
    _make_metadata(
        conv_dir,
        "task.md",
        "2026-02-07T14:00:00Z",
        extras={
            "cwd": "/home/steve/apps/wicap",
            "git": {"repository_url": "https://github.com/SteveFreeBSD/wicap.git"},
        },
    )

    conn = connect_db(tmp_path / "test.db")
    _, conversations_added, _, _ = ingest_antigravity_logs(conn, root=tmp_path)
    conn.commit()

    assert conversations_added == 1
    assert conn.execute("SELECT count(*) as cnt FROM conversations").fetchone()["cnt"] == 1
    conn.close()


def test_antigravity_ingest_is_idempotent_for_unchanged_dirs(tmp_path: Path) -> None:
    """Second ingest pass over unchanged artifacts should add no rows."""
    conv_dir = _make_conversation(
        tmp_path, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        {
            "task.md": (
                "# WICAP Idempotency\n\n"
                "- [x] run verifier\n"
                "- [ ] inspect logs\n"
            ),
            "walkthrough.md": "All tests passed\n",
        },
    )
    _make_metadata(conv_dir, "task.md", "2026-02-07T14:00:00Z")

    conn = connect_db(tmp_path / "test.db")

    first = ingest_antigravity_logs(conn, root=tmp_path)
    conn.commit()
    first_counts = {
        "conversations": int(conn.execute("SELECT count(*) as cnt FROM conversations").fetchone()["cnt"]),
        "signals": int(conn.execute("SELECT count(*) as cnt FROM conversation_signals").fetchone()["cnt"]),
        "outcomes": int(conn.execute("SELECT count(*) as cnt FROM verification_outcomes").fetchone()["cnt"]),
    }

    second = ingest_antigravity_logs(conn, root=tmp_path)
    conn.commit()
    second_counts = {
        "conversations": int(conn.execute("SELECT count(*) as cnt FROM conversations").fetchone()["cnt"]),
        "signals": int(conn.execute("SELECT count(*) as cnt FROM conversation_signals").fetchone()["cnt"]),
        "outcomes": int(conn.execute("SELECT count(*) as cnt FROM verification_outcomes").fetchone()["cnt"]),
    }

    assert first[1] == 1
    assert first[2] >= 1
    assert first[3] >= 1
    assert second[1] == 0
    assert second[2] == 0
    assert second[3] == 0
    assert second_counts == first_counts
    conn.close()
