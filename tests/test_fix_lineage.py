"""Tests for fix lineage resolution."""

from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.db import (
    connect_db,
    insert_conversation,
    insert_conversation_signal,
    insert_verification_outcome,
    upsert_source,
)
from wicap_assist.fix_lineage import (
    fix_lineage_to_json,
    format_fix_lineage_text,
    resolve_fix_lineage,
)
from wicap_assist.util.redact import sha1_text


def test_fix_lineage_finds_relevant_conversation(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")
    source_id = upsert_source(conn, kind="test", path="/test", mtime=1.0, size=100)

    # Conv 1: Relevant to "redis timeout"
    pk1, _ = insert_conversation(
        conn,
        source_id=source_id,
        conversation_id="conv-1",
        title="Fixing Redis Timeout",
        ts_first="2026-01-01T10:00:00Z",
        ts_last="2026-01-01T11:00:00Z",
        task_summary=None,
        artifact_type=None,
    )
    insert_conversation_signal(
        conn,
        conversation_pk=pk1,
        ts="2026-01-01T10:05:00Z",
        category="error",
        fingerprint=sha1_text("redis timeout"),
        snippet="Error: Redis connection timeout detected",
        artifact_name="log.txt",
    )
    insert_conversation_signal(
        conn,
        conversation_pk=pk1,
        ts="2026-01-01T10:10:00Z",
        category="commands",
        fingerprint=sha1_text("cmd1"),
        snippet="sudo service redis restart",
        artifact_name="cmd.sh",
    )
    insert_verification_outcome(
        conn,
        conversation_pk=pk1,
        signature="redis timeout",
        outcome="pass",
        evidence_snippet="fixed",
        ts="2026-01-01T10:50:00Z",
    )

    # Conv 2: Irrelevant
    pk2, _ = insert_conversation(
        conn,
        source_id=source_id,
        conversation_id="conv-2",
        title="UI tweaks",
        ts_first="2026-01-02T10:00:00Z",
        ts_last="2026-01-02T11:00:00Z",
        task_summary=None,
        artifact_type=None,
    )
    insert_conversation_signal(
        conn,
        conversation_pk=pk2,
        ts="2026-01-02T10:05:00Z",
        category="error",
        fingerprint=sha1_text("ui glitch"),
        snippet="CSS overflow",
        artifact_name="style.css",
    )

    conn.commit()

    attempts = resolve_fix_lineage(conn, "redis timeout error")
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.conversation_id == "conv-1"
    assert "sudo service redis restart" in attempt.commands
    assert len(attempt.verification_outcomes) == 1
    assert attempt.verification_outcomes[0]["outcome"] == "pass"

    # Text output
    text = format_fix_lineage_text(attempts)
    assert "Fixing Redis Timeout" in text
    assert "$ sudo service redis restart" in text
    assert "[PASS] fixed" in text

    # JSON output
    json_out = fix_lineage_to_json(attempts)
    data = json.loads(json_out)
    assert len(data) == 1
    assert data[0]["conversation_id"] == "conv-1"

    conn.close()


def test_fix_lineage_handles_unknown_signature(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")
    attempts = resolve_fix_lineage(conn, "totally unknown error")
    assert len(attempts) == 0

    text = format_fix_lineage_text(attempts)
    assert "No fix lineage found" in text
    conn.close()


def test_cli_fix_lineage(tmp_path: Path) -> None:
    from wicap_assist.cli import main
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)
    conn.close()

    rc = main(["--db", str(db_path), "fix-lineage", "some signature"])
    assert rc == 0
