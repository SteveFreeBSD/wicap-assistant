"""Tests for verification outcome tracking and confidence integration."""

from pathlib import Path

from wicap_assist.db import (
    connect_db,
    insert_conversation,
    insert_verification_outcome,
    query_outcomes_for_signature,
    upsert_source,
)
from wicap_assist.recommend_confidence import _verification_outcome_effect


def _setup_db(tmp_path: Path):
    """Create a fresh DB and return (conn, source_id, conv_pk)."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    source_id = upsert_source(conn, kind="test", path="/test/src", mtime=1.0, size=100)
    conv_pk, _ = insert_conversation(
        conn,
        source_id=source_id,
        conversation_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        title="Test conversation",
        ts_first="2026-02-01T12:00:00Z",
        ts_last="2026-02-01T14:00:00Z",
        task_summary=None,
        artifact_type=None,
    )
    conn.commit()
    return conn, source_id, conv_pk


def test_walkthrough_success_outcome(tmp_path: Path) -> None:
    """Walkthrough with success marker should normalize to pass outcome."""
    conn, _, conv_pk = _setup_db(tmp_path)

    inserted = insert_verification_outcome(
        conn,
        conversation_pk=conv_pk,
        signature="all tests passed",
        outcome="success",
        evidence_snippet="424 passed, 21 skipped",
        ts="2026-02-01T14:00:00Z",
    )
    conn.commit()

    assert inserted is True

    rows = query_outcomes_for_signature(conn, "tests passed")
    assert len(rows) >= 1
    assert rows[0]["outcome"] == "pass"

    conn.close()


def test_walkthrough_failure_outcome(tmp_path: Path) -> None:
    """Walkthrough with failure marker should normalize to fail outcome."""
    conn, _, conv_pk = _setup_db(tmp_path)

    insert_verification_outcome(
        conn,
        conversation_pk=conv_pk,
        signature="docker restart still failing",
        outcome="failure",
        evidence_snippet="Still failing on Docker restart",
        ts="2026-02-01T14:00:00Z",
    )
    conn.commit()

    rows = query_outcomes_for_signature(conn, "docker restart")
    assert len(rows) >= 1
    assert rows[0]["outcome"] == "fail"

    conn.close()


def test_confidence_boost_from_success(tmp_path: Path) -> None:
    """Verification outcome boost from passes is capped at +2."""
    conn, _, conv_pk = _setup_db(tmp_path)

    for i in range(3):
        insert_verification_outcome(
            conn,
            conversation_pk=conv_pk,
            signature="redis timeout fix",
            outcome="success",
            evidence_snippet=f"Verified fix #{i+1}",
            ts=f"2026-02-0{i+1}T14:00:00Z",
        )
    conn.commit()

    effect = _verification_outcome_effect(conn, "redis timeout")
    assert effect.score == 2

    conn.close()


def test_confidence_penalty_from_failure(tmp_path: Path) -> None:
    """Verified failure outcomes should produce negative confidence penalty."""
    conn, _, conv_pk = _setup_db(tmp_path)

    for i in range(2):
        insert_verification_outcome(
            conn,
            conversation_pk=conv_pk,
            signature="docker port conflict regression",
            outcome="failure",
            evidence_snippet=f"Regression #{i+1}",
            ts=f"2026-02-0{i+1}T14:00:00Z",
        )
    conn.commit()

    effect = _verification_outcome_effect(conn, "docker port conflict")
    assert effect.score == -4

    conn.close()


def test_mixed_outcomes_net_effect(tmp_path: Path) -> None:
    """Mixed pass/fail outcomes should compute deterministic net effect."""
    conn, _, conv_pk = _setup_db(tmp_path)

    # +2 capped from passes, -2 for one fail => 0
    for i in range(3):
        insert_verification_outcome(
            conn,
            conversation_pk=conv_pk,
            signature="scout reconnect fix",
            outcome="success",
            evidence_snippet=f"Success #{i+1}",
            ts=f"2026-02-0{i+1}T14:00:00Z",
        )

    insert_verification_outcome(
        conn,
        conversation_pk=conv_pk,
        signature="scout reconnect fix",
        outcome="failure",
        evidence_snippet="Regressed once",
        ts="2026-02-05T14:00:00Z",
    )
    conn.commit()

    effect = _verification_outcome_effect(conn, "scout reconnect")
    assert effect.score == 0

    conn.close()


def test_unknown_outcome_does_not_boost(tmp_path: Path) -> None:
    """Unknown outcomes must not increase verification boost."""
    conn, _, conv_pk = _setup_db(tmp_path)

    insert_verification_outcome(
        conn,
        conversation_pk=conv_pk,
        signature="redis timeout fix",
        outcome="unknown",
        evidence_snippet="Pending verification",
        ts="2026-02-01T14:00:00Z",
    )
    conn.commit()

    rows = query_outcomes_for_signature(conn, "redis timeout")
    assert len(rows) == 1
    assert rows[0]["outcome"] == "unknown"
    assert _verification_outcome_effect(conn, "redis timeout").score == 0

    conn.close()


def test_no_conn_returns_zero() -> None:
    """None connection should return zero boost."""
    effect = _verification_outcome_effect(None, "anything")
    assert effect.score == 0


def test_empty_signature_returns_zero(tmp_path: Path) -> None:
    """Empty signature should return zero boost."""
    conn, _, _ = _setup_db(tmp_path)
    effect = _verification_outcome_effect(conn, "")
    assert effect.score == 0
    conn.close()
