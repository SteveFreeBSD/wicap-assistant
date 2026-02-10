"""Tests for cross-conversation chronic pattern detection."""

import json
from pathlib import Path

from wicap_assist.cross_pattern import (
    chronic_patterns_to_json,
    detect_chronic_patterns,
    format_chronic_patterns_text,
)
from wicap_assist.db import (
    connect_db,
    insert_conversation,
    insert_conversation_signal,
    upsert_source,
)
from wicap_assist.util.redact import sha1_text


def _seed_conversation_error(
    conn, source_id: int, conv_id: str, fingerprint: str, snippet: str, ts: str
) -> None:
    """Insert a conversation with one error signal."""
    conv_pk, _ = insert_conversation(
        conn,
        source_id=source_id,
        conversation_id=conv_id,
        title="Test conv",
        ts_first=ts,
        ts_last=ts,
        task_summary=None,
        artifact_type=None,
    )
    insert_conversation_signal(
        conn,
        conversation_pk=conv_pk,
        ts=ts,
        category="error",
        fingerprint=fingerprint,
        snippet=snippet,
        artifact_name="task.md",
    )


def test_detects_pattern_across_sources(tmp_path: Path) -> None:
    """Pattern appearing in >= 3 sources should be detected."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    source_id = upsert_source(conn, kind="test", path="/test/src", mtime=1.0, size=100)
    fp = sha1_text("redis timeout error")

    for i in range(4):
        _seed_conversation_error(
            conn, source_id,
            conv_id=f"aaaa{i:04d}-bbbb-cccc-dddd-eeeeeeeeeeee",
            fingerprint=fp,
            snippet="redis timeout error",
            ts=f"2026-01-{10 + i}T12:00:00Z",
        )
    conn.commit()

    patterns = detect_chronic_patterns(conn, min_occurrences=3, min_span_days=1.0)
    assert len(patterns) >= 1
    assert patterns[0].signature == "redis timeout error"
    assert patterns[0].occurrence_count >= 3

    conn.close()


def test_ignores_below_threshold(tmp_path: Path) -> None:
    """Pattern appearing in < min_occurrences should be ignored."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    source_id = upsert_source(conn, kind="test", path="/test/src", mtime=1.0, size=100)
    fp = sha1_text("rare error")

    for i in range(2):
        _seed_conversation_error(
            conn, source_id,
            conv_id=f"bbbb{i:04d}-cccc-dddd-eeee-ffffffffffff",
            fingerprint=fp,
            snippet="rare error",
            ts=f"2026-01-{10 + i}T12:00:00Z",
        )
    conn.commit()

    patterns = detect_chronic_patterns(conn, min_occurrences=3, min_span_days=0.0)
    assert len(patterns) == 0

    conn.close()


def test_relapse_detection(tmp_path: Path) -> None:
    """Pattern with a >= 7-day gap should be marked as relapse."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    source_id = upsert_source(conn, kind="test", path="/test/src", mtime=1.0, size=100)
    fp = sha1_text("docker restart loop")

    timestamps = ["2026-01-01T12:00:00Z", "2026-01-02T12:00:00Z", "2026-01-15T12:00:00Z"]
    for i, ts in enumerate(timestamps):
        _seed_conversation_error(
            conn, source_id,
            conv_id=f"cccc{i:04d}-dddd-eeee-ffff-000000000000",
            fingerprint=fp,
            snippet="docker restart loop",
            ts=ts,
        )
    conn.commit()

    patterns = detect_chronic_patterns(conn, min_occurrences=3, min_span_days=1.0)
    assert len(patterns) >= 1
    pattern = patterns[0]
    assert pattern.is_relapse is True
    assert pattern.span_days >= 13.0

    conn.close()


def test_json_output(tmp_path: Path) -> None:
    """JSON output should be valid JSON with expected fields."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    source_id = upsert_source(conn, kind="test", path="/test/src", mtime=1.0, size=100)
    fp = sha1_text("json test error")

    for i in range(3):
        _seed_conversation_error(
            conn, source_id,
            conv_id=f"dddd{i:04d}-eeee-ffff-0000-111111111111",
            fingerprint=fp,
            snippet="json test error",
            ts=f"2026-01-{10 + i}T12:00:00Z",
        )
    conn.commit()

    patterns = detect_chronic_patterns(conn, min_occurrences=3, min_span_days=0.0)
    output = chronic_patterns_to_json(patterns)
    data = json.loads(output)

    assert isinstance(data, list)
    assert len(data) >= 1
    assert "signature" in data[0]
    assert "is_relapse" in data[0]
    assert "occurrence_count" in data[0]

    conn.close()


def test_text_output_empty() -> None:
    """Empty patterns should produce 'no chronic patterns' message."""
    output = format_chronic_patterns_text([])
    assert "No chronic patterns" in output


def test_soak_comma_timestamps_produce_nonzero_span(tmp_path: Path) -> None:
    """Soak-format timestamps (YYYY-MM-DD HH:MM:SS,mmm) should parse and produce real spans."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    source_id = upsert_source(conn, kind="soak_log", path="/test/soak", mtime=1.0, size=100)

    # Insert soak-format log events with comma-millisecond timestamps
    soak_timestamps = [
        "2026-01-30 02:52:13,585",
        "2026-02-01 10:30:00,123",
        "2026-02-05 15:45:22,999",
    ]
    fp = sha1_text("pyodbc timeout on sql write path")
    for idx, ts in enumerate(soak_timestamps, start=1):
        conn.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (source_id, ts, fp, "pyodbc timeout on sql write path", f"/test/soak/run_{idx}.log"),
        )
    conn.commit()

    patterns = detect_chronic_patterns(conn, min_occurrences=3, min_span_days=1.0)
    assert len(patterns) >= 1
    pattern = patterns[0]
    assert pattern.span_days >= 6.0  # Jan 30 -> Feb 5 ≈ 6.5 days
    assert pattern.first_seen is not None
    assert pattern.last_seen is not None

    conn.close()


def test_parse_ts_soak_format() -> None:
    """_parse_ts should handle soak comma-millisecond format."""
    from wicap_assist.cross_pattern import _parse_ts

    result = _parse_ts("2026-01-30 02:52:13,585")
    assert result is not None
    assert result.year == 2026
    assert result.month == 1
    assert result.day == 30
    assert result.hour == 2
    assert result.minute == 52

    # Normal ISO should still work
    assert _parse_ts("2026-01-15T12:00:00Z") is not None
    assert _parse_ts(None) is None
    assert _parse_ts("") is None
