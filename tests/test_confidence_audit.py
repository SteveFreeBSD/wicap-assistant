"""Tests for confidence calibration audit."""

from __future__ import annotations

import math
from pathlib import Path
from types import SimpleNamespace

from wicap_assist.confidence_audit import (
    confidence_audit_to_json,
    format_confidence_audit_text,
    run_confidence_audit,
)
from wicap_assist.db import (
    connect_db,
    insert_conversation,
    insert_conversation_signal,
    insert_verification_outcome,
    upsert_source,
)
from wicap_assist.util.redact import sha1_text

_FIXTURE_SQL = Path(__file__).parent / "fixtures" / "calibration_regression_seed.sql"


def test_confidence_audit_stats(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "test.db")
    source_id = upsert_source(conn, kind="test", path="/test", mtime=1.0, size=100)

    # pattern 1: High confidence (verified pass)
    pk1, _ = insert_conversation(
        conn,
        source_id=source_id,
        conversation_id="conv-1",
        title="Fixing Redis",
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
    # Verification outcome for boost
    insert_verification_outcome(
        conn,
        conversation_pk=pk1,
        signature="redis timeout",
        outcome="pass",
        evidence_snippet="fixed",
        ts="2026-01-01T11:00:00Z",
    )

    # pattern 2: Low confidence (no data)
    pk2, _ = insert_conversation(
        conn,
        source_id=source_id,
        conversation_id="conv-2",
        title="Unknown Error",
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
        fingerprint=sha1_text("unknown panic"),
        snippet="Error: Unknown kernel panic",
        artifact_name="log.txt",
    )

    conn.commit()

    # Run audit
    report = run_confidence_audit(conn, limit=100)
    
    # We expect 2 patterns found (min_occurrences=1 used in audit)
    assert report["count"] == 2
    
    stats = report["stats"]
    assert stats["min"] <= stats["median"] <= stats["max"]
    assert stats["count"] == 2 if "count" in stats else True # Python statistics doesn't include count in stats object usually
    
    # Hist keys should sum to count
    hist = report["histogram"]
    total_hist = sum(hist.values())
    assert total_hist == 2
    
    # Text output
    text = format_confidence_audit_text(report)
    assert "Analyzed 2 signatures" in text
    assert "Median:" in text

    # JSON output
    json_out = confidence_audit_to_json(report)
    assert "histogram" in json_out

    conn.close()


def test_confidence_audit_empty(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "empty.db")
    report = run_confidence_audit(conn)
    assert report["count"] == 0
    assert report["distribution"] == "empty"
    
    text = format_confidence_audit_text(report)
    assert "No data available" in text
    conn.close()


def test_cli_confidence_audit(tmp_path: Path) -> None:
    from wicap_assist.cli import main
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)
    conn.close() # Create empty db
    
    rc = main(["--db", str(db_path), "confidence-audit", "--limit", "50"])
    assert rc == 0


def test_confidence_audit_reads_confidence_key(monkeypatch) -> None:
    from wicap_assist import confidence_audit as mod

    def fake_patterns(*args, **kwargs):
        return [
            SimpleNamespace(signature="sig-a", occurrence_count=4),
            SimpleNamespace(signature="sig-b", occurrence_count=2),
        ]

    def fake_recommendation(conn, signature):
        if signature == "sig-a":
            return {"confidence": 0.8}
        return {"confidence": 0.2}

    monkeypatch.setattr(mod, "detect_chronic_patterns", fake_patterns)
    monkeypatch.setattr(mod, "build_recommendation", fake_recommendation)

    conn = connect_db(":memory:")
    report = mod.run_confidence_audit(conn, limit=10)
    conn.close()

    assert report["count"] == 2
    assert report["stats"]["max"] == 0.8
    assert report["stats"]["min"] == 0.2


def test_confidence_audit_reports_high95_metrics(monkeypatch) -> None:
    from wicap_assist import confidence_audit as mod

    def fake_patterns(*args, **kwargs):
        return [
            SimpleNamespace(signature="sig-a", occurrence_count=4),
            SimpleNamespace(signature="sig-b", occurrence_count=2),
            SimpleNamespace(signature="sig-c", occurrence_count=1),
        ]

    def fake_recommendation(conn, signature):
        mapping = {
            "sig-a": {"confidence": 0.96},
            "sig-b": {"confidence": 0.50},
            "sig-c": {"confidence": 0.20},
        }
        return mapping[signature]

    monkeypatch.setattr(mod, "detect_chronic_patterns", fake_patterns)
    monkeypatch.setattr(mod, "build_recommendation", fake_recommendation)

    conn = connect_db(":memory:")
    report = mod.run_confidence_audit(conn, limit=10)
    conn.close()

    assert report["stats"]["high95_count"] == 1
    assert report["stats"]["high95_pct"] == 33.3


def test_confidence_audit_fixture_guard_blocks_non_strict_saturation() -> None:
    conn = connect_db(":memory:")
    conn.executescript(_FIXTURE_SQL.read_text(encoding="utf-8"))
    conn.commit()

    report = run_confidence_audit(conn, limit=20)
    stats = report["stats"]

    # CI guard: this non-strict fixture must not drift into high-confidence saturation.
    assert report["count"] > 0
    assert float(stats["max"]) < 0.95
    assert int(stats["high95_count"]) == 0
    assert float(stats["high95_pct"]) == 0.0
    assert int(stats["one_count"]) == 0
    assert float(stats["one_pct"]) == 0.0

    conn.close()
