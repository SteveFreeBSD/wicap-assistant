"""Tests for CHANGELOG.md ingestion adapter."""

from pathlib import Path

from wicap_assist import cli
from wicap_assist.db import connect_db
from wicap_assist.ingest.changelog import ingest_changelog, parse_changelog


SAMPLE_CHANGELOG = """\
# Changelog

## [0.9.0] – 2026-01-22

### Added
- **Neuro-Adaptive Channel Governor**: Dynamic dwell time with EMA smoothing
- **Parallel PCAP mining**: ThreadPool-based backfill architecture

### Fixed
- **Redis connection leak**: Proper cleanup in `event_processor.py`
- **TypeErrors in scout.py**: Fixed tuple concatenation issues in packet processing

### Changed
- **Dashboard refresh**: Reduced interval from 5s to 2s for real-time feel

## [0.8.0] – 2026-01-15

### Added
- **Ghost Hunter ML module**: Anomaly detection via Isolation Forest
- **Identity Lattice**: MAC-to-identity graph with LRU eviction

### Fixed
- **Socket.IO reconnect**: Fixed stale websocket connections on page refresh
"""


def test_parse_changelog_sections() -> None:
    """Parser should extract entries from all three section types."""
    entries = parse_changelog(SAMPLE_CHANGELOG)

    # Expect 8 entries total: 4 Added + 3 Fixed + 1 Changed
    assert len(entries) == 8

    sections = {e.section for e in entries}
    assert sections == {"added", "fixed", "changed"}

    # Check release tags
    tags = {e.release_tag for e in entries}
    assert tags == {"0.9.0", "0.8.0"}


def test_parse_changelog_fingerprint_uniqueness() -> None:
    """Each entry should have a unique fingerprint."""
    entries = parse_changelog(SAMPLE_CHANGELOG)
    fingerprints = [e.fingerprint for e in entries]
    assert len(fingerprints) == len(set(fingerprints))


def test_parse_empty_changelog() -> None:
    """Empty changelog should produce zero entries."""
    entries = parse_changelog("")
    assert entries == []

    entries = parse_changelog("# Changelog\n\nNothing here.\n")
    assert entries == []


def test_ingest_changelog_round_trip(tmp_path: Path) -> None:
    """Full ingestion should store entries in SQLite."""
    changelog_path = tmp_path / "CHANGELOG.md"
    changelog_path.write_text(SAMPLE_CHANGELOG, encoding="utf-8")

    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    files_seen, entries_added = ingest_changelog(conn, changelog_path=changelog_path)
    conn.commit()

    assert files_seen == 1
    assert entries_added == 8

    row = conn.execute("SELECT count(*) as cnt FROM changelog_entries").fetchone()
    assert row["cnt"] == 8

    # Second run should detect no changes
    files_seen2, entries_added2 = ingest_changelog(conn, changelog_path=changelog_path)
    assert files_seen2 == 1
    assert entries_added2 == 0

    conn.close()


def test_ingest_changelog_missing_file(tmp_path: Path) -> None:
    """Missing changelog should return (0, 0)."""
    db_path = tmp_path / "test.db"
    conn = connect_db(db_path)

    files_seen, entries_added = ingest_changelog(conn, changelog_path=tmp_path / "nope.md")

    assert files_seen == 0
    assert entries_added == 0

    conn.close()


def test_ingest_scan_changelog_prints_summary_line(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """CLI ingest should print deterministic changelog totals."""
    db_path = tmp_path / "assistant.db"

    def _fake_ingest(conn):
        conn.execute(
            "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
            ("changelog", str(tmp_path / "CHANGELOG.md"), 1.0, 20),
        )
        source_id = int(conn.execute("SELECT id FROM sources LIMIT 1").fetchone()["id"])
        conn.execute(
            """
            INSERT INTO changelog_entries(source_id, release_tag, section, snippet, fingerprint)
            VALUES(?, ?, ?, ?, ?)
            """,
            (source_id, "2026-02-10", "fixed", "A: one", "fp-one"),
        )
        conn.execute(
            """
            INSERT INTO changelog_entries(source_id, release_tag, section, snippet, fingerprint)
            VALUES(?, ?, ?, ?, ?)
            """,
            (source_id, "2026-02-10", "added", "B: two", "fp-two"),
        )
        return 1, 2

    monkeypatch.setattr(cli, "ingest_changelog", _fake_ingest)

    exit_code = cli._run_ingest(
        db_path,
        scan_codex=False,
        scan_soaks=False,
        scan_harness=False,
        scan_antigravity=False,
        scan_changelog=True,
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Changelog: entries_added=2 entries_total=2 sources_seen=1" in captured.out
