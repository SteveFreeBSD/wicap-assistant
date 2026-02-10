from __future__ import annotations

from pathlib import Path

from wicap_assist.changelog_stats import collect_changelog_stats, format_changelog_stats_text
from wicap_assist.cli import main as cli_main
from wicap_assist.db import connect_db


def _seed_entries(conn, root: Path) -> None:
    conn.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("changelog", str(root / "CHANGELOG.md"), 1.0, 100),
    )
    source_id = int(conn.execute("SELECT id FROM sources LIMIT 1").fetchone()["id"])
    conn.executemany(
        """
        INSERT INTO changelog_entries(source_id, release_tag, section, snippet, fingerprint)
        VALUES(?, ?, ?, ?, ?)
        """,
        [
            (source_id, "0.9.0-2026-02-09", "fixed", "A", "fp-1"),
            (source_id, "0.9.0-2026-02-09", "fixed", "B", "fp-2"),
            (source_id, "0.8.0-2026-02-08", "added", "C", "fp-3"),
        ],
    )
    conn.commit()


def test_collect_changelog_stats_includes_available_fields(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    _seed_entries(conn, tmp_path)

    stats = collect_changelog_stats(conn)
    text = format_changelog_stats_text(stats)

    assert stats["total_entries"] == 3
    assert stats["distinct_days"] == 2
    assert stats["top10_change_types"][0] == {"type": "fixed", "count": 2}
    assert "distinct_components" not in stats
    assert "total_entries=3" in text
    assert "distinct_days=2" in text
    assert "- fixed: 2" in text

    conn.close()


def test_cli_changelog_stats_command_prints_summary(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    _seed_entries(conn, tmp_path)
    conn.close()

    rc = cli_main(["--db", str(db_path), "changelog-stats"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "total_entries=3" in out
    assert "distinct_days=2" in out
    assert "top10_change_types:" in out
    assert "- fixed: 2" in out
