"""Changelog statistics helpers."""

from __future__ import annotations

from collections.abc import Mapping
import re
import sqlite3
from typing import Any

_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row["name"]) for row in rows}


def collect_changelog_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """Collect deterministic stats from changelog_entries."""
    stats: dict[str, Any] = {}

    row = conn.execute("SELECT count(*) AS cnt FROM changelog_entries").fetchone()
    stats["total_entries"] = int(row["cnt"]) if row is not None else 0

    columns = _table_columns(conn, "changelog_entries")

    component_column = next((name for name in ("component", "components") if name in columns), None)
    if component_column:
        component_row = conn.execute(
            f"""
            SELECT count(DISTINCT {component_column}) AS cnt
            FROM changelog_entries
            WHERE {component_column} IS NOT NULL AND trim({component_column}) != ''
            """
        ).fetchone()
        stats["distinct_components"] = int(component_row["cnt"]) if component_row is not None else 0

    date_column = next((name for name in ("day", "date", "release_date") if name in columns), None)
    if date_column:
        date_row = conn.execute(
            f"""
            SELECT count(DISTINCT {date_column}) AS cnt
            FROM changelog_entries
            WHERE {date_column} IS NOT NULL AND trim({date_column}) != ''
            """
        ).fetchone()
        stats["distinct_days"] = int(date_row["cnt"]) if date_row is not None else 0
    elif "release_tag" in columns:
        days: set[str] = set()
        for row in conn.execute("SELECT release_tag FROM changelog_entries WHERE release_tag IS NOT NULL"):
            release_tag = str(row["release_tag"])
            match = _DATE_RE.search(release_tag)
            if match:
                days.add(match.group(0))
        stats["distinct_days"] = len(days)

    type_column = next((name for name in ("type", "category", "section") if name in columns), None)
    if type_column:
        rows = conn.execute(
            f"""
            SELECT {type_column} AS change_type, count(*) AS cnt
            FROM changelog_entries
            WHERE {type_column} IS NOT NULL AND trim({type_column}) != ''
            GROUP BY {type_column}
            ORDER BY cnt DESC, {type_column} ASC
            LIMIT 10
            """
        ).fetchall()
        stats["top10_change_types"] = [
            {"type": str(row["change_type"]), "count": int(row["cnt"])}
            for row in rows
        ]

    return stats


def format_changelog_stats_text(stats: Mapping[str, Any]) -> str:
    """Format changelog stats for CLI output."""
    lines: list[str] = []
    lines.append(f"total_entries={int(stats.get('total_entries', 0))}")

    if "distinct_components" in stats:
        lines.append(f"distinct_components={int(stats['distinct_components'])}")
    if "distinct_days" in stats:
        lines.append(f"distinct_days={int(stats['distinct_days'])}")

    if "top10_change_types" in stats:
        lines.append("top10_change_types:")
        top_types = stats.get("top10_change_types") or []
        if top_types:
            for item in top_types:
                if not isinstance(item, Mapping):
                    continue
                lines.append(f"- {item.get('type')}: {int(item.get('count', 0))}")
        else:
            lines.append("- (none)")

    return "\n".join(lines)
