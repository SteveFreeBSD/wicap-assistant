"""Backfill validation report – data completeness metrics."""

from __future__ import annotations

import json
import sqlite3
from typing import Any


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row["name"]) for row in rows}


def _count(conn: sqlite3.Connection, table: str) -> int:
    if not _table_exists(conn, table):
        return 0
    row = conn.execute(f"SELECT count(*) AS cnt FROM {table}").fetchone()
    return int(row["cnt"]) if row else 0


def _date_range(conn: sqlite3.Connection, table: str, ts_col: str) -> dict[str, str | None]:
    """Return earliest and latest values for a timestamp column."""
    if not _table_exists(conn, table):
        return {"earliest": None, "latest": None}
    cols = _table_columns(conn, table)
    if ts_col not in cols:
        return {"earliest": None, "latest": None}
    row = conn.execute(
        f"""
        SELECT min({ts_col}) AS earliest, max({ts_col}) AS latest
        FROM {table}
        WHERE {ts_col} IS NOT NULL AND trim({ts_col}) != ''
        """
    ).fetchone()
    if not row:
        return {"earliest": None, "latest": None}
    return {
        "earliest": str(row["earliest"]) if row["earliest"] else None,
        "latest": str(row["latest"]) if row["latest"] else None,
    }


def generate_backfill_report(conn: sqlite3.Connection) -> dict[str, Any]:
    """Compute data completeness metrics across all ingestion tables."""
    report: dict[str, Any] = {}

    # Sources
    report["sources"] = {"total": _count(conn, "sources")}
    if _table_exists(conn, "sources"):
        kinds = conn.execute(
            "SELECT kind, count(*) AS cnt FROM sources GROUP BY kind ORDER BY cnt DESC"
        ).fetchall()
        report["sources"]["by_kind"] = {str(r["kind"]): int(r["cnt"]) for r in kinds}

    # Sessions
    sessions_total = _count(conn, "sessions")
    report["sessions"] = {"total": sessions_total}
    if _table_exists(conn, "sessions") and sessions_total > 0:
        report["sessions"]["date_range"] = _date_range(conn, "sessions", "ts_last")
        cols = _table_columns(conn, "sessions")
        if "repo_url" in cols:
            row = conn.execute(
                """
                SELECT count(*) AS cnt FROM sessions
                WHERE repo_url IS NULL OR trim(repo_url) = ''
                """
            ).fetchone()
            missing_git = int(row["cnt"]) if row else 0
            report["sessions"]["missing_git_metadata"] = missing_git
            report["sessions"]["with_git_metadata"] = sessions_total - missing_git

    # Log events
    log_total = _count(conn, "log_events")
    report["log_events"] = {"total": log_total}
    if _table_exists(conn, "log_events") and log_total > 0:
        cats = conn.execute(
            "SELECT category, count(*) AS cnt FROM log_events GROUP BY category ORDER BY cnt DESC"
        ).fetchall()
        report["log_events"]["by_category"] = {str(r["category"]): int(r["cnt"]) for r in cats}

    # Conversations
    conv_total = _count(conn, "conversations")
    report["conversations"] = {"total": conv_total}
    if _table_exists(conn, "conversations") and conv_total > 0:
        report["conversations"]["date_range"] = _date_range(conn, "conversations", "ts_first")

    # Conversation signals
    report["conversation_signals"] = {"total": _count(conn, "conversation_signals")}

    # Verification outcomes
    vo_total = _count(conn, "verification_outcomes")
    report["verification_outcomes"] = {"total": vo_total}
    if _table_exists(conn, "verification_outcomes") and vo_total > 0:
        outcomes = conn.execute(
            "SELECT outcome, count(*) AS cnt FROM verification_outcomes GROUP BY outcome ORDER BY cnt DESC"
        ).fetchall()
        report["verification_outcomes"]["by_outcome"] = {
            str(r["outcome"]): int(r["cnt"]) for r in outcomes
        }
        # Conversations with vs without verification outcomes
        if conv_total > 0 and _table_exists(conn, "conversations"):
            row = conn.execute(
                """
                SELECT count(DISTINCT conversation_pk) AS cnt
                FROM verification_outcomes
                WHERE conversation_pk IS NOT NULL
                """
            ).fetchone()
            convs_with_outcomes = int(row["cnt"]) if row else 0
            report["verification_outcomes"]["conversations_with_outcomes"] = convs_with_outcomes
            report["verification_outcomes"]["conversations_without_outcomes"] = (
                conv_total - convs_with_outcomes
            )

    # Changelog entries
    report["changelog_entries"] = {"total": _count(conn, "changelog_entries")}
    if _table_exists(conn, "changelog_entries") and report["changelog_entries"]["total"] > 0:
        cols = _table_columns(conn, "changelog_entries")
        if "release_tag" in cols:
            row = conn.execute(
                "SELECT count(DISTINCT release_tag) AS cnt FROM changelog_entries WHERE release_tag IS NOT NULL"
            ).fetchone()
            report["changelog_entries"]["distinct_releases"] = int(row["cnt"]) if row else 0

    # Coverage gaps
    gaps: list[str] = []
    missing_git = report.get("sessions", {}).get("missing_git_metadata", 0)
    if missing_git > 0:
        gaps.append(f"{missing_git} sessions missing git metadata")
    convs_without = report.get("verification_outcomes", {}).get("conversations_without_outcomes", 0)
    if convs_without > 0:
        gaps.append(f"{convs_without} conversations without verification outcomes")
    if _count(conn, "changelog_entries") == 0:
        gaps.append("No changelog entries ingested")
    if conv_total == 0:
        gaps.append("No Antigravity conversations ingested")
    report["coverage_gaps"] = gaps

    return report


def format_backfill_report_text(report: dict[str, Any]) -> str:
    """Render human-readable backfill report."""
    lines: list[str] = ["=== WICAP Backfill Validation Report ===", ""]

    for section in ("sources", "sessions", "log_events", "conversations",
                    "conversation_signals", "verification_outcomes", "changelog_entries"):
        data = report.get(section, {})
        if not isinstance(data, dict):
            continue
        total = data.get("total", 0)
        lines.append(f"{section}: {total}")

        for key, value in data.items():
            if key == "total":
                continue
            if isinstance(value, dict):
                for subkey, subval in value.items():
                    lines.append(f"  {key}.{subkey}={subval}")
            elif key == "by_kind" or key == "by_category" or key == "by_outcome":
                pass  # already handled as dict above
            else:
                lines.append(f"  {key}={value}")

    gaps = report.get("coverage_gaps", [])
    if gaps:
        lines.append("")
        lines.append("Coverage gaps:")
        for gap in gaps:
            lines.append(f"  ⚠ {gap}")
    else:
        lines.append("")
        lines.append("✓ No coverage gaps detected")

    return "\n".join(lines)


def backfill_report_to_json(report: dict[str, Any]) -> str:
    """Encode backfill report as JSON."""
    return json.dumps(report, indent=2, sort_keys=False)
