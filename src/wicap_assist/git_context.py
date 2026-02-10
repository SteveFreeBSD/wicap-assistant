"""Deterministic git context aggregation from stored metadata only."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Any

from wicap_assist.util.time import to_iso


def _has_git_metadata(item: dict[str, Any]) -> bool:
    repo_url = item.get("repo_url")
    branch = item.get("branch")
    commit_hash = item.get("commit_hash")
    return any(
        isinstance(value, str) and value.strip()
        for value in (repo_url, branch, commit_hash)
    )


def _dedupe_evidence_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        source = str(item.get("source") or "").strip().lower()
        source_id = str(item.get("source_id") or "").strip()
        key = (source, source_id)
        if source_id and key in seen:
            continue
        if source_id:
            seen.add(key)
        out.append(item)
    return out


def _parse_dt(value: object) -> datetime | None:
    iso = to_iso(value)
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_git_context(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate git context from normalized evidence item rows."""
    evidence_items = _dedupe_evidence_items(
        [item for item in evidence_items if _has_git_metadata(item)]
    )
    repo_values: list[str] = []
    commit_counts: Counter[str] = Counter()
    branch_counts: Counter[str] = Counter()
    source_counts = {
        "codex_sessions": 0,
        "antigravity_conversations": 0,
    }

    for item in evidence_items:
        source = str(item.get("source") or "").strip().lower()
        if source == "codex":
            source_counts["codex_sessions"] += 1
        elif source == "antigravity":
            source_counts["antigravity_conversations"] += 1

        repo_url = item.get("repo_url")
        branch = item.get("branch")
        commit_hash = item.get("commit_hash")

        if isinstance(repo_url, str) and repo_url.strip():
            repo_values.append(repo_url.strip())
        if isinstance(branch, str) and branch.strip():
            branch_counts[branch.strip()] += 1
        if isinstance(commit_hash, str) and commit_hash.strip():
            commit_counts[commit_hash.strip()] += 1

    unique_repo_values = sorted(set(repo_values))
    repo_url: str | None = unique_repo_values[0] if len(unique_repo_values) == 1 else None

    unique_commits = [
        {"commit_hash": commit_hash, "count": count}
        for commit_hash, count in sorted(commit_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    unique_branches = [
        {"branch": branch, "count": count}
        for branch, count in sorted(branch_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    return {
        "repo_url": repo_url,
        "most_common_commit_hash": unique_commits[0]["commit_hash"] if unique_commits else None,
        "unique_commits": unique_commits,
        "unique_branches": unique_branches,
        "commit_spread": len(commit_counts),
        "evidence_sources": source_counts,
    }


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row["name"]) for row in rows}


def load_codex_git_evidence(
    conn: sqlite3.Connection,
    session_ids: list[str],
) -> list[dict[str, Any]]:
    """Load git evidence from Codex sessions by session_id."""
    ids = sorted({value.strip() for value in session_ids if value and value.strip()})
    if not ids:
        return []

    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        f"""
        SELECT session_id, repo_url, branch, commit_hash
        FROM sessions
        WHERE session_id IN ({placeholders})
        ORDER BY session_id ASC
        """,
        ids,
    ).fetchall()

    return _dedupe_evidence_items(
        [
            {
                "source_id": str(row["session_id"]),
                "source": "codex",
                "repo_url": row["repo_url"],
                "branch": row["branch"],
                "commit_hash": row["commit_hash"],
            }
            for row in rows
        ]
    )


def load_codex_git_evidence_fallback(
    conn: sqlite3.Connection,
    *,
    reference_ts: datetime | None,
    window_days: int = 7,
    exclude_session_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Load fallback Codex git evidence from WICAP sessions in a time window."""
    rows = conn.execute(
        """
        SELECT session_id, ts_last, repo_url, branch, commit_hash
        FROM sessions
        WHERE
            lower(coalesce(cwd, '')) LIKE '%/wicap%'
            AND (
                (repo_url IS NOT NULL AND trim(repo_url) != '')
                OR (commit_hash IS NOT NULL AND trim(commit_hash) != '')
            )
        ORDER BY coalesce(ts_last, '') DESC, session_id ASC
        """
    ).fetchall()

    excluded = {value.strip() for value in (exclude_session_ids or []) if value and value.strip()}
    window = timedelta(days=max(1, int(window_days)))
    filtered: list[dict[str, Any]] = []
    for row in rows:
        session_id = str(row["session_id"]).strip()
        if not session_id or session_id in excluded:
            continue

        if reference_ts is not None:
            session_ts = _parse_dt(row["ts_last"])
            if session_ts is None:
                continue
            if abs(session_ts - reference_ts) > window:
                continue

        filtered.append(
            {
                "source_id": session_id,
                "source": "codex",
                "repo_url": row["repo_url"],
                "branch": row["branch"],
                "commit_hash": row["commit_hash"],
            }
        )
    return _dedupe_evidence_items(filtered)


def load_antigravity_git_evidence(
    conn: sqlite3.Connection,
    conversation_ids: list[str],
) -> list[dict[str, Any]]:
    """Load git evidence from Antigravity conversations when git fields exist."""
    ids = sorted({value.strip() for value in conversation_ids if value and value.strip()})
    if not ids:
        return []

    cols = _table_columns(conn, "conversations")
    required = {"conversation_id", "repo_url", "branch", "commit_hash"}
    if not required.issubset(cols):
        return []

    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        f"""
        SELECT conversation_id, repo_url, branch, commit_hash
        FROM conversations
        WHERE conversation_id IN ({placeholders})
        ORDER BY conversation_id ASC
        """,
        ids,
    ).fetchall()

    return _dedupe_evidence_items(
        [
            {
                "source_id": str(row["conversation_id"]),
                "source": "antigravity",
                "repo_url": row["repo_url"],
                "branch": row["branch"],
                "commit_hash": row["commit_hash"],
            }
            for row in rows
        ]
    )
