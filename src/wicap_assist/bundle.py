"""Bundle triage by correlating soak log events with Codex sessions."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.ingest.git_history import (
    GitCommit,
    compute_window_from_mtimes,
    load_git_commits,
)
from wicap_assist.util.evidence import commit_overlap_score, extract_tokens

SOAK_CATEGORIES = ("error", "docker_fail", "pytest_fail")
SIGNAL_CATEGORIES = ("errors", "commands", "file_paths", "outcomes")
_PATH_HINT_RE = re.compile(r"\b(?:src|wicap-ui)/[A-Za-z0-9_./-]+")


def _resolve_target_filter(target: str, *, repo_root: Path) -> tuple[str, list[str], str]:
    raw = target.strip()
    if not raw:
        raise ValueError("target is required")

    resolved_repo_root = repo_root.resolve()
    root_prefix = str(resolved_repo_root) + "/"
    if raw.startswith(root_prefix):
        cleaned = raw.rstrip("/")
        if cleaned.endswith(".log"):
            return "file_path = ?", [cleaned], cleaned
        return "file_path LIKE ?", [cleaned + "/%"], cleaned

    if raw.endswith(".log"):
        if "/" in raw:
            full = str((resolved_repo_root / raw.lstrip("/")).resolve())
            return "file_path = ?", [full], full
        return "file_path LIKE ?", [f"%/{raw}"], raw

    dirname = raw.strip("/").split("/")[-1]
    return "file_path LIKE ?", [f"%/{dirname}/%"], dirname


def resolve_target_filter(target: str, *, repo_root: Path | None = None) -> tuple[str, list[str], str]:
    """Public wrapper for bundle target resolution."""
    resolved_repo_root = repo_root or wicap_repo_root()
    return _resolve_target_filter(target, repo_root=resolved_repo_root)


def _log_summary(conn: sqlite3.Connection, where_sql: str, params: list[str]) -> dict[str, list[dict[str, Any]]]:
    placeholder = ",".join("?" for _ in SOAK_CATEGORIES)
    rows = conn.execute(
        f"""
        SELECT le.category, le.fingerprint, agg.cnt, le.snippet, le.file_path
        FROM (
            SELECT category, fingerprint, COUNT(*) AS cnt, MIN(id) AS min_id
            FROM log_events
            WHERE {where_sql} AND category IN ({placeholder})
            GROUP BY category, fingerprint
        ) AS agg
        JOIN log_events AS le ON le.id = agg.min_id
        ORDER BY le.category ASC, agg.cnt DESC
        """,
        [*params, *SOAK_CATEGORIES],
    ).fetchall()

    out: dict[str, list[dict[str, Any]]] = {category: [] for category in SOAK_CATEGORIES}
    for row in rows:
        category = str(row["category"])
        bucket = out.get(category)
        if bucket is None:
            continue
        if len(bucket) >= 20:
            continue
        bucket.append(
            {
                "count": int(row["cnt"]),
                "snippet": row["snippet"],
                "file": row["file_path"],
                "fingerprint": row["fingerprint"],
            }
        )
    return out


def _related_sessions(
    conn: sqlite3.Connection,
    log_summary: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    token_set: set[str] = set()
    for entries in log_summary.values():
        for item in entries:
            snippet = str(item.get("snippet", ""))
            for token in extract_tokens(snippet, limit=6):
                token_set.add(token)

    tokens = sorted(token_set)
    if not tokens:
        return []

    # Bound query size while keeping broad coverage.
    tokens = tokens[:80]
    where = " OR ".join("lower(sg.snippet) LIKE ?" for _ in tokens)
    args = [f"%{token}%" for token in tokens]

    rows = conn.execute(
        f"""
        SELECT
            s.id AS session_pk,
            s.session_id,
            s.ts_last,
            s.cwd,
            s.branch,
            s.commit_hash,
            s.repo_url,
            s.raw_path,
            sg.category,
            sg.snippet,
            sg.fingerprint
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE s.is_wicap = 1 AND ({where})
        ORDER BY coalesce(s.ts_last, '') DESC, sg.id DESC
        """,
        args,
    ).fetchall()

    grouped: dict[int, dict[str, Any]] = {}
    for row in rows:
        session_pk = int(row["session_pk"])
        bucket = grouped.setdefault(
            session_pk,
            {
                "session_id": row["session_id"],
                "ts_last": row["ts_last"],
                "cwd": row["cwd"],
                "git": {
                    "repo_url": row["repo_url"],
                    "branch": row["branch"],
                    "commit_hash": row["commit_hash"],
                },
                "source": row["raw_path"],
                "matches": {category: [] for category in SIGNAL_CATEGORIES},
                "_score": 0,
                "_seen": set(),
            },
        )

        signal_category = str(row["category"])
        if signal_category not in SIGNAL_CATEGORIES:
            continue

        sig_key = (signal_category, row["fingerprint"])
        if sig_key not in bucket["_seen"]:
            bucket["_seen"].add(sig_key)
            bucket["_score"] += 1

        match_bucket = bucket["matches"][signal_category]
        if len(match_bucket) < 5:
            match_bucket.append(
                {
                    "snippet": row["snippet"],
                    "fingerprint": row["fingerprint"],
                }
            )

    ordered = sorted(
        grouped.values(),
        key=lambda item: (int(item["_score"]), str(item["ts_last"] or "")),
        reverse=True,
    )

    result: list[dict[str, Any]] = []
    for entry in ordered[:5]:
        entry.pop("_score", None)
        entry.pop("_seen", None)
        result.append(entry)
    return result


def _target_files(conn: sqlite3.Connection, where_sql: str, params: list[str]) -> list[str]:
    rows = conn.execute(
        f"""
        SELECT DISTINCT file_path
        FROM log_events
        WHERE {where_sql}
        ORDER BY file_path ASC
        """,
        params,
    ).fetchall()
    return [str(row["file_path"]) for row in rows]


def _extract_path_hints(log_summary: dict[str, list[dict[str, Any]]]) -> set[str]:
    hints: set[str] = set()
    for entries in log_summary.values():
        for item in entries:
            snippet = str(item.get("snippet", ""))
            for match in _PATH_HINT_RE.findall(snippet):
                hints.add(match.rstrip(".,;:!?)\"'`"))
    return hints


def _git_commits_for_bundle(
    conn: sqlite3.Connection,
    where_sql: str,
    params: list[str],
    log_summary: dict[str, list[dict[str, Any]]],
    *,
    repo_root: Path,
) -> list[dict[str, Any]]:
    files = _target_files(conn, where_sql, params)
    window_start, window_end = compute_window_from_mtimes(files)
    commits = load_git_commits(repo_root, window_start, window_end, max_commits=30)

    hints = _extract_path_hints(log_summary)
    for commit in commits:
        commit.overlap_score = commit_overlap_score(commit.files, hints)

    commits.sort(key=lambda item: (item.overlap_score, item.date), reverse=True)

    result: list[dict[str, Any]] = []
    for commit in commits[:30]:
        result.append(
            {
                "hash": commit.hash,
                "author": commit.author,
                "date": commit.date,
                "subject": commit.subject,
                "files": commit.files,
                "overlap_score": commit.overlap_score,
            }
        )
    return result


def build_bundle(conn: sqlite3.Connection, target: str, *, repo_root: Path | None = None) -> dict[str, Any]:
    """Build one triage bundle for a soak target."""
    resolved_repo_root = repo_root or wicap_repo_root()
    where_sql, params, normalized = _resolve_target_filter(target, repo_root=resolved_repo_root)
    summary = _log_summary(conn, where_sql, params)
    related = _related_sessions(conn, summary)
    git_commits = _git_commits_for_bundle(
        conn,
        where_sql,
        params,
        summary,
        repo_root=resolved_repo_root,
    )

    # Drop helper fingerprint used only internally for matching/ranking display quality.
    for category in SOAK_CATEGORIES:
        for item in summary[category]:
            item.pop("fingerprint", None)

    return {
        "target": normalized,
        "log_summary": summary,
        "related_sessions": related,
        "git_commits": git_commits,
    }


def format_bundle_text(bundle: dict[str, Any]) -> str:
    """Render human-readable bundle output."""
    lines: list[str] = [f"Target: {bundle['target']}", "", "Log Summary:"]
    summary = bundle.get("log_summary", {})
    for category in SOAK_CATEGORIES:
        lines.append(f"- {category}:")
        entries = summary.get(category, [])
        if not entries:
            lines.append("  (none)")
            continue
        for item in entries:
            lines.append(f"  - count={item['count']} file={item['file']}")
            lines.append(f"    {item['snippet']}")

    lines.append("")
    lines.append("Related Sessions:")
    related = bundle.get("related_sessions", [])
    if not related:
        lines.append("(none)")
        return "\n".join(lines)

    for idx, session in enumerate(related, start=1):
        git = session.get("git", {})
        lines.append(
            f"{idx}. session_id={session.get('session_id')} ts_last={session.get('ts_last')} cwd={session.get('cwd')}"
        )
        lines.append(
            f"   repo={git.get('repo_url')} branch={git.get('branch')} commit={git.get('commit_hash')}"
        )
        lines.append(f"   source={session.get('source')}")
        matches = session.get("matches", {})
        for category in SIGNAL_CATEGORIES:
            entries = matches.get(category, [])
            if not entries:
                continue
            lines.append(f"   {category}:")
            for item in entries:
                lines.append(f"   - {item['snippet']} [{str(item['fingerprint'])[:10]}]")

    lines.append("")
    lines.append("Git Commits:")
    commits = bundle.get("git_commits", [])
    if not commits:
        lines.append("(none)")
        return "\n".join(lines)

    for idx, commit in enumerate(commits, start=1):
        lines.append(
            f"{idx}. {commit.get('hash')} {commit.get('date')} "
            f"overlap={commit.get('overlap_score')}"
        )
        lines.append(f"   {commit.get('subject')}")
        files = commit.get("files", [])
        if files:
            lines.append(f"   files: {', '.join(files[:8])}")

    return "\n".join(lines)


def bundle_to_json(bundle: dict[str, Any]) -> str:
    """Render bundle as pretty JSON."""
    return json.dumps(bundle, indent=2, ensure_ascii=True)
