"""Incident report generation from bundle output."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from wicap_assist.bundle import resolve_target_filter
from wicap_assist.config import wicap_repo_root
from wicap_assist.git_context import (
    build_git_context,
    load_antigravity_git_evidence,
    load_codex_git_evidence,
    load_codex_git_evidence_fallback,
)
from wicap_assist.harness_match import find_relevant_harness_scripts
from wicap_assist.util.evidence import normalize_signature, parse_utc_datetime
from wicap_assist.util.time import utc_now_iso

_CATEGORIES = ("error", "docker_fail", "pytest_fail")
_SIGNAL_SECTIONS = (
    ("Commands", "commands"),
    ("Errors", "errors"),
    ("File Paths", "file_paths"),
    ("Outcomes", "outcomes"),
)


def default_incidents_dir(*, repo_root: Path | None = None) -> Path:
    resolved_repo_root = repo_root or wicap_repo_root()
    return resolved_repo_root / "docs" / "incidents"


# Compatibility exports for existing imports; do not use as function defaults.
INCIDENTS_DIR = default_incidents_dir()
INDEX_PATH = INCIDENTS_DIR / "INDEX.md"


def load_bundle_json(path: Path) -> dict[str, Any]:
    """Load bundle JSON from file."""
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("bundle json must contain an object")
    return payload


def _resolve_incident_timestamp(
    conn: sqlite3.Connection,
    target: str,
    *,
    repo_root: Path | None = None,
) -> tuple[str, datetime]:
    where_sql, params, _ = resolve_target_filter(target, repo_root=repo_root)
    rows = conn.execute(
        f"""
        SELECT ts_text
        FROM log_events
        WHERE {where_sql} AND ts_text IS NOT NULL AND trim(ts_text) != ''
        """,
        params,
    ).fetchall()

    parsed: list[datetime] = []
    for row in rows:
        ts_text = row["ts_text"]
        if not isinstance(ts_text, str):
            continue
        parsed_dt = parse_utc_datetime(ts_text)
        if parsed_dt is not None:
            parsed.append(parsed_dt)

    if parsed:
        earliest = min(parsed)
        return earliest.strftime("%Y-%m-%dT%H:%M:%SZ"), earliest

    now_iso = utc_now_iso()
    now_dt = datetime.now(timezone.utc)
    return now_iso.replace("+00:00", "Z"), now_dt


def _sanitize_target(target: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", target.strip().lower()).strip("-")
    return slug or "incident"


def _category_total(bundle: dict[str, Any], category: str) -> int:
    summary = bundle.get("log_summary", {})
    entries = summary.get(category, []) if isinstance(summary, dict) else []
    total = 0
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                total += int(entry.get("count", 0))
    return total


def _bundle_harness_references(conn: sqlite3.Connection, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    summary = bundle.get("log_summary", {})
    if not isinstance(summary, dict):
        return []

    related_sessions = bundle.get("related_sessions", [])
    fix_steps: list[str] = []
    if isinstance(related_sessions, list):
        for session in related_sessions:
            if not isinstance(session, dict):
                continue
            matches = session.get("matches", {})
            if not isinstance(matches, dict):
                continue
            commands = matches.get("commands", [])
            if not isinstance(commands, list):
                continue
            for entry in commands:
                if not isinstance(entry, dict):
                    continue
                snippet = str(entry.get("snippet", "")).strip()
                if snippet:
                    fix_steps.append(f"Run `{snippet}`.")

    merged: dict[str, dict[str, Any]] = {}
    for category in _CATEGORIES:
        entries = summary.get(category, [])
        if not isinstance(entries, list):
            continue
        for entry in entries[:3]:
            if not isinstance(entry, dict):
                continue
            snippet = str(entry.get("snippet", "")).strip()
            if not snippet:
                continue
            signature = normalize_signature(snippet)
            matches = find_relevant_harness_scripts(
                conn,
                category=category,
                signature=signature,
                fix_steps=fix_steps,
                context_texts=[snippet],
                top_n=3,
            )
            for match in matches:
                script_path = str(match.get("script_path", ""))
                if not script_path:
                    continue

                current = merged.get(script_path)
                if current is None or int(match.get("score", 0)) > int(current.get("score", 0)):
                    merged[script_path] = {
                        "script_path": script_path,
                        "role": match.get("role"),
                        "score": int(match.get("score", 0)),
                        "matched_commands": list(match.get("matched_commands", [])),
                        "matched_tools": list(match.get("matched_tools", [])),
                        "commands": list(match.get("commands", [])),
                    }
                    continue

                for key in ("matched_commands", "matched_tools", "commands"):
                    existing = current.get(key, [])
                    incoming = match.get(key, [])
                    if not isinstance(existing, list):
                        existing = []
                    if not isinstance(incoming, list):
                        incoming = []
                    combined = sorted({str(value) for value in existing + incoming if str(value)})
                    current[key] = combined

    ranked = sorted(
        merged.values(),
        key=lambda item: (-int(item["score"]), str(item["script_path"])),
    )
    return ranked[:3]


def _bundle_session_git_evidence(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    sessions = bundle.get("related_sessions", [])
    if not isinstance(sessions, list):
        return []

    by_session: dict[str, dict[str, Any]] = {}
    for session in sessions:
        if not isinstance(session, dict):
            continue
        session_id = str(session.get("session_id", "")).strip()
        if not session_id:
            continue
        git = session.get("git", {})
        if not isinstance(git, dict):
            git = {}
        repo_url = git.get("repo_url") or git.get("repository_url")
        branch = git.get("branch")
        commit_hash = git.get("commit_hash")
        has_git = any(
            isinstance(value, str) and value.strip()
            for value in (repo_url, branch, commit_hash)
        )
        if not has_git:
            continue
        by_session[session_id] = {
            "source_id": session_id,
            "source": "codex",
            "repo_url": repo_url,
            "branch": branch,
            "commit_hash": commit_hash,
        }

    return [by_session[key] for key in sorted(by_session)]


def _render_markdown(
    target: str,
    generated_ts: str,
    bundle: dict[str, Any],
    *,
    git_context: dict[str, Any] | None = None,
    harness_refs: list[dict[str, Any]] | None = None,
) -> str:
    lines: list[str] = ["# WICAP Incident Report", "", "## Summary"]
    lines.append(f"- Target: {target}")
    lines.append(f"- Generated: {generated_ts}")
    lines.append("- Error Categories:")
    for category in _CATEGORIES:
        lines.append(f"  - {category}: {_category_total(bundle, category)}")

    lines.extend(["", "## Git Context"])
    ctx = git_context or {}
    lines.append(f"- repo_url: {ctx.get('repo_url')}")
    lines.append(f"- most_common_commit_hash: {ctx.get('most_common_commit_hash')}")
    lines.append(f"- commit_spread: {ctx.get('commit_spread')}")

    evidence_sources = ctx.get("evidence_sources", {})
    if isinstance(evidence_sources, dict):
        lines.append(
            "- evidence_sources: "
            f"codex_sessions={evidence_sources.get('codex_sessions', 0)}, "
            f"antigravity_conversations={evidence_sources.get('antigravity_conversations', 0)}"
        )
    else:
        lines.append("- evidence_sources: codex_sessions=0, antigravity_conversations=0")

    lines.append("- top_commits:")
    unique_commits = ctx.get("unique_commits", [])
    if isinstance(unique_commits, list) and unique_commits:
        for entry in unique_commits[:5]:
            if not isinstance(entry, dict):
                continue
            lines.append(f"  - {entry.get('commit_hash')}: {entry.get('count')}")
    else:
        lines.append("  - (none)")

    lines.append("- top_branches:")
    unique_branches = ctx.get("unique_branches", [])
    if isinstance(unique_branches, list) and unique_branches:
        for entry in unique_branches[:5]:
            if not isinstance(entry, dict):
                continue
            lines.append(f"  - {entry.get('branch')}: {entry.get('count')}")
    else:
        lines.append("  - (none)")

    lines.extend(["", "## Failure Signatures"])
    summary = bundle.get("log_summary", {})
    if not isinstance(summary, dict):
        summary = {}

    for category in _CATEGORIES:
        entries = summary.get(category, [])
        total = _category_total(bundle, category)
        lines.append(f"### {category}")
        lines.append(f"- Occurrences: {total}")
        if isinstance(entries, list) and entries:
            first = entries[0] if isinstance(entries[0], dict) else {}
            snippet = str(first.get("snippet", "(none)"))
            file_path = str(first.get("file", "(none)"))
            lines.append(f"- Example snippet: {snippet}")
            lines.append(f"- Example file path: {file_path}")
        else:
            lines.append("- Example snippet: (none)")
            lines.append("- Example file path: (none)")

    lines.extend(["", "## Related Fix Sessions"])
    sessions = bundle.get("related_sessions", [])
    if not isinstance(sessions, list) or not sessions:
        lines.append("(none)")
    else:
        for session in sessions:
            if not isinstance(session, dict):
                continue
            git = session.get("git", {})
            if not isinstance(git, dict):
                git = {}
            lines.append(f"### Session {session.get('session_id')}")
            lines.append(f"- session_id: {session.get('session_id')}")
            lines.append(f"- ts_last: {session.get('ts_last')}")
            lines.append(f"- repo_url: {git.get('repo_url')}")
            lines.append(f"- branch: {git.get('branch')}")
            lines.append(f"- commit_hash: {git.get('commit_hash')}")
            lines.append(f"- cwd: {session.get('cwd')}")

            matches = session.get("matches", {})
            if not isinstance(matches, dict):
                matches = {}

            for title, key in _SIGNAL_SECTIONS:
                lines.append(title)
                entries = matches.get(key, [])
                if not isinstance(entries, list) or not entries:
                    lines.append("- (none)")
                    continue
                for entry in entries[:5]:
                    if not isinstance(entry, dict):
                        continue
                    lines.append(f"- {entry.get('snippet')}")

    lines.extend(["", "## Nearby Commits"])
    commits = bundle.get("git_commits", [])
    if not isinstance(commits, list) or not commits:
        lines.append("(none)")
    else:
        for commit in commits:
            if not isinstance(commit, dict):
                continue
            lines.append(f"### Commit {commit.get('hash')}")
            lines.append(f"- hash: {commit.get('hash')}")
            lines.append(f"- subject: {commit.get('subject')}")
            lines.append(f"- date: {commit.get('date')}")
            lines.append(f"- overlap score: {commit.get('overlap_score')}")
            lines.append("- changed files:")
            files = commit.get("files", [])
            if isinstance(files, list) and files:
                for file_name in files:
                    lines.append(f"  - {file_name}")
            else:
                lines.append("  - (none)")

    lines.extend(["", "## Harness References"])
    refs = harness_refs or []
    if not refs:
        lines.append("(none)")
    else:
        for entry in refs:
            if not isinstance(entry, dict):
                continue
            lines.append(f"- script_path: {entry.get('script_path')}")
            lines.append(f"- role: {entry.get('role')}")
            commands = entry.get("commands", [])
            if isinstance(commands, list) and commands:
                lines.append(f"- commands: {', '.join(str(value) for value in commands[:3])}")
            else:
                lines.append("- commands: (none)")

    lines.append("")
    return "\n".join(lines)


def _update_index(index_path: Path, *, filename: str, target: str, bundle: dict[str, Any]) -> None:
    date_str = filename[:10]
    stem = Path(filename).stem
    slug = stem[11:] if len(stem) > 11 else stem

    error_count = _category_total(bundle, "error")
    docker_fail_count = _category_total(bundle, "docker_fail")
    pytest_fail_count = _category_total(bundle, "pytest_fail")

    new_entry = (
        f"- [{date_str} {slug}]({filename}) — "
        f"{target} | error={error_count}, docker_fail={docker_fail_count}, pytest_fail={pytest_fail_count}"
    )

    existing_entries: list[str] = []
    if index_path.exists():
        for line in index_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("- ["):
                existing_entries.append(line)

    existing_entries = [entry for entry in existing_entries if f"({filename})" not in entry]
    entries = [new_entry, *existing_entries]

    index_lines = ["# Incident Index", "", *entries, ""]
    index_path.write_text("\n".join(index_lines), encoding="utf-8")


def write_incident_report(
    conn: sqlite3.Connection,
    *,
    target: str,
    bundle: dict[str, Any],
    incidents_dir: Path | None = None,
    repo_root: Path | None = None,
    overwrite: bool = False,
) -> Path:
    """Write incident markdown and update index, returning report path."""
    resolved_repo_root = repo_root or wicap_repo_root()
    resolved_incidents_dir = incidents_dir or default_incidents_dir(repo_root=resolved_repo_root)
    generated_ts, generated_dt = _resolve_incident_timestamp(
        conn,
        target,
        repo_root=resolved_repo_root,
    )
    slug = _sanitize_target(target)
    date_part = generated_dt.strftime("%Y-%m-%d")
    filename = f"{date_part}-{slug}.md"

    resolved_incidents_dir.mkdir(parents=True, exist_ok=True)
    report_path = resolved_incidents_dir / filename

    if report_path.exists() and not overwrite:
        raise FileExistsError(f"Incident report already exists: {report_path}")

    harness_refs = _bundle_harness_references(conn, bundle)
    related_sessions = bundle.get("related_sessions", [])
    related_session_ids: list[str] = []
    if isinstance(related_sessions, list):
        for item in related_sessions:
            if not isinstance(item, dict):
                continue
            session_id = str(item.get("session_id", "")).strip()
            if session_id:
                related_session_ids.append(session_id)
    related_conversation_ids: list[str] = []
    if isinstance(bundle.get("related_conversations"), list):
        for item in bundle.get("related_conversations", []):
            if not isinstance(item, dict):
                continue
            conv_id = str(item.get("conversation_id", "")).strip()
            if conv_id:
                related_conversation_ids.append(conv_id)

    bundle_codex_evidence = _bundle_session_git_evidence(bundle)
    codex_evidence = load_codex_git_evidence(conn, related_session_ids)
    fallback_codex_evidence = load_codex_git_evidence_fallback(
        conn,
        reference_ts=generated_dt,
        window_days=7,
        exclude_session_ids=[
            *(item.get("source_id", "") for item in bundle_codex_evidence),
            *(item.get("source_id", "") for item in codex_evidence),
        ],
    )
    antigravity_evidence = load_antigravity_git_evidence(conn, related_conversation_ids)
    git_context = build_git_context(
        [
            *bundle_codex_evidence,
            *codex_evidence,
            *fallback_codex_evidence,
            *antigravity_evidence,
        ]
    )
    markdown = _render_markdown(
        target=target,
        generated_ts=generated_ts,
        bundle=bundle,
        git_context=git_context,
        harness_refs=harness_refs,
    )
    report_path.write_text(markdown, encoding="utf-8")

    _update_index(
        resolved_incidents_dir / "INDEX.md",
        filename=filename,
        target=target,
        bundle=bundle,
    )

    return report_path
