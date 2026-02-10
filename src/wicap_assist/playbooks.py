"""Playbook generation from recurring soak failure clusters."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable

from wicap_assist.harness_match import find_relevant_harness_scripts
from wicap_assist.ingest.git_history import GitCommit, compute_window_from_mtimes, load_git_commits
from wicap_assist.util.evidence import (
    commit_overlap_score,
    extract_tokens,
    normalize_signature as _normalize_signature,
)

WICAP_REPO_ROOT = Path("/home/steve/apps/wicap")
PLAYBOOKS_DIR = WICAP_REPO_ROOT / "docs" / "playbooks"
INDEX_PATH = PLAYBOOKS_DIR / "INDEX.md"

_CATEGORIES = ("error", "docker_fail", "pytest_fail")
_SIGNAL_CATEGORIES = ("errors", "commands", "file_paths", "outcomes")
_PATH_HINT_RE = re.compile(r"\b(?:src|wicap-ui)/[A-Za-z0-9_./-]+")
_SERVICE_RE = re.compile(r"\b(?:wicap|redis|sql|odbc|docker|systemd)\b", re.IGNORECASE)
_COMMAND_TRAILING_FP_RE = re.compile(r"(?:\s*\[[0-9a-f]{8,40}\])+\s*$", re.IGNORECASE)
_LEADING_BULLET_RE = re.compile(r"^\s*[-*]\s+")


def normalize_signature(snippet: str) -> str:
    """Compatibility shim: delegate to canonical evidence normalization."""
    return _normalize_signature(snippet)


def _slugify(text: str, *, max_len: int = 64) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug[:max_len] or "cluster").strip("-") or "cluster"


def _cluster_failures(conn: sqlite3.Connection, top_n: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT category, snippet, file_path
        FROM log_events
        WHERE category IN ('error', 'docker_fail', 'pytest_fail')
        """
    ).fetchall()

    clusters: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        category = str(row["category"])
        snippet = str(row["snippet"])
        file_path = str(row["file_path"])
        signature = normalize_signature(snippet)
        key = (category, signature)

        bucket = clusters.setdefault(
            key,
            {
                "category": category,
                "signature": signature,
                "count": 0,
                "snippet_counts": Counter(),
                "file_counts": Counter(),
            },
        )
        bucket["count"] += 1
        bucket["snippet_counts"][snippet] += 1
        bucket["file_counts"][file_path] += 1

    materialized: list[dict[str, Any]] = []
    for cluster in clusters.values():
        snippet_counts: Counter[str] = cluster["snippet_counts"]
        file_counts: Counter[str] = cluster["file_counts"]

        example_snippet = ""
        if snippet_counts:
            example_snippet = sorted(snippet_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]

        example_file = ""
        if file_counts:
            example_file = sorted(file_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]

        materialized.append(
            {
                "category": cluster["category"],
                "signature": cluster["signature"],
                "count": int(cluster["count"]),
                "example_snippet": example_snippet,
                "example_file": example_file,
                "files": sorted(file_counts.keys()),
            }
        )

    materialized.sort(key=lambda item: (-int(item["count"]), str(item["category"]), str(item["signature"])))
    return materialized[: max(1, int(top_n))]


def _related_sessions(conn: sqlite3.Connection, cluster: dict[str, Any]) -> list[dict[str, Any]]:
    token_set: set[str] = set()
    for token in extract_tokens(str(cluster["signature"]), limit=6):
        token_set.add(token)
    for token in extract_tokens(str(cluster["example_snippet"]), limit=6):
        token_set.add(token)

    tokens = sorted(token_set)
    if not tokens:
        return []

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
                "repo_url": row["repo_url"],
                "branch": row["branch"],
                "commit_hash": row["commit_hash"],
                "source": row["raw_path"],
                "matches": {key: [] for key in _SIGNAL_CATEGORIES},
                "_score": 0,
                "_seen": set(),
            },
        )

        category = str(row["category"])
        if category not in _SIGNAL_CATEGORIES:
            continue

        fp_key = (category, str(row["fingerprint"]))
        if fp_key not in bucket["_seen"]:
            bucket["_seen"].add(fp_key)
            bucket["_score"] += 1

        target_list = bucket["matches"][category]
        if len(target_list) < 5:
            target_list.append({"snippet": str(row["snippet"]), "fingerprint": str(row["fingerprint"])})

    ordered = sorted(
        grouped.values(),
        key=lambda item: (int(item["_score"]), str(item["ts_last"] or ""), str(item["session_id"])),
        reverse=True,
    )

    results: list[dict[str, Any]] = []
    for item in ordered[:5]:
        item.pop("_score", None)
        item.pop("_seen", None)
        results.append(item)
    return results


def _collect_signal_values(sessions: list[dict[str, Any]], category: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for session in sessions:
        matches = session.get("matches", {})
        entries = matches.get(category, []) if isinstance(matches, dict) else []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            snippet = str(entry.get("snippet", "")).strip()
            if not snippet or snippet in seen:
                continue
            seen.add(snippet)
            values.append(snippet)
    return values


def _normalize_command_snippet(snippet: str) -> str:
    value = snippet.strip()
    value = _LEADING_BULLET_RE.sub("", value)

    if value.lower().startswith("run `") and value.endswith("`."):
        value = value[5:-2]
    elif value.lower().startswith("run `") and value.endswith("`"):
        value = value[5:-1]

    value = value.strip().strip("`")
    value = _COMMAND_TRAILING_FP_RE.sub("", value).strip()
    value = value.rstrip(".").strip()
    return value


def _command_priority(command: str) -> tuple[int, str]:
    lowered = command.lower()
    if "python scripts/check_wicap_status.py" in lowered:
        return (0, lowered)
    if "docker logs" in lowered:
        return (1, lowered)
    if "docker ps" in lowered:
        return (2, lowered)
    if "systemctl" in lowered:
        return (3, lowered)
    if "start_wicap.py" in lowered:
        return (4, lowered)
    if lowered.startswith("cd ") or lowered == "cd" or lowered.startswith("ls ") or lowered == "ls":
        return (100, lowered)
    return (10, lowered)


def _preferred_commands(sessions: list[dict[str, Any]]) -> list[str]:
    raw = _collect_signal_values(sessions, "commands")
    dedup: dict[str, str] = {}
    for value in raw:
        normalized = _normalize_command_snippet(value)
        if not normalized:
            continue
        key = normalized.lower()
        if key not in dedup:
            dedup[key] = normalized

    commands = list(dedup.values())
    commands.sort(key=_command_priority)
    return commands


def _generic_check_commands(category: str) -> list[str]:
    if category == "docker_fail":
        return [
            "docker ps",
            "docker logs wicap-ui --tail 200",
            "systemctl status docker",
            "python scripts/check_wicap_status.py --sql-only",
        ]
    return [
        "docker ps",
        "docker logs wicap-processor --tail 200",
        "python scripts/check_wicap_status.py --sql-only",
        "python scripts/check_wicap_status.py --local-only",
    ]


def _build_quick_checks(cluster: dict[str, Any], sessions: list[dict[str, Any]]) -> list[str]:
    checks: list[str] = []
    seen: set[str] = set()
    commands = _preferred_commands(sessions)

    for command in commands:
        if len(checks) >= 5:
            break
        checkish = bool(re.search(r"check|status|logs|journalctl|systemctl|pytest|soak|docker", command, re.IGNORECASE))
        if not checkish:
            continue
        key = command.lower()
        if key in seen:
            continue
        seen.add(key)
        checks.append(command)

    for generic in _generic_check_commands(str(cluster["category"])):
        if len(checks) >= 5:
            break
        key = generic.lower()
        if key in seen:
            continue
        seen.add(key)
        checks.append(generic)

    if not checks:
        checks = _generic_check_commands(str(cluster["category"]))[:3]
    return checks[:5]


def _build_fix_steps(cluster: dict[str, Any], sessions: list[dict[str, Any]]) -> list[str]:
    steps: list[str] = []
    seen_commands: set[str] = set()
    seen_steps: set[str] = set()
    commands = _preferred_commands(sessions)
    outcomes = _collect_signal_values(sessions, "outcomes")

    for command in commands:
        if len(steps) >= 8:
            break
        key = command.lower()
        if key in seen_commands:
            continue
        seen_commands.add(key)
        line = f"Run `{command}`."
        if line in seen_steps:
            continue
        seen_steps.add(line)
        steps.append(line)

    for outcome in outcomes:
        if len(steps) >= 8:
            break
        if not re.search(r"fixed|resolved|works now|success|failed", outcome, re.IGNORECASE):
            continue
        line = f"Apply known fix pattern: {outcome}"
        if line in seen_steps:
            continue
        seen_steps.add(line)
        steps.append(line)

    fallback = [
        "Inspect recent logs for the trigger signature and isolate the failing component.",
        "Apply the smallest config or code change that addresses the signature.",
        "Restart affected services and rerun the failing flow.",
    ]
    for line in fallback:
        if len(steps) >= 8:
            break
        if line in seen_steps:
            continue
        seen_steps.add(line)
        steps.append(line)

    return steps[:8] if len(steps) > 8 else steps[: max(3, len(steps))]


def _build_verify(cluster: dict[str, Any], sessions: list[dict[str, Any]]) -> list[str]:
    commands = _preferred_commands(sessions)
    selected: list[str] = []

    for command in commands:
        if "python scripts/check_wicap_status.py" in command.lower():
            selected.append(command)
            break

    for command in commands:
        if "docker logs" in command.lower():
            if command not in selected:
                selected.append(command)
            break

    if not selected:
        selected = _generic_check_commands(str(cluster["category"]))[:2]
    elif len(selected) == 1 and "docker logs" not in selected[0].lower():
        default_logs = "docker logs wicap-ui --tail 200" if str(cluster["category"]) == "docker_fail" else "docker logs wicap-processor --tail 200"
        if default_logs.lower() != selected[0].lower():
            selected.append(default_logs)

    # Ensure max 2 and deterministic order while deduping.
    ordered: list[str] = []
    seen: set[str] = set()
    for command in selected:
        key = command.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(command)
        if len(ordered) >= 2:
            break
    return ordered


def _cluster_path_hints(cluster: dict[str, Any], sessions: list[dict[str, Any]]) -> set[str]:
    hints: set[str] = set()
    for match in _PATH_HINT_RE.findall(str(cluster.get("example_snippet", ""))):
        hints.add(match.rstrip(".,;:!?)\"'`"))

    for snippet in _collect_signal_values(sessions, "file_paths"):
        for match in _PATH_HINT_RE.findall(snippet):
            hints.add(match.rstrip(".,;:!?)\"'`"))
    return hints


def _related_commits(
    cluster: dict[str, Any],
    sessions: list[dict[str, Any]],
    *,
    repo_root: Path,
    load_commits_fn: Callable[..., list[GitCommit]],
) -> list[dict[str, Any]]:
    files = [str(value) for value in cluster.get("files", [])]
    window_start, window_end = compute_window_from_mtimes(files)
    commits = load_commits_fn(repo_root, window_start, window_end, max_commits=30)

    hints = _cluster_path_hints(cluster, sessions)
    for commit in commits:
        commit.overlap_score = commit_overlap_score(commit.files, hints)

    commits.sort(key=lambda item: (int(item.overlap_score), str(item.date), str(item.hash)), reverse=True)

    out: list[dict[str, Any]] = []
    for commit in commits[:5]:
        out.append(
            {
                "hash": commit.hash,
                "subject": commit.subject,
                "date": commit.date,
                "overlap_score": int(commit.overlap_score),
                "files": list(commit.files),
            }
        )
    return out


def _short_title(cluster: dict[str, Any]) -> str:
    words = [word for word in str(cluster["signature"]).split() if word]
    prefix = str(cluster["category"]).replace("_", " ").title()
    if not words:
        return prefix
    return f"{prefix} - {' '.join(words[:8])}"


def _render_playbook(
    cluster: dict[str, Any],
    sessions: list[dict[str, Any]],
    commits: list[dict[str, Any]],
    *,
    fix_steps: list[str] | None = None,
    harness_refs: list[dict[str, Any]] | None = None,
) -> str:
    quick_checks = _build_quick_checks(cluster, sessions)
    resolved_fix_steps = fix_steps if fix_steps is not None else _build_fix_steps(cluster, sessions)
    verify = _build_verify(cluster, sessions)
    resolved_harness_refs = harness_refs or []

    lines: list[str] = [f"# Playbook: {_short_title(cluster)}", "", "## Trigger"]
    lines.append(f"- Category: {cluster['category']}")
    lines.append(f"- Signature: {cluster['signature']}")
    lines.append(f"- Seen: {cluster['count']} events")
    lines.append(f"- Example file: {cluster['example_file']}")

    lines.extend(["", "## Quick checks"])
    for item in quick_checks:
        lines.append(f"- `{item}`")

    lines.extend(["", "## Fix steps"])
    for index, step in enumerate(resolved_fix_steps, start=1):
        lines.append(f"{index}. {step}")

    lines.extend(["", "## Verify"])
    for item in verify:
        lines.append(f"- `{item}`")

    lines.extend(["", "## Harness Integration"])
    if resolved_harness_refs:
        for entry in resolved_harness_refs[:3]:
            match_parts: list[str] = []
            commands = entry.get("matched_commands", [])
            tools = entry.get("matched_tools", [])
            if isinstance(commands, list) and commands:
                match_parts.append(f"commands={', '.join(str(value) for value in commands[:3])}")
            if isinstance(tools, list) and tools:
                match_parts.append(f"tools={', '.join(str(value) for value in tools[:3])}")
            match_text = "; ".join(match_parts) if match_parts else "matches=category/role"
            lines.append(f"- {entry.get('script_path')} | role={entry.get('role')} | {match_text}")
    else:
        lines.append("- (none)")

    lines.extend(["", "## Notes"])
    lines.append("- Related sessions:")
    if sessions:
        for session in sessions[:5]:
            lines.append(f"  - {session['session_id']} ({session['ts_last']})")
    else:
        lines.append("  - (none)")

    if commits:
        lines.append("- Related commits:")
        for commit in commits[:5]:
            changed = ", ".join(commit["files"][:5]) if commit["files"] else "(none)"
            lines.append(
                f"  - {commit['hash']} | {commit['date']} | overlap={commit['overlap_score']} | "
                f"{commit['subject']} | files: {changed}"
            )

    lines.append("")
    return "\n".join(lines)


def _update_index(playbooks_dir: Path, generated: list[dict[str, Any]]) -> None:
    index_path = playbooks_dir / "INDEX.md"

    new_lines = [
        f"- [{entry['filename']}]({entry['filename']}) | seen={entry['count']} | {entry['signature']}"
        for entry in generated
    ]

    existing_lines: list[str] = []
    if index_path.exists():
        for line in index_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("- ["):
                continue
            existing_lines.append(line)

    filenames = {entry["filename"] for entry in generated}
    filtered_existing = [line for line in existing_lines if not any(f"({name})" in line for name in filenames)]

    content = ["# Playbook Index", "", *new_lines, *filtered_existing, ""]
    index_path.write_text("\n".join(content), encoding="utf-8")


def generate_playbooks(
    conn: sqlite3.Connection,
    *,
    top_n: int = 5,
    playbooks_dir: Path = PLAYBOOKS_DIR,
    repo_root: Path = WICAP_REPO_ROOT,
    load_commits_fn: Callable[..., list[GitCommit]] = load_git_commits,
) -> list[Path]:
    """Generate or update top-N playbooks and return their paths."""
    clusters = _cluster_failures(conn, top_n=max(1, int(top_n)))
    if not clusters:
        playbooks_dir.mkdir(parents=True, exist_ok=True)
        _update_index(playbooks_dir, [])
        return []

    playbooks_dir.mkdir(parents=True, exist_ok=True)
    generated_meta: list[dict[str, Any]] = []
    generated_paths: list[Path] = []

    for cluster in clusters:
        sessions = _related_sessions(conn, cluster)
        commits = _related_commits(
            cluster,
            sessions,
            repo_root=repo_root,
            load_commits_fn=load_commits_fn,
        )
        fix_steps = _build_fix_steps(cluster, sessions)
        harness_refs = find_relevant_harness_scripts(
            conn,
            category=str(cluster["category"]),
            signature=str(cluster["signature"]),
            fix_steps=fix_steps,
            context_texts=[str(cluster.get("example_snippet", ""))],
            top_n=3,
        )

        slug = _slugify(str(cluster["signature"]))
        filename = f"{cluster['category']}-{slug}.md"
        path = playbooks_dir / filename

        markdown = _render_playbook(
            cluster,
            sessions,
            commits,
            fix_steps=fix_steps,
            harness_refs=harness_refs,
        )
        path.write_text(markdown, encoding="utf-8")

        generated_paths.append(path)
        generated_meta.append(
            {
                "filename": filename,
                "count": int(cluster["count"]),
                "signature": str(cluster["signature"]),
            }
        )

    _update_index(playbooks_dir, generated_meta)
    return generated_paths
