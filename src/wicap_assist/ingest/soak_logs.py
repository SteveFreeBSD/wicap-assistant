"""Soak log ingestion for WICAP repository logs."""

from __future__ import annotations

from dataclasses import dataclass
import glob
from pathlib import Path
import re
import sqlite3

from wicap_assist.db import (
    delete_log_events_for_source,
    get_source,
    insert_log_event,
    upsert_source,
)
from wicap_assist.util.redact import sha1_text, to_snippet

WICAP_REPO_ROOT = Path("/home/steve/apps/wicap")
SOAK_PATTERNS = (
    "logs_soak_*/**/*.log",
    "logs_verification_*/**/*.log",
    "wicap.log",
    "wicap_verified.log",
    "soak_test_*.log",
    "wicap-ui/ui.log",
)

_ERROR_RE = re.compile(
    r"(?:Traceback|Exception|Error:|failed to|permission denied|ECONNREFUSED|ETIMEDOUT|EACCES|ENOENT)",
    re.IGNORECASE,
)
_PYTEST_FAIL_RE = re.compile(r"(?:\bFAILED\b|AssertionError|\bE\s{3})")
_PYTEST_PASS_RE = re.compile(r"(?:\bPASSED\b|==.*passed)", re.IGNORECASE)
_WARNING_RE = re.compile(r"\bwarning\b", re.IGNORECASE)
_DOCKER_FAIL_SEVERITY_RE = re.compile(
    r"\b(?:ERROR|Exception|Traceback|FATAL|PANIC|CRITICAL)\b",
    re.IGNORECASE,
)
_DOCKER_FAIL_PHRASE_RE = re.compile(
    r"(?:\bfailed\b|\btimeout\b|\brefused\b|\bdenied\b|\bunhealthy\b|exit code|\bkilled\b|\bOOM\b|\bsegfault\b)",
    re.IGNORECASE,
)
_DOCKER_FAIL_HTTP_200_RE = re.compile(r"HTTP/\d(?:\.\d)?\"\s+200(?:\s+OK)?\b", re.IGNORECASE)
_DOCKER_FAIL_STATE_MARKERS = (
    "restarting",
    "exited",
    "health: unhealthy",
    "back-off",
    "crashloop",
    "error response from daemon",
    "no such container",
    "cannot connect",
)
_TS_PREFIX_RE = re.compile(
    r"^\s*(?:\[)?"
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
)


@dataclass(slots=True)
class LogEvent:
    """Parsed log event from a soak log line."""

    ts_text: str | None
    category: str
    fingerprint: str
    snippet: str
    file_path: str
    extra_json: dict[str, int]


def scan_soak_log_paths(repo_root: Path = WICAP_REPO_ROOT) -> list[Path]:
    """Scan configured WICAP soak log patterns under repo root."""
    seen: set[str] = set()
    results: list[Path] = []

    for pattern in SOAK_PATTERNS:
        full_pattern = str(repo_root / pattern)
        for hit in sorted(glob.glob(full_pattern, recursive=True)):
            path = Path(hit)
            if not path.is_file():
                continue
            resolved = str(path)
            if resolved in seen:
                continue
            seen.add(resolved)
            results.append(path)

    return results


def _extract_ts_text(line: str) -> str | None:
    match = _TS_PREFIX_RE.match(line)
    if not match:
        return None
    return match.group(1)


def _is_docker_fail_context(line_lower: str, file_path: Path) -> bool:
    """Return True when line/file context indicates docker/container scope."""
    if "docker_fail_iter_" in file_path.name.lower():
        return True
    return "docker" in line_lower or "container" in line_lower


def _matches_docker_fail_markers(line: str, line_lower: str) -> bool:
    """Return True when line contains meaningful docker failure markers."""
    if _DOCKER_FAIL_SEVERITY_RE.search(line):
        return True
    if _DOCKER_FAIL_PHRASE_RE.search(line):
        return True
    return any(marker in line_lower for marker in _DOCKER_FAIL_STATE_MARKERS)


def _is_docker_fail_line(line: str, file_path: Path) -> bool:
    """Filter docker_fail lines to keep only operationally meaningful failures."""
    line_lower = line.lower()

    if not _is_docker_fail_context(line_lower, file_path):
        return False

    # Explicitly drop successful HTTP request noise from docker_fail_iter logs.
    if _DOCKER_FAIL_HTTP_200_RE.search(line):
        return False

    if not _matches_docker_fail_markers(line, line_lower):
        return False

    return True


def _categories_for_line(line: str, file_path: Path) -> list[str]:
    categories: list[str] = []
    lower = line.lower()

    if _ERROR_RE.search(line):
        categories.append("error")

    if _is_docker_fail_line(line, file_path):
        categories.append("docker_fail")

    if _PYTEST_FAIL_RE.search(line):
        categories.append("pytest_fail")

    if _PYTEST_PASS_RE.search(line):
        categories.append("pytest_pass")

    if _WARNING_RE.search(line):
        categories.append("warning")

    # Keep info sparse: only when no stronger signal matched and line explicitly marks INFO.
    if not categories and re.search(r"\bINFO\b", line):
        categories.append("info")

    return categories


def parse_soak_log_file(path: Path) -> list[LogEvent]:
    """Parse one log file into categorized line-level events."""
    events: list[LogEvent] = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            categories = _categories_for_line(line, path)
            if not categories:
                continue

            ts_text = _extract_ts_text(line)
            fingerprint = sha1_text(line)
            snippet = to_snippet(line, max_len=200)

            for category in categories:
                events.append(
                    LogEvent(
                        ts_text=ts_text,
                        category=category,
                        fingerprint=fingerprint,
                        snippet=snippet,
                        file_path=str(path),
                        extra_json={"line_number": line_number},
                    )
                )

    return events


def _is_unchanged_source(row: sqlite3.Row | None, *, mtime: float, size: int, kind: str) -> bool:
    if row is None:
        return False
    return float(row["mtime"]) == float(mtime) and int(row["size"]) == int(size) and str(row["kind"]) == kind


def ingest_soak_logs(conn: sqlite3.Connection, repo_root: Path = WICAP_REPO_ROOT) -> tuple[int, int]:
    """Ingest soak logs into log_events and return (files_seen, events_added)."""
    files = scan_soak_log_paths(repo_root=repo_root)
    events_added = 0

    for file_path in files:
        stat = file_path.stat()
        source_row = get_source(conn, str(file_path))
        if _is_unchanged_source(source_row, mtime=stat.st_mtime, size=stat.st_size, kind="soak_log"):
            continue

        source_id = upsert_source(
            conn,
            kind="soak_log",
            path=str(file_path),
            mtime=stat.st_mtime,
            size=stat.st_size,
        )

        delete_log_events_for_source(conn, source_id)

        for event in parse_soak_log_file(file_path):
            inserted = insert_log_event(
                conn,
                source_id=source_id,
                ts_text=event.ts_text,
                category=event.category,
                fingerprint=event.fingerprint,
                snippet=event.snippet,
                file_path=event.file_path,
                extra_json=event.extra_json,
            )
            if inserted:
                events_added += 1

    return len(files), events_added
