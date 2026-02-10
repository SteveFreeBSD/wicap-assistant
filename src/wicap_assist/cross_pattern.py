"""Cross-conversation pattern detection for recurring failure signatures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import sqlite3
from typing import Any

from wicap_assist.util.evidence import parse_utc_datetime

@dataclass(slots=True)
class ChronicPattern:
    """A failure signature that recurs across multiple sources."""

    signature: str
    category: str
    occurrence_count: int
    first_seen: str | None
    last_seen: str | None
    span_days: float
    sources: list[str]
    is_relapse: bool


def _parse_ts(value: str | None) -> datetime | None:
    """Best-effort UTC timestamp parse for ISO and soak-log formats."""
    return parse_utc_datetime(value)


def _compute_span_days(first: str | None, last: str | None) -> float:
    """Compute span in days between two ISO timestamps."""
    dt_first = _parse_ts(first)
    dt_last = _parse_ts(last)
    if dt_first is None or dt_last is None:
        return 0.0
    delta = dt_last - dt_first
    return max(0.0, delta.total_seconds() / 86400.0)


def _detect_relapse(timestamps: list[str], gap_days: float = 7.0) -> bool:
    """Return True if signature has a gap >= gap_days between consecutive appearances."""
    parsed = sorted(ts for raw in timestamps if (ts := _parse_ts(raw)) is not None)
    if len(parsed) < 2:
        return False
    for i in range(1, len(parsed)):
        delta = (parsed[i] - parsed[i - 1]).total_seconds() / 86400.0
        if delta >= gap_days:
            return True
    return False


def detect_chronic_patterns(
    conn: sqlite3.Connection,
    *,
    min_occurrences: int = 3,
    min_span_days: float = 7.0,
    top_n: int = 20,
) -> list[ChronicPattern]:
    """Detect recurring failure signatures across conversations and soak events.

    Queries both conversation_signals and log_events/signals tables, groups by
    normalized fingerprint, and returns patterns meeting occurrence + span thresholds.
    """
    # Collect all error-category signals with their timestamps and sources
    raw_data: dict[str, dict[str, Any]] = {}

    # From conversation signals
    _error_categories = ("errors", "error", "docker_fail", "pytest_fail")
    placeholders = ",".join("?" for _ in _error_categories)

    rows = conn.execute(
        f"""
        SELECT cs.fingerprint, cs.snippet, cs.category, cs.ts,
               c.conversation_id AS source
        FROM conversation_signals AS cs
        JOIN conversations AS c ON c.id = cs.conversation_pk
        WHERE cs.category IN ({placeholders})
        """,
        _error_categories,
    ).fetchall()

    for row in rows:
        fp = str(row["fingerprint"])
        bucket = raw_data.setdefault(fp, {
            "snippet": str(row["snippet"]),
            "category": str(row["category"]),
            "timestamps": [],
            "sources": set(),
        })
        ts = row["ts"]
        if ts:
            bucket["timestamps"].append(str(ts))
        bucket["sources"].add(f"conversation:{row['source']}")

    # From soak log events
    rows = conn.execute(
        f"""
        SELECT le.fingerprint, le.snippet, le.category, le.ts_text AS ts,
               le.file_path AS source
        FROM log_events AS le
        WHERE le.category IN ({placeholders})
        """,
        _error_categories,
    ).fetchall()

    for row in rows:
        fp = str(row["fingerprint"])
        bucket = raw_data.setdefault(fp, {
            "snippet": str(row["snippet"]),
            "category": str(row["category"]),
            "timestamps": [],
            "sources": set(),
        })
        ts = row["ts"]
        if ts:
            bucket["timestamps"].append(str(ts))
        bucket["sources"].add(f"soak:{row['source']}")

    # From Codex session signals
    rows = conn.execute(
        f"""
        SELECT sg.fingerprint, sg.snippet, sg.category, sg.ts,
               s.session_id AS source
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE sg.category IN ({placeholders})
          AND s.is_wicap = 1
        """,
        _error_categories,
    ).fetchall()

    for row in rows:
        fp = str(row["fingerprint"])
        bucket = raw_data.setdefault(fp, {
            "snippet": str(row["snippet"]),
            "category": str(row["category"]),
            "timestamps": [],
            "sources": set(),
        })
        ts = row["ts"]
        if ts:
            bucket["timestamps"].append(str(ts))
        bucket["sources"].add(f"session:{row['source']}")

    # Filter and build patterns
    patterns: list[ChronicPattern] = []

    for fp, bucket in raw_data.items():
        sources = sorted(bucket["sources"])
        count = len(sources)
        if count < min_occurrences:
            continue

        timestamps = bucket["timestamps"]
        timestamps.sort()
        first_seen = timestamps[0] if timestamps else None
        last_seen = timestamps[-1] if timestamps else None
        span = _compute_span_days(first_seen, last_seen)

        if span < min_span_days:
            continue

        is_relapse = _detect_relapse(timestamps)

        patterns.append(ChronicPattern(
            signature=bucket["snippet"],
            category=bucket["category"],
            occurrence_count=count,
            first_seen=first_seen,
            last_seen=last_seen,
            span_days=round(span, 1),
            sources=sources,
            is_relapse=is_relapse,
        ))

    # Sort by occurrence count descending, then span
    patterns.sort(key=lambda p: (-p.occurrence_count, -p.span_days))
    return patterns[:top_n]


def format_chronic_patterns_text(patterns: list[ChronicPattern]) -> str:
    """Render human-readable chronic pattern report."""
    if not patterns:
        return "No chronic patterns detected.\n"

    lines: list[str] = [
        f"Chronic Patterns Detected: {len(patterns)}",
        "=" * 50,
        "",
    ]

    for i, pattern in enumerate(patterns, start=1):
        relapse_tag = " [RELAPSE]" if pattern.is_relapse else ""
        lines.append(f"#{i}: {pattern.signature}{relapse_tag}")
        lines.append(f"   Category: {pattern.category}")
        lines.append(f"   Occurrences: {pattern.occurrence_count}")
        lines.append(f"   Span: {pattern.span_days} days")
        lines.append(f"   First seen: {pattern.first_seen or 'unknown'}")
        lines.append(f"   Last seen: {pattern.last_seen or 'unknown'}")
        lines.append(f"   Sources ({len(pattern.sources)}):")
        for source in pattern.sources[:5]:
            lines.append(f"     - {source}")
        if len(pattern.sources) > 5:
            lines.append(f"     ... and {len(pattern.sources) - 5} more")
        lines.append("")

    return "\n".join(lines)


def chronic_patterns_to_json(patterns: list[ChronicPattern]) -> str:
    """Encode chronic patterns as JSON."""
    data = [
        {
            "signature": p.signature,
            "category": p.category,
            "occurrence_count": p.occurrence_count,
            "first_seen": p.first_seen,
            "last_seen": p.last_seen,
            "span_days": p.span_days,
            "sources": p.sources,
            "is_relapse": p.is_relapse,
        }
        for p in patterns
    ]
    return json.dumps(data, indent=2)
