"""Daily regression and health report from soak log events."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from wicap_assist.incident import INCIDENTS_DIR
from wicap_assist.playbooks import PLAYBOOKS_DIR
from wicap_assist.util.evidence import extract_tokens, normalize_signature, parse_utc_datetime

_CATEGORIES = ("error", "docker_fail", "pytest_fail")
_DATE_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-")


def _parse_event_ts(ts_text: object, fallback_mtime: object) -> datetime:
    parsed = parse_utc_datetime(ts_text)
    if parsed is not None:
        return parsed

    try:
        return datetime.fromtimestamp(float(fallback_mtime), tz=timezone.utc)
    except (TypeError, ValueError):
        return datetime.fromtimestamp(0.0, tz=timezone.utc)


def _load_playbook_map(playbooks_dir: Path) -> dict[tuple[str, str], str]:
    mapped: dict[tuple[str, str], str] = {}
    if not playbooks_dir.exists():
        return mapped

    for path in sorted(playbooks_dir.glob("*.md")):
        if path.name.upper() == "INDEX.MD":
            continue
        category = None
        signature = None
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("- Category: "):
                category = line[len("- Category: ") :].strip()
            elif line.startswith("- Signature: "):
                signature = line[len("- Signature: ") :].strip()
            if category and signature:
                mapped[(category, signature)] = path.name
                break
    return mapped


def _incident_date_key(path: Path) -> tuple[datetime, str]:
    match = _DATE_PREFIX_RE.match(path.name)
    if match:
        try:
            parsed = datetime.strptime(match.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return parsed, path.name
        except ValueError:
            pass
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc), path.name


def _signature_tokens(signature: str) -> list[str]:
    return extract_tokens(signature, limit=32, stopwords={"n", "hex", "mac"})


def _match_incident_filename(signature: str, category: str, incidents_dir: Path) -> str | None:
    if not incidents_dir.exists():
        return None

    tokens = _signature_tokens(signature)
    if not tokens:
        return None

    min_score = 2 if len(tokens) >= 2 else 1
    candidates: list[tuple[datetime, str]] = []
    category_marker = f"### {category.lower()}"

    for path in sorted(incidents_dir.glob("*.md")):
        if path.name.upper() == "INDEX.MD":
            continue

        content = path.read_text(encoding="utf-8", errors="ignore").lower()
        if category_marker not in content:
            continue

        score = 0
        for token in tokens:
            if token in content:
                score += 1
        if score < min_score:
            continue

        candidates.append(_incident_date_key(path))

    if not candidates:
        return None

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][1]


def generate_daily_report(
    conn: sqlite3.Connection,
    *,
    days: int = 3,
    top: int = 10,
    now: datetime | None = None,
    playbooks_dir: Path = PLAYBOOKS_DIR,
    incidents_dir: Path = INCIDENTS_DIR,
) -> dict[str, Any]:
    """Build daily regression report data."""
    bounded_days = max(1, int(days))
    bounded_top = max(1, int(top))
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    recent_start = now_utc - timedelta(days=bounded_days)
    baseline_start = recent_start - timedelta(days=bounded_days)

    rows = conn.execute(
        """
        SELECT le.category, le.snippet, le.file_path, le.ts_text, s.mtime
        FROM log_events AS le
        JOIN sources AS s ON s.id = le.source_id
        WHERE le.category IN ('error', 'docker_fail', 'pytest_fail')
        """
    ).fetchall()

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        category = str(row["category"])
        snippet = str(row["snippet"])
        file_path = str(row["file_path"])
        event_ts = _parse_event_ts(row["ts_text"], row["mtime"])

        if event_ts < baseline_start or event_ts > now_utc:
            continue

        signature = normalize_signature(snippet)
        key = (category, signature)
        bucket = grouped.setdefault(
            key,
            {
                "category": category,
                "signature": signature,
                "recent_count": 0,
                "baseline_count": 0,
                "file_counts": Counter(),
            },
        )

        if event_ts >= recent_start:
            bucket["recent_count"] += 1
            bucket["file_counts"][file_path] += 1
        else:
            bucket["baseline_count"] += 1

    playbook_map = _load_playbook_map(playbooks_dir)

    items: list[dict[str, Any]] = []
    for bucket in grouped.values():
        recent_count = int(bucket["recent_count"])
        baseline_count = int(bucket["baseline_count"])
        trend_score = recent_count - baseline_count

        if recent_count < 5 or trend_score <= 0:
            continue

        file_counts: Counter[str] = bucket["file_counts"]
        example_file = ""
        if file_counts:
            example_file = sorted(file_counts.items(), key=lambda entry: (-entry[1], entry[0]))[0][0]

        signature = str(bucket["signature"])
        category = str(bucket["category"])
        playbook = playbook_map.get((category, signature))
        incident = _match_incident_filename(signature, category, incidents_dir)

        items.append(
            {
                "signature": signature,
                "category": category,
                "recent_count": recent_count,
                "baseline_count": baseline_count,
                "trend_score": trend_score,
                "example_file": example_file,
                "playbook": playbook,
                "incident": incident,
            }
        )

    items.sort(
        key=lambda item: (
            -int(item["trend_score"]),
            -int(item["recent_count"]),
            str(item["category"]),
            str(item["signature"]),
        )
    )
    items = items[:bounded_top]

    return {
        "generated_at": now_utc.isoformat(timespec="seconds"),
        "days": bounded_days,
        "top": bounded_top,
        "recent_window": {
            "start": recent_start.isoformat(timespec="seconds"),
            "end": now_utc.isoformat(timespec="seconds"),
        },
        "baseline_window": {
            "start": baseline_start.isoformat(timespec="seconds"),
            "end": recent_start.isoformat(timespec="seconds"),
        },
        "items": items,
    }


def format_daily_report_text(report: dict[str, Any]) -> str:
    """Render daily regression report as text."""
    lines: list[str] = ["=== WICAP Daily Regression Report ===", ""]
    items = report.get("items", [])

    if not isinstance(items, list) or not items:
        lines.append("No upward trends found.")
        return "\n".join(lines)

    for item in items:
        if not isinstance(item, dict):
            continue
        lines.append(f"Signature: {item.get('signature')}")
        lines.append(f"Category: {item.get('category')}")
        lines.append(f"Recent: {item.get('recent_count')}")
        lines.append(f"Previous: {item.get('baseline_count')}")
        lines.append(f"Trend: +{item.get('trend_score')}")
        lines.append("")
        lines.append("Example file:")
        lines.append(str(item.get("example_file") or "(none)"))
        lines.append("")
        lines.append("Suggested Playbook:")
        lines.append(str(item.get("playbook") or "(none)"))
        lines.append("")
        lines.append("Matching Incident:")
        lines.append(str(item.get("incident") or "(none)"))
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def daily_report_to_json(report: dict[str, Any]) -> str:
    """Encode daily report as JSON."""
    return json.dumps(report, indent=2, sort_keys=True)
