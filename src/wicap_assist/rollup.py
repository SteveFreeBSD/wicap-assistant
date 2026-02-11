"""Cross-incident rollups for recurring failures."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from wicap_assist.git_context import (
    build_git_context,
    load_antigravity_git_evidence,
    load_codex_git_evidence,
    load_codex_git_evidence_fallback,
)
from wicap_assist.evidence_query import (
    query_related_session_ids,
    query_verification_track_record,
    signature_tokens,
    where_like,
)
from wicap_assist.incident import default_incidents_dir
from wicap_assist.playbooks import default_playbooks_dir
from wicap_assist.util.evidence import normalize_signature, parse_utc_datetime

_CATEGORIES = ("error", "docker_fail", "pytest_fail", "network_anomaly", "network_flow")
_INCIDENT_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-")
_INCIDENT_CAT_RE = re.compile(
    r"^###\s+(error|docker_fail|pytest_fail|network_anomaly|network_flow)\s*$",
    re.IGNORECASE,
)


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row["name"]) for row in rows}


def _parse_event_ts(ts_text: object, source_mtime: object) -> datetime | None:
    parsed = parse_utc_datetime(ts_text)
    if parsed is not None:
        return parsed

    try:
        return datetime.fromtimestamp(float(source_mtime), tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def _load_playbook_map(playbooks_dir: Path) -> dict[tuple[str, str], str]:
    mapping: dict[tuple[str, str], str] = {}
    if not playbooks_dir.exists():
        return mapping

    for path in sorted(playbooks_dir.glob("*.md")):
        if path.name.upper() == "INDEX.MD":
            continue
        category: str | None = None
        signature: str | None = None
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("- Category: "):
                category = line[len("- Category: ") :].strip()
            elif line.startswith("- Signature: "):
                signature = line[len("- Signature: ") :].strip()
            if category and signature:
                mapping[(category, signature)] = path.name
                break
    return mapping


def _load_incident_signatures_from_db(
    conn: sqlite3.Connection,
    *,
    start: datetime,
    end: datetime,
) -> set[tuple[str, str]]:
    if not _table_exists(conn, "incidents"):
        return set()

    columns = _table_columns(conn, "incidents")
    if not {"category", "signature"}.issubset(columns):
        return set()

    ts_col = next((name for name in ("generated_ts", "created_ts", "ts") if name in columns), None)
    if ts_col is None:
        rows = conn.execute("SELECT category, signature FROM incidents").fetchall()
    else:
        rows = conn.execute(f"SELECT category, signature, {ts_col} AS ts FROM incidents").fetchall()

    signatures: set[tuple[str, str]] = set()
    for row in rows:
        category = str(row["category"]).strip().lower()
        signature_raw = str(row["signature"]).strip()
        if category not in _CATEGORIES or not signature_raw:
            continue
        if ts_col is not None:
            dt = parse_utc_datetime(row["ts"])
            if dt is None or dt < start or dt > end:
                continue
        signatures.add((category, normalize_signature(signature_raw)))
    return signatures


def _load_incident_signatures_from_markdown(
    incidents_dir: Path,
    *,
    start: datetime,
    end: datetime,
) -> set[tuple[str, str]]:
    signatures: set[tuple[str, str]] = set()
    if not incidents_dir.exists():
        return signatures

    for path in sorted(incidents_dir.glob("*.md")):
        if path.name.upper() == "INDEX.MD":
            continue

        file_dt: datetime | None = None
        date_match = _INCIDENT_DATE_RE.match(path.name)
        if date_match:
            try:
                file_dt = datetime.strptime(date_match.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                file_dt = None
        if file_dt is None:
            file_dt = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if file_dt < start or file_dt > end:
            continue

        current_category: str | None = None
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            cat_match = _INCIDENT_CAT_RE.match(line)
            if cat_match:
                current_category = cat_match.group(1).lower()
                continue
            if current_category and line.startswith("- Example snippet:"):
                snippet = line.split(":", 1)[1].strip() if ":" in line else ""
                if snippet and snippet != "(none)":
                    signatures.add((current_category, normalize_signature(snippet)))
                current_category = None

    return signatures


def _related_session_ids(conn: sqlite3.Connection, signature: str) -> list[str]:
    return query_related_session_ids(conn, signature, limit=50)


def _related_conversation_ids(conn: sqlite3.Connection, signature: str) -> list[str]:
    if not _table_exists(conn, "conversation_signals") or not _table_exists(conn, "conversations"):
        return []
    tokens = signature_tokens(signature, limit=8)
    where, args = where_like("cs.snippet", tokens)
    if not where:
        return []
    rows = conn.execute(
        f"""
        SELECT DISTINCT c.conversation_id
        FROM conversation_signals AS cs
        JOIN conversations AS c ON c.id = cs.conversation_pk
        WHERE {where}
        ORDER BY c.conversation_id ASC
        LIMIT 50
        """,
        args,
    ).fetchall()
    return [str(row["conversation_id"]) for row in rows if str(row["conversation_id"]).strip()]


def _build_item_git_context(
    conn: sqlite3.Connection,
    *,
    signature: str,
    reference_ts: datetime | None,
) -> dict[str, Any]:
    session_ids = _related_session_ids(conn, signature)
    codex = load_codex_git_evidence(conn, session_ids)
    fallback = load_codex_git_evidence_fallback(
        conn,
        reference_ts=reference_ts,
        window_days=7,
        exclude_session_ids=[str(item.get("source_id", "")) for item in codex],
    )

    conversation_ids = _related_conversation_ids(conn, signature)
    antigravity = load_antigravity_git_evidence(conn, conversation_ids)
    return build_git_context([*codex, *fallback, *antigravity])


def _build_verification_track_record(
    conn: sqlite3.Connection,
    signature: str,
) -> dict[str, Any] | None:
    """Build verification outcome summary for a rollup signature."""
    if not _table_exists(conn, "verification_outcomes"):
        return None
    return query_verification_track_record(conn, signature)


def generate_rollup(
    conn: sqlite3.Connection,
    *,
    days: int = 30,
    top: int = 10,
    now: datetime | None = None,
    incidents_dir: Path | None = None,
    playbooks_dir: Path | None = None,
) -> dict[str, Any]:
    """Generate cross-incident rollup data."""
    resolved_incidents_dir = incidents_dir or default_incidents_dir()
    resolved_playbooks_dir = playbooks_dir or default_playbooks_dir()
    bounded_days = max(1, int(days))
    bounded_top = max(1, int(top))
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    window_start = now_utc - timedelta(days=bounded_days)

    incident_signatures = _load_incident_signatures_from_db(conn, start=window_start, end=now_utc)
    if not incident_signatures:
        incident_signatures = _load_incident_signatures_from_markdown(
            resolved_incidents_dir,
            start=window_start,
            end=now_utc,
        )

    placeholders = ", ".join("?" for _ in _CATEGORIES)
    rows = conn.execute(
        f"""
        SELECT le.category, le.snippet, le.ts_text, s.mtime
        FROM log_events AS le
        JOIN sources AS s ON s.id = le.source_id
        WHERE le.category IN ({placeholders})
        """,
        tuple(_CATEGORIES),
    ).fetchall()

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        category = str(row["category"])
        signature = normalize_signature(str(row["snippet"]))
        key = (category, signature)

        event_dt = _parse_event_ts(row["ts_text"], row["mtime"])
        if event_dt is None:
            continue
        if event_dt < window_start or event_dt > now_utc:
            continue

        if incident_signatures and key not in incident_signatures:
            continue

        bucket = grouped.setdefault(
            key,
            {
                "category": category,
                "signature": signature,
                "occurrence_count": 0,
                "first_seen_dt": event_dt,
                "last_seen_dt": event_dt,
            },
        )
        bucket["occurrence_count"] += 1
        if event_dt < bucket["first_seen_dt"]:
            bucket["first_seen_dt"] = event_dt
        if event_dt > bucket["last_seen_dt"]:
            bucket["last_seen_dt"] = event_dt

    playbook_map = _load_playbook_map(resolved_playbooks_dir)

    items: list[dict[str, Any]] = []
    for bucket in grouped.values():
        first_dt = bucket["first_seen_dt"]
        last_dt = bucket["last_seen_dt"]
        span_days = 0.0
        if isinstance(first_dt, datetime) and isinstance(last_dt, datetime):
            span_days = round(max(0.0, (last_dt - first_dt).total_seconds() / 86400.0), 1)

        category = str(bucket["category"])
        signature = str(bucket["signature"])
        git_context = _build_item_git_context(
            conn,
            signature=signature,
            reference_ts=last_dt if isinstance(last_dt, datetime) else now_utc,
        )

        track_record = _build_verification_track_record(conn, signature)

        items.append(
            {
                "category": category,
                "signature": signature,
                "occurrence_count": int(bucket["occurrence_count"]),
                "first_seen": first_dt.isoformat(timespec="seconds") if isinstance(first_dt, datetime) else None,
                "last_seen": last_dt.isoformat(timespec="seconds") if isinstance(last_dt, datetime) else None,
                "span_days": span_days,
                "playbook": {"path": playbook_map.get((category, signature))},
                "git_context": git_context,
                "verification_track_record": track_record,
            }
        )

    items.sort(
        key=lambda item: (
            -int(item["occurrence_count"]),
            -float(item["span_days"]),
            str(item["category"]),
            str(item["signature"]),
        )
    )
    items = items[:bounded_top]

    return {
        "window": {
            "days": bounded_days,
            "start": window_start.isoformat(timespec="seconds"),
            "end": now_utc.isoformat(timespec="seconds"),
        },
        "items": items,
    }


def format_rollup_text(report: dict[str, Any]) -> str:
    """Render human-readable rollup output."""
    window = report.get("window", {})
    items = report.get("items", [])
    if not isinstance(window, dict):
        window = {}
    if not isinstance(items, list):
        items = []

    lines: list[str] = ["=== WICAP Cross-Incident Rollup ==="]
    lines.append(f"Window: {window.get('start')} -> {window.get('end')} (days={window.get('days')})")

    if not items:
        lines.append("")
        lines.append("(no matching recurring signatures in window)")
        return "\n".join(lines)

    for idx, item in enumerate(items, start=1):
        git = item.get("git_context", {})
        if not isinstance(git, dict):
            git = {}
        branches = git.get("unique_branches", [])
        branch_summary = "(none)"
        if isinstance(branches, list) and branches:
            parts: list[str] = []
            for entry in branches[:3]:
                if not isinstance(entry, dict):
                    continue
                parts.append(f"{entry.get('branch')}({entry.get('count')})")
            if parts:
                branch_summary = ", ".join(parts)

        vtr = item.get("verification_track_record")
        vtr_line = "(no verification data)"
        relapse_tag = ""
        if isinstance(vtr, dict):
            vtr_line = f"pass={vtr.get('passes', 0)} fail={vtr.get('fails', 0)} unknown={vtr.get('unknowns', 0)} net={vtr.get('net_confidence_effect', 0)}"
            if vtr.get("relapse_detected"):
                relapse_tag = " ⚠ RELAPSE RISK"

        lines.extend(
            [
                "",
                f"{idx}. category={item.get('category')}",
                f"   signature={item.get('signature')}",
                f"   total_occurrences={item.get('occurrence_count')}",
                f"   first_seen={item.get('first_seen')}",
                f"   last_seen={item.get('last_seen')}",
                f"   span_days={item.get('span_days')}",
                f"   linked_playbook={((item.get('playbook') or {}).get('path') if isinstance(item.get('playbook'), dict) else None)}",
                f"   verification={vtr_line}{relapse_tag}",
                f"   git.most_common_commit_hash={git.get('most_common_commit_hash')}",
                f"   git.commit_spread={git.get('commit_spread')}",
                f"   git.top_branches={branch_summary}",
            ]
        )
    return "\n".join(lines)


def rollup_to_json(report: dict[str, Any]) -> str:
    """Encode rollup payload as JSON."""
    return json.dumps(report, indent=2, sort_keys=False)
