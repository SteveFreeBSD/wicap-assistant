"""Live soak guardian monitoring mode."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import glob
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any

from wicap_assist.harness_match import find_relevant_harness_scripts
from wicap_assist.ingest.soak_logs import _categories_for_line
from wicap_assist.evidence_query import (
    query_recent_related_session,
    query_verification_track_record,
)
from wicap_assist.playbooks import default_playbooks_dir
from wicap_assist.config import wicap_repo_root
from wicap_assist.util.evidence import normalize_signature
from wicap_assist.util.redact import to_snippet

_ALERT_CATEGORIES = {"error", "docker_fail", "pytest_fail"}


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


@dataclass(slots=True)
class PlaybookEntry:
    category: str
    signature: str
    filename: str
    first_fix_step: str


@dataclass(slots=True)
class GuardianAlert:
    signature: str
    category: str
    playbook: str
    recent_session_id: str | None
    recent_session_ts: str | None
    first_step: str
    harness_script: str | None
    harness_role: str | None
    file_path: str
    line: str
    past_fix_passes: int = 0
    past_fix_fails: int = 0
    relapse_risk: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "category": self.category,
            "playbook": self.playbook,
            "recent_session": {
                "session_id": self.recent_session_id,
                "ts_last": self.recent_session_ts,
            },
            "first_step": self.first_step,
            "harness_suggestion": {
                "script_path": self.harness_script,
                "role": self.harness_role,
            },
            "past_fix_track_record": {
                "passes": self.past_fix_passes,
                "fails": self.past_fix_fails,
                "relapse_risk": self.relapse_risk,
            },
            "file": self.file_path,
            "line": self.line,
        }


@dataclass(slots=True)
class GuardianState:
    offsets: dict[str, int] = field(default_factory=dict)
    last_alert_at: dict[tuple[str, str], datetime] = field(default_factory=dict)


def _has_wildcards(value: str) -> bool:
    return any(char in value for char in "*?[]")


def default_path_specs(*, repo_root: Path | None = None) -> tuple[str, ...]:
    resolved_root = (repo_root or wicap_repo_root()).resolve()
    return (
        str(resolved_root / "logs_soak_*/*.log"),
        str(resolved_root / "logs_soak_*/*/*.log"),
        str(resolved_root / "logs_verification_*/*.log"),
        str(resolved_root / "logs_verification_*/*/*.log"),
        str(resolved_root / "soak_test_*.log"),
        str(resolved_root / "wicap.log"),
        str(resolved_root / "wicap_verified.log"),
        str(resolved_root / "wicap-ui/ui.log"),
    )


def _expand_path_spec(spec: str) -> list[Path]:
    if _has_wildcards(spec):
        hits = [Path(hit) for hit in sorted(glob.glob(spec, recursive=True))]
    else:
        path = Path(spec)
        if path.is_file():
            hits = [path]
        elif path.is_dir():
            hits = sorted(path.rglob("*.log"))
        else:
            hits = [Path(hit) for hit in sorted(glob.glob(spec, recursive=True))]

    out: list[Path] = []
    for hit in hits:
        if hit.is_file():
            out.append(hit)
        elif hit.is_dir():
            out.extend(sorted(hit.rglob("*.log")))
    return out


def resolve_monitor_files(path_specs: list[str] | None, *, repo_root: Path | None = None) -> list[Path]:
    """Resolve monitored files from explicit path specs or defaults."""
    specs = path_specs if path_specs else list(default_path_specs(repo_root=repo_root))
    seen: set[str] = set()
    files: list[Path] = []
    for spec in specs:
        for path in _expand_path_spec(spec):
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            files.append(path)
    files.sort(key=lambda item: str(item))
    return files


def load_playbook_entries(playbooks_dir: Path | None = None) -> dict[tuple[str, str], PlaybookEntry]:
    """Load playbook category/signature and first fix step for matching."""
    resolved_playbooks_dir = (playbooks_dir or default_playbooks_dir()).resolve()
    entries: dict[tuple[str, str], PlaybookEntry] = {}
    if not resolved_playbooks_dir.exists():
        return entries

    for path in sorted(resolved_playbooks_dir.glob("*.md")):
        if path.name.upper() == "INDEX.MD":
            continue

        category: str | None = None
        signature: str | None = None
        first_fix_step: str | None = None
        in_fix_steps = False

        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if line.startswith("- Category: "):
                category = line[len("- Category: ") :].strip()
                continue
            if line.startswith("- Signature: "):
                signature = line[len("- Signature: ") :].strip()
                continue
            if line == "## Fix steps":
                in_fix_steps = True
                continue
            if in_fix_steps and re.match(r"^\d+\.\s+", line):
                first_fix_step = re.sub(r"^\d+\.\s+", "", line).strip()
                break
            if in_fix_steps and line.startswith("## "):
                break

        if not category or not signature:
            continue

        entries[(category, signature)] = PlaybookEntry(
            category=category,
            signature=signature,
            filename=path.name,
            first_fix_step=first_fix_step or "(none)",
        )
    return entries


def _recent_related_session(
    conn: sqlite3.Connection,
    *,
    signature: str,
) -> tuple[str | None, str | None]:
    return query_recent_related_session(conn, signature)


def _query_verification_track_record(
    conn: sqlite3.Connection,
    signature: str,
) -> tuple[int, int, bool]:
    """Return (passes, fails, relapse_risk) for a signature."""
    if not _table_exists(conn, "verification_outcomes"):
        return 0, 0, False
    record = query_verification_track_record(conn, signature)
    if record is None:
        return 0, 0, False
    return (
        int(record.get("passes", 0)),
        int(record.get("fails", 0)),
        bool(record.get("relapse_detected", False)),
    )


def _read_new_lines(
    path: Path,
    state: GuardianState,
    *,
    start_at_end_for_new: bool,
) -> list[str]:
    key = str(path)
    size = path.stat().st_size

    if key not in state.offsets:
        state.offsets[key] = size if start_at_end_for_new else 0

    offset = state.offsets[key]
    if size < offset:
        offset = 0

    with path.open("rb") as handle:
        handle.seek(offset)
        chunk = handle.read()
        state.offsets[key] = handle.tell()

    if not chunk:
        return []

    text = chunk.decode("utf-8", errors="replace")
    return [line.rstrip("\r") for line in text.splitlines() if line.strip()]


def scan_guardian_once(
    conn: sqlite3.Connection,
    *,
    state: GuardianState,
    path_specs: list[str] | None = None,
    playbooks: dict[tuple[str, str], PlaybookEntry] | None = None,
    now: datetime | None = None,
    dedupe_window: timedelta = timedelta(minutes=10),
    start_at_end_for_new: bool = False,
) -> list[GuardianAlert]:
    """Scan currently available log files once and emit matched alerts."""
    files = resolve_monitor_files(path_specs)
    playbook_map = playbooks if playbooks is not None else load_playbook_entries()
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    alerts: list[GuardianAlert] = []
    for path in files:
        if not path.exists() or not path.is_file():
            continue

        for line in _read_new_lines(path, state, start_at_end_for_new=start_at_end_for_new):
            snippet = to_snippet(line, max_len=200)
            categories = _categories_for_line(line, path)
            if not categories:
                continue

            for category in categories:
                if category not in _ALERT_CATEGORIES:
                    continue

                signature = normalize_signature(snippet)
                match = playbook_map.get((category, signature))
                if match is None:
                    continue

                dedupe_key = (category, signature)
                last_seen = state.last_alert_at.get(dedupe_key)
                if last_seen is not None and (now_utc - last_seen) < dedupe_window:
                    continue
                state.last_alert_at[dedupe_key] = now_utc

                session_id, session_ts = _recent_related_session(
                    conn,
                    signature=signature,
                )
                harness = find_relevant_harness_scripts(
                    conn,
                    category=category,
                    signature=signature,
                    fix_steps=[match.first_fix_step] if match.first_fix_step else [],
                    context_texts=[snippet],
                    top_n=1,
                )
                harness_script = None
                harness_role = None
                if harness:
                    harness_script = str(harness[0].get("script_path") or "")
                    harness_role = str(harness[0].get("role") or "")
                    if not harness_script:
                        harness_script = None
                    if not harness_role:
                        harness_role = None
                vtr_passes, vtr_fails, vtr_relapse = _query_verification_track_record(
                    conn, signature
                )
                alerts.append(
                    GuardianAlert(
                        signature=signature,
                        category=category,
                        playbook=match.filename,
                        recent_session_id=session_id,
                        recent_session_ts=session_ts,
                        first_step=match.first_fix_step,
                        harness_script=harness_script,
                        harness_role=harness_role,
                        file_path=str(path),
                        line=snippet,
                        past_fix_passes=vtr_passes,
                        past_fix_fails=vtr_fails,
                        relapse_risk=vtr_relapse,
                    )
                )
    return alerts


def format_guardian_alert_text(alert: GuardianAlert) -> str:
    """Render one guardian alert block."""
    session = "(none)"
    if alert.recent_session_id:
        ts = alert.recent_session_ts or "unknown-ts"
        session = f"{alert.recent_session_id} {ts}"

    harness = "(none)"
    if alert.harness_script:
        role = alert.harness_role or "unknown"
        harness = f"{alert.harness_script} ({role})"

    vtr_line = "(no verification data)"
    relapse_tag = ""
    if alert.past_fix_passes > 0 or alert.past_fix_fails > 0:
        vtr_line = f"pass={alert.past_fix_passes} fail={alert.past_fix_fails}"
        if alert.relapse_risk:
            relapse_tag = " \u26a0 RELAPSE RISK"

    return "\n".join(
        [
            "=== WICAP Guardian Alert ===",
            f"Signature: {alert.signature}",
            f"Category: {alert.category}",
            "Matched Playbook:",
            alert.playbook,
            "",
            "Recent Related Session:",
            session,
            "",
            "Suggested First Step:",
            alert.first_step,
            "",
            "Harness Suggestion:",
            harness,
            "",
            f"Past Fix Track Record: {vtr_line}{relapse_tag}",
            "",
            "File:",
            alert.file_path,
            "",
            "Line:",
            alert.line,
            "",
            "--------------------------------",
        ]
    )


def guardian_alerts_to_json(alerts: list[GuardianAlert]) -> str:
    """Encode guardian alerts as JSON."""
    return json.dumps([alert.to_dict() for alert in alerts], indent=2, sort_keys=True)


def run_guardian(
    conn: sqlite3.Connection,
    *,
    path_specs: list[str] | None = None,
    interval: float = 10.0,
    once: bool = False,
    as_json: bool = False,
) -> list[GuardianAlert]:
    """Run guardian monitoring loop. Returns alerts for --once."""
    state = GuardianState()
    playbooks = load_playbook_entries()

    if once:
        alerts = scan_guardian_once(
            conn,
            state=state,
            path_specs=path_specs,
            playbooks=playbooks,
            start_at_end_for_new=False,
        )
        if as_json:
            print(guardian_alerts_to_json(alerts))
        else:
            for alert in alerts:
                print(format_guardian_alert_text(alert))
        return alerts

    while True:
        alerts = scan_guardian_once(
            conn,
            state=state,
            path_specs=path_specs,
            playbooks=playbooks,
            start_at_end_for_new=True,
        )
        if alerts:
            if as_json:
                for alert in alerts:
                    print(json.dumps(alert.to_dict(), sort_keys=True))
            else:
                for alert in alerts:
                    print(format_guardian_alert_text(alert))
        time.sleep(max(0.1, float(interval)))
