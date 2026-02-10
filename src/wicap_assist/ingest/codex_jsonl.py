"""Codex JSONL scanner/parser for WICAP assistant."""

from __future__ import annotations

from dataclasses import dataclass, field
import glob
import json
from pathlib import Path
from typing import Any

from wicap_assist.extract.signals import Signal, extract_operational_signals, session_gate
from wicap_assist.util.time import to_iso

CODEX_ROOT = Path("/home/steve/.codex")
HISTORY_PATH = CODEX_ROOT / "history.jsonl"
SESSIONS_GLOB = str(CODEX_ROOT / "sessions" / "**" / "rollout-*.jsonl")
ARCHIVED_GLOB = str(CODEX_ROOT / "archived_sessions" / "rollout-*.jsonl")


@dataclass(slots=True)
class ParsedSession:
    """Canonical parsed session object for DB ingest."""

    session_id: str
    cwd: str | None
    ts_first: str | None
    ts_last: str | None
    repo_url: str | None
    branch: str | None
    commit_hash: str | None
    is_wicap: bool
    raw_path: str
    signals: list[Signal] = field(default_factory=list)


def source_kind_for(path: Path) -> str:
    """Return a coarse source kind label for a path."""
    if path.name == "history.jsonl":
        return "history"
    if "archived_sessions" in path.parts:
        return "archived_session"
    return "session"


def scan_codex_paths() -> list[Path]:
    """List configured Codex JSONL sources."""
    seen: set[str] = set()
    results: list[Path] = []

    if HISTORY_PATH.exists():
        seen.add(str(HISTORY_PATH))
        results.append(HISTORY_PATH)

    for pattern in (SESSIONS_GLOB, ARCHIVED_GLOB):
        for hit in sorted(glob.glob(pattern, recursive=True)):
            if hit in seen:
                continue
            seen.add(hit)
            results.append(Path(hit))

    return results


def _dedupe_signals(signals: list[Signal]) -> list[Signal]:
    deduped: list[Signal] = []
    seen: set[tuple[str, str]] = set()
    for signal in signals:
        key = (signal.category, signal.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)
    return deduped


def _parse_rollout(path: Path) -> list[ParsedSession]:
    session_id = path.stem
    cwd: str | None = None
    repo_url: str | None = None
    branch: str | None = None
    commit_hash: str | None = None
    has_wicap_text = False
    signals: list[Signal] = []
    timestamps: list[str] = []

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            payload = record.get("payload")
            payload_dict = payload if isinstance(payload, dict) else {}

            for candidate in (record.get("timestamp"), payload_dict.get("timestamp"), record.get("ts")):
                iso = to_iso(candidate)
                if iso:
                    timestamps.append(iso)

            record_type = record.get("type")
            if record_type == "session_meta":
                sid = payload_dict.get("id")
                if isinstance(sid, str) and sid.strip():
                    session_id = sid.strip()
                meta_cwd = payload_dict.get("cwd")
                if isinstance(meta_cwd, str) and meta_cwd.strip():
                    cwd = meta_cwd.strip()

                git_meta = payload_dict.get("git")
                if isinstance(git_meta, dict):
                    repo = git_meta.get("repository_url") or git_meta.get("repo_url")
                    if isinstance(repo, str) and repo.strip():
                        repo_url = repo.strip()
                    branch_name = git_meta.get("branch")
                    if isinstance(branch_name, str) and branch_name.strip():
                        branch = branch_name.strip()
                    commit = git_meta.get("commit_hash")
                    if isinstance(commit, str) and commit.strip():
                        commit_hash = commit.strip()
                continue

            if record_type != "response_item":
                continue

            content = payload_dict.get("content")
            if not isinstance(content, list):
                continue

            ts_for_signals = to_iso(record.get("timestamp"))
            for item in content:
                if not isinstance(item, dict):
                    continue
                text = item.get("text")
                if not isinstance(text, str):
                    continue
                if "wicap" in text.lower():
                    has_wicap_text = True
                signals.extend(extract_operational_signals(text, ts=ts_for_signals))

    signals = _dedupe_signals(signals)
    ts_first = min(timestamps) if timestamps else None
    ts_last = max(timestamps) if timestamps else None
    is_wicap = session_gate(cwd, repo_url, has_wicap_text, bool(signals))

    return [
        ParsedSession(
            session_id=session_id,
            cwd=cwd,
            ts_first=ts_first,
            ts_last=ts_last,
            repo_url=repo_url,
            branch=branch,
            commit_hash=commit_hash,
            is_wicap=is_wicap,
            raw_path=str(path),
            signals=signals,
        )
    ]


def _parse_history(path: Path) -> list[ParsedSession]:
    grouped: dict[str, dict[str, Any]] = {}

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            session_id = record.get("session_id")
            if not isinstance(session_id, str) or not session_id.strip():
                continue

            session_id = session_id.strip()
            bucket = grouped.setdefault(
                session_id,
                {
                    "timestamps": [],
                    "signals": [],
                    "has_wicap_text": False,
                },
            )

            ts = to_iso(record.get("ts"))
            if ts:
                bucket["timestamps"].append(ts)

            text = record.get("text")
            if isinstance(text, str):
                if "wicap" in text.lower():
                    bucket["has_wicap_text"] = True
                bucket["signals"].extend(extract_operational_signals(text, ts=ts))

    sessions: list[ParsedSession] = []
    for session_id, bucket in grouped.items():
        signals = _dedupe_signals(bucket["signals"])
        timestamps = bucket["timestamps"]
        ts_first = min(timestamps) if timestamps else None
        ts_last = max(timestamps) if timestamps else None
        is_wicap = session_gate(
            cwd=None,
            repo_url=None,
            has_wicap_text=bool(bucket["has_wicap_text"]),
            has_operational_signals=bool(signals),
        )

        sessions.append(
            ParsedSession(
                session_id=session_id,
                cwd=None,
                ts_first=ts_first,
                ts_last=ts_last,
                repo_url=None,
                branch=None,
                commit_hash=None,
                is_wicap=is_wicap,
                raw_path=str(path),
                signals=signals,
            )
        )

    sessions.sort(key=lambda value: (value.ts_last or "", value.session_id))
    return sessions


def parse_codex_file(path: Path) -> list[ParsedSession]:
    """Parse one configured source into zero or more logical sessions."""
    if path.name == "history.jsonl":
        return _parse_history(path)
    return _parse_rollout(path)
