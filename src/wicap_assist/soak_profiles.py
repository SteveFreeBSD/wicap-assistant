"""Deterministic soak-run profile learning from historical session evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import sqlite3
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.recommend_confidence import normalize_verification_step

_PREFERRED = "tests/soak_test.py"
_FALLBACK = "scripts/run_live_soak.py"
_PASS_RE = re.compile(r"\b(?:fixed|resolved|success|passed|works now|verified)\b", re.IGNORECASE)
_FAIL_RE = re.compile(r"\b(?:failed|still broken|didn't work|did not work|error:)\b", re.IGNORECASE)
_SOAK_CMD_RE = re.compile(
    r"(?:soak_test\.py|run_live_soak\.py|soak_preflight\.py|start_wicap\.py|stop_wicap\.py|"
    r"docker\s+compose\s+up|check_wicap_status\.py|playwright|wicap-assist\s+soak-run)",
    re.IGNORECASE,
)
_RUNBOOK_EXCLUDE_RE = re.compile(
    r"(?:docker\s+compose\s+down|stop_wicap\.py|\brm\b)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class SoakProfile:
    runner_path: str | None
    duration_minutes: int | None
    playwright_interval_minutes: int | None
    baseline_path: str | None
    baseline_update: bool | None
    score: int
    evidence_count: int
    success_count: int
    fail_count: int
    session_ids: list[str]


@dataclass(slots=True)
class SoakRunbook:
    steps: list[str]
    session_ids: list[str]
    success_session_count: int


def _normalize_command(snippet: str) -> str:
    value = snippet.strip()
    if value.startswith("$"):
        value = value[1:].strip()
    value = re.sub(r"^\s*[-*]\s*", "", value).strip()
    return normalize_verification_step(value)


def _extract_flag_value(tokens: list[str], flag: str) -> str | None:
    for idx, token in enumerate(tokens):
        if token == flag and idx + 1 < len(tokens):
            return tokens[idx + 1]
        if token.startswith(flag + "="):
            return token.split("=", 1)[1]
    return None


def _extract_bool_flag(tokens: list[str], flag: str) -> bool | None:
    positive = any(token == flag for token in tokens)
    negative = any(token == flag.replace("--", "--no-") for token in tokens)
    if positive and not negative:
        return True
    if negative and not positive:
        return False
    return None


def parse_soak_command_profile(command: str, *, repo_root: Path | None = None) -> dict[str, Any] | None:
    """Parse soak runner profile hints from one command line."""
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    raw = command.strip()
    if not raw:
        return None
    if raw.startswith("$"):
        raw = raw[1:].strip()

    try:
        tokens = shlex.split(raw)
    except ValueError:
        return None
    if not tokens:
        return None

    joined = " ".join(tokens)
    has_soak_target = (
        _PREFERRED in joined
        or _FALLBACK in joined
        or (len(tokens) >= 2 and tokens[0] == "wicap-assist" and tokens[1] == "soak-run")
    )
    if not has_soak_target:
        return None

    preferred_abs = str(resolved_repo_root / _PREFERRED)
    fallback_abs = str(resolved_repo_root / _FALLBACK)
    runner_path: str | None = None
    if _PREFERRED in joined:
        runner_path = preferred_abs
    elif _FALLBACK in joined:
        runner_path = fallback_abs
    elif len(tokens) >= 2 and tokens[0] == "wicap-assist" and tokens[1] == "soak-run":
        # Canonical CLI wrapper defaults to preferred harness when available.
        runner_path = preferred_abs

    duration_raw = _extract_flag_value(tokens, "--duration-minutes")
    interval_raw = _extract_flag_value(tokens, "--playwright-interval-minutes")
    baseline_path = _extract_flag_value(tokens, "--baseline-path")
    baseline_update = _extract_bool_flag(tokens, "--baseline-update")

    duration_minutes: int | None = None
    if duration_raw is not None:
        try:
            duration_minutes = int(duration_raw)
        except ValueError:
            duration_minutes = None

    playwright_interval_minutes: int | None = None
    if interval_raw is not None:
        try:
            playwright_interval_minutes = int(interval_raw)
        except ValueError:
            playwright_interval_minutes = None

    return {
        "runner_path": runner_path,
        "duration_minutes": duration_minutes,
        "playwright_interval_minutes": playwright_interval_minutes,
        "baseline_path": baseline_path,
        "baseline_update": baseline_update,
    }


def learn_soak_runbook(conn: sqlite3.Connection, *, max_steps: int = 8) -> SoakRunbook:
    """Learn a deterministic soak startup runbook from successful historical sessions."""
    rows = conn.execute(
        """
        SELECT s.session_id, s.ts_last, sg.category, sg.snippet
        FROM sessions AS s
        JOIN signals AS sg ON s.id = sg.session_pk
        WHERE s.is_wicap = 1
          AND sg.category IN ('commands', 'command', 'outcomes')
        ORDER BY coalesce(s.ts_last, '') DESC, sg.id DESC
        """
    ).fetchall()

    sessions: dict[str, dict[str, Any]] = {}
    for row in rows:
        session_id = str(row["session_id"]).strip()
        if not session_id:
            continue
        bucket = sessions.setdefault(
            session_id,
            {
                "commands": [],
                "outcomes": [],
            },
        )
        category = str(row["category"])
        snippet = str(row["snippet"])
        if category in {"commands", "command"}:
            bucket["commands"].append(snippet)
        elif category == "outcomes":
            bucket["outcomes"].append(snippet)

    command_sessions: dict[str, set[str]] = {}
    successful_sessions: set[str] = set()
    for session_id, data in sessions.items():
        outcomes = data.get("outcomes", [])
        if not isinstance(outcomes, list):
            outcomes = []
        has_pass = any(_PASS_RE.search(str(value)) for value in outcomes)
        if not has_pass:
            continue
        successful_sessions.add(session_id)

        commands = data.get("commands", [])
        if not isinstance(commands, list):
            continue
        for raw in commands:
            command = _normalize_command(str(raw))
            if not command:
                continue
            if not _SOAK_CMD_RE.search(command):
                continue
            if _RUNBOOK_EXCLUDE_RE.search(command):
                continue
            cmd_bucket = command_sessions.setdefault(command, set())
            cmd_bucket.add(session_id)

    ranked = sorted(
        command_sessions.items(),
        key=lambda item: (-len(item[1]), item[0]),
    )
    steps = [command for command, _ in ranked[: max(1, int(max_steps))]]
    return SoakRunbook(
        steps=steps,
        session_ids=sorted(successful_sessions),
        success_session_count=len(successful_sessions),
    )


def select_learned_soak_profile(conn: sqlite3.Connection, *, repo_root: Path | None = None) -> SoakProfile | None:
    """Select highest-confidence soak profile from historical session commands/outcomes."""
    resolved_repo_root = repo_root or wicap_repo_root()
    rows = conn.execute(
        """
        SELECT s.session_id, s.ts_last, sg.category, sg.snippet
        FROM sessions AS s
        JOIN signals AS sg ON s.id = sg.session_pk
        WHERE s.is_wicap = 1
          AND sg.category IN ('commands', 'command', 'outcomes')
        ORDER BY coalesce(s.ts_last, '') DESC, sg.id DESC
        """
    ).fetchall()

    sessions: dict[str, dict[str, Any]] = {}
    for row in rows:
        session_id = str(row["session_id"]).strip()
        if not session_id:
            continue
        bucket = sessions.setdefault(
            session_id,
            {
                "ts_last": str(row["ts_last"] or ""),
                "commands": [],
                "outcomes": [],
            },
        )
        category = str(row["category"])
        snippet = str(row["snippet"])
        if category in {"commands", "command"}:
            bucket["commands"].append(snippet)
        elif category == "outcomes":
            bucket["outcomes"].append(snippet)

    profile_stats: dict[tuple[Any, ...], dict[str, Any]] = {}

    for session_id, data in sessions.items():
        commands = data.get("commands", [])
        if not isinstance(commands, list):
            continue

        parsed_profiles = []
        for command in commands:
            profile = parse_soak_command_profile(str(command), repo_root=resolved_repo_root)
            if profile is not None:
                parsed_profiles.append(profile)
        if not parsed_profiles:
            continue

        outcomes = data.get("outcomes", [])
        if not isinstance(outcomes, list):
            outcomes = []

        has_pass = any(_PASS_RE.search(str(value)) for value in outcomes)
        has_fail = any(_FAIL_RE.search(str(value)) for value in outcomes)

        for profile in parsed_profiles:
            key = (
                profile.get("runner_path"),
                profile.get("duration_minutes"),
                profile.get("playwright_interval_minutes"),
                profile.get("baseline_path"),
                profile.get("baseline_update"),
            )
            stat = profile_stats.setdefault(
                key,
                {
                    "score": 0,
                    "evidence_count": 0,
                    "success_count": 0,
                    "fail_count": 0,
                    "latest_ts": "",
                    "session_ids": set(),
                },
            )

            stat["score"] += 1
            stat["evidence_count"] += 1
            if has_pass:
                stat["score"] += 2
                stat["success_count"] += 1
            if has_fail and not has_pass:
                stat["score"] -= 2
                stat["fail_count"] += 1

            ts_last = str(data.get("ts_last") or "")
            if ts_last > str(stat["latest_ts"]):
                stat["latest_ts"] = ts_last

            stat["session_ids"].add(session_id)

    if not profile_stats:
        return None

    ranked = sorted(
        profile_stats.items(),
        key=lambda item: (
            int(item[1]["score"]),
            int(item[1]["success_count"]),
            int(item[1]["evidence_count"]),
            str(item[1]["latest_ts"]),
            str(item[0]),
        ),
        reverse=True,
    )

    key, stat = ranked[0]
    runner_path, duration_minutes, interval_minutes, baseline_path, baseline_update = key

    return SoakProfile(
        runner_path=str(runner_path) if isinstance(runner_path, str) and runner_path else None,
        duration_minutes=int(duration_minutes) if isinstance(duration_minutes, int) else None,
        playwright_interval_minutes=int(interval_minutes) if isinstance(interval_minutes, int) else None,
        baseline_path=str(baseline_path) if isinstance(baseline_path, str) and baseline_path else None,
        baseline_update=bool(baseline_update) if isinstance(baseline_update, bool) else None,
        score=int(stat["score"]),
        evidence_count=int(stat["evidence_count"]),
        success_count=int(stat["success_count"]),
        fail_count=int(stat["fail_count"]),
        session_ids=sorted(str(value) for value in stat["session_ids"]),
    )
