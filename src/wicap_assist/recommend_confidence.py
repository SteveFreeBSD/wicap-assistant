"""Phase 4 confidence calibration and verification ranking helpers."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
import re
import sqlite3
from typing import Any

from wicap_assist.db import query_outcomes_for_signature
from wicap_assist.harness_match import normalize_command
from wicap_assist.util.evidence import normalize_signature, parse_utc_datetime

_FIX_RE = re.compile(r"\b(?:fixed|resolved)\b", re.IGNORECASE)
_SUCCESS_RE = re.compile(r"\b(?:fixed|resolved|success|passed|works now|verified)\b", re.IGNORECASE)
_VERIFY_CMD_RE = re.compile(r"(?:check|status|verify|pytest|health|smoke|test|logs?|journalctl|monitor)", re.IGNORECASE)
_TRAILING_FP_RE = re.compile(r"(?:\s*\[[0-9a-f]{8,40}\])+\s*$", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")
_DESTRUCTIVE_RE = re.compile(r"(?:\brm\b|\bwipe\b|\bmkfs(?:\.\w+)?\b|\bdd\b|\btruncate\b|\bchmod\s+-R\b|\bchown\s+-R\b)", re.IGNORECASE)
_CAUTION_RE = re.compile(
    r"(?:\bsystemctl\s+restart\b|\bdocker\s+compose\s+down\b|\bip\s+link\s+set\s+down\b|\bairmon-ng\s+check\s+kill\b)",
    re.IGNORECASE,
)
_SAFE_RE = re.compile(r"(?:check_wicap_status|docker\s+ps|docker\s+logs|journalctl|\brg\b|\bls\b|\bcat\b)", re.IGNORECASE)


@dataclass(slots=True)
class Phase4Result:
    confidence_breakdown: dict[str, int]
    confidence: float
    verification_priority: list[str]


@dataclass(slots=True)
class VerificationOutcomeEffect:
    score: int
    pass_count: int
    fail_count: int
    unknown_count: int


def normalize_verification_step(step: str) -> str:
    """Normalize verification command text and strip trailing fingerprint tags."""
    value = normalize_command(step)
    value = _TRAILING_FP_RE.sub("", value).strip()
    value = _WS_RE.sub(" ", value).strip()
    return value


def classify_verification_step(step: str) -> str:
    """Classify verification command safety as safe/caution/destructive."""
    value = normalize_verification_step(step)
    if not value:
        return "caution"

    if _DESTRUCTIVE_RE.search(value):
        return "destructive"
    if _CAUTION_RE.search(value):
        return "caution"
    if _SAFE_RE.search(value):
        return "safe"
    return "caution"


def _compute_fix_success_count(fix_outcomes: list[tuple[datetime | None, str, str]]) -> int:
    if not fix_outcomes:
        return 0

    buckets: dict[str, set[str]] = defaultdict(set)
    for _, session_id, snippet in fix_outcomes:
        buckets[normalize_signature(snippet)].add(session_id)

    if not buckets:
        return 0
    return max(len(session_ids) for session_ids in buckets.values())


def _compute_recurrence_penalty(
    *,
    event_times: list[datetime],
    fix_outcomes: list[tuple[datetime | None, str, str]],
) -> int:
    if not event_times:
        return 0

    fix_times = [ts for ts, _, _ in fix_outcomes if ts is not None]
    if fix_times:
        latest_fix = max(fix_times)
        recurrence_count = sum(1 for event_ts in event_times if event_ts > latest_fix)
        return min(5, recurrence_count)

    # No known fix timestamp: repeated events still indicate recurrence.
    repeated_count = max(0, len(event_times) - 1)
    return min(5, repeated_count)


def _verification_signal_stats(rows: list[Any]) -> tuple[Counter[str], Counter[str], int]:
    session_commands: dict[str, list[tuple[str, datetime | None]]] = defaultdict(list)
    session_success_outcomes: dict[str, list[datetime | None]] = defaultdict(list)
    session_fix_outcomes: dict[str, list[datetime | None]] = defaultdict(list)

    for row in rows:
        session_id = str(row["session_id"])
        category = str(row["category"])
        snippet = str(row["snippet"]).strip()
        ts = parse_utc_datetime(row["ts"]) or parse_utc_datetime(row["ts_last"])

        if not snippet:
            continue

        if category == "commands":
            command = normalize_verification_step(snippet)
            if command and _VERIFY_CMD_RE.search(command):
                session_commands[session_id].append((command, ts))
            continue

        if category != "outcomes":
            continue

        if _SUCCESS_RE.search(snippet):
            session_success_outcomes[session_id].append(ts)
        if _FIX_RE.search(snippet):
            session_fix_outcomes[session_id].append(ts)

    success_counts: Counter[str] = Counter()
    follow_fix_counts: Counter[str] = Counter()
    verification_success_score = 0

    for session_id, commands in session_commands.items():
        success_times = session_success_outcomes.get(session_id, [])
        if not success_times:
            continue

        fix_times = [value for value in session_fix_outcomes.get(session_id, []) if value is not None]
        latest_fix = max(fix_times) if fix_times else None
        session_has_success = False

        for command, command_ts in commands:
            success_after_command = False
            for success_ts in success_times:
                if command_ts is None or success_ts is None:
                    success_after_command = True
                    break
                if success_ts >= command_ts:
                    success_after_command = True
                    break
            if not success_after_command:
                continue

            session_has_success = True
            success_counts[command] += 1

            if latest_fix is None or command_ts is None:
                continue
            if command_ts >= latest_fix:
                follow_fix_counts[command] += 1

        if session_has_success:
            verification_success_score += 1

    return success_counts, follow_fix_counts, verification_success_score


def _rank_verification_priority(
    *,
    candidate_steps: list[str],
    success_counts: Counter[str],
    follow_fix_counts: Counter[str],
) -> list[str]:
    candidates = [normalize_verification_step(step) for step in candidate_steps if normalize_verification_step(step)]
    ordered_candidates: list[str] = []
    seen: set[str] = set()
    for command in candidates:
        key = command.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered_candidates.append(command)

    if not ordered_candidates:
        ordered_candidates = sorted(success_counts.keys(), key=lambda item: item.lower())

    safety_rank = {"safe": 0, "caution": 1, "destructive": 2}

    def rank_key(command: str) -> tuple[int, int, int, str]:
        safety = classify_verification_step(command)
        return (
            -int(safety_rank.get(safety, 1)),
            int(success_counts.get(command, 0)),
            int(follow_fix_counts.get(command, 0)),
            command,
        )

    ordered_candidates.sort(key=rank_key, reverse=True)
    return ordered_candidates[:5]


def _verification_outcome_effect(
    conn: sqlite3.Connection | None,
    signature: str,
) -> VerificationOutcomeEffect:
    """Score adjustment from historical verification outcomes.

    Returns positive value when past fixes succeeded, negative when relapsed.
    """
    if conn is None or not signature.strip():
        return VerificationOutcomeEffect(score=0, pass_count=0, fail_count=0, unknown_count=0)

    rows = query_outcomes_for_signature(conn, signature)
    if not rows:
        return VerificationOutcomeEffect(score=0, pass_count=0, fail_count=0, unknown_count=0)

    passes = 0
    fails = 0
    unknowns = 0
    for row in rows:
        value = str(row["outcome"]).strip().lower()
        if value in {"pass", "passed", "success", "successful", "resolved", "fixed"}:
            passes += 1
        elif value in {"fail", "failed", "failure", "broken", "still broken"}:
            fails += 1
        else:
            unknowns += 1

    # Positive boost is strictly capped to +2.
    positive_boost = min(2, passes)
    failure_penalty = min(4, fails * 2)
    return VerificationOutcomeEffect(
        score=positive_boost - failure_penalty,
        pass_count=passes,
        fail_count=fails,
        unknown_count=unknowns,
    )


def _confidence_cap(
    *,
    fix_success_count: int,
    verification_success_score: int,
    verification_outcome_score: int,
    verification_outcome_fail_count: int,
    recurrence_penalty: int,
) -> tuple[float, bool]:
    """Apply deterministic anti-saturation guardrails."""
    cap = 0.94
    strict_high_confidence = (
        fix_success_count >= 2
        and verification_success_score >= 8
        and verification_outcome_score > 0
        and verification_outcome_fail_count == 0
        and recurrence_penalty == 0
    )

    if fix_success_count == 0:
        cap = min(cap, 0.70)
    elif fix_success_count == 1:
        cap = min(cap, 0.82)

    if verification_success_score < 3:
        cap = min(cap, 0.85)
    if verification_success_score == 0:
        cap = min(cap, 0.78)

    if recurrence_penalty > 0:
        cap = min(cap, 0.75)
    if recurrence_penalty >= 3:
        cap = min(cap, 0.65)

    if strict_high_confidence:
        cap = 1.0
    return cap, strict_high_confidence


def calibrate_phase4(
    *,
    related_rows: list[Any],
    context_event_times: list[datetime],
    fix_outcomes: list[tuple[datetime | None, str, str]],
    candidate_verification_steps: list[str],
    conn: sqlite3.Connection | None = None,
    target_signature: str = "",
) -> Phase4Result:
    """Compute Phase 4 confidence breakdown and verification priority list."""
    fix_success_count = _compute_fix_success_count(fix_outcomes)
    session_evidence_score = min(10, fix_success_count)
    recurrence_penalty = _compute_recurrence_penalty(event_times=context_event_times, fix_outcomes=fix_outcomes)
    success_counts, follow_fix_counts, verification_signal_score = _verification_signal_stats(related_rows)
    verification_signal_score = min(10, verification_signal_score)

    outcome_effect = _verification_outcome_effect(conn, target_signature)
    verification_outcome_score = outcome_effect.score
    if recurrence_penalty > 0 and verification_outcome_score > 0:
        # Never let post-recurrence pass outcomes increase confidence.
        verification_outcome_score = 0

    has_verified_success = verification_signal_score > 0 or verification_outcome_score > 0
    if recurrence_penalty > 0 and not has_verified_success:
        # Repeated failures without verified success get additional penalty.
        recurrence_penalty = min(6, recurrence_penalty + 1)

    verification_success_score = max(0, verification_signal_score + verification_outcome_score)

    raw_points = (
        (3 * session_evidence_score)
        + (2 * verification_signal_score)
        + (2 * max(0, verification_outcome_score))
        - (3 * max(0, -verification_outcome_score))
        - (3 * recurrence_penalty)
    )
    raw_confidence = min(1.0, max(0.0, raw_points / 40.0))

    cap, strict_high_confidence = _confidence_cap(
        fix_success_count=fix_success_count,
        verification_success_score=verification_success_score,
        verification_outcome_score=verification_outcome_score,
        verification_outcome_fail_count=outcome_effect.fail_count,
        recurrence_penalty=recurrence_penalty,
    )
    confidence = round(min(raw_confidence, cap), 2)

    verification_priority = _rank_verification_priority(
        candidate_steps=candidate_verification_steps,
        success_counts=success_counts,
        follow_fix_counts=follow_fix_counts,
    )

    return Phase4Result(
        confidence_breakdown={
            "fix_success_count": int(fix_success_count),
            "session_evidence_score": int(session_evidence_score),
            "recurrence_penalty": int(recurrence_penalty),
            "verification_signal_score": int(verification_signal_score),
            "verification_outcome_score": int(verification_outcome_score),
            "verification_outcome_pass_count": int(outcome_effect.pass_count),
            "verification_outcome_fail_count": int(outcome_effect.fail_count),
            "verification_outcome_unknown_count": int(outcome_effect.unknown_count),
            "verification_success_score": int(verification_success_score),
            "high_confidence_criteria_met": int(1 if strict_high_confidence else 0),
            "confidence_cap_pct": int(round(cap * 100)),
        },
        confidence=confidence,
        verification_priority=verification_priority,
    )
