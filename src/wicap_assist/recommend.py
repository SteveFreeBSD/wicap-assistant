"""Deterministic recommendation layer based on historical evidence."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
import sqlite3
from typing import Any

from wicap_assist.git_context import (
    build_git_context,
    load_antigravity_git_evidence,
    load_codex_git_evidence,
    load_codex_git_evidence_fallback,
)
from wicap_assist.harness_match import find_relevant_harness_scripts
from wicap_assist.evidence_query import signature_tokens, where_like
from wicap_assist.recommend_confidence import (
    calibrate_phase4,
    classify_verification_step,
    normalize_verification_step,
)
from wicap_assist.util.evidence import normalize_signature, parse_utc_datetime
from wicap_assist.util.redact import to_snippet

_LOG_CATEGORIES = ("error", "docker_fail", "pytest_fail", "network_anomaly", "network_flow")
_SIGNAL_CATEGORIES = ("outcomes", "commands", "file_paths", "errors")
_FIX_RE = re.compile(r"\b(?:fixed|resolved)\b", re.IGNORECASE)
_SUCCESS_RE = re.compile(r"\b(?:fixed|resolved|success)\b", re.IGNORECASE)
_MD_RE = re.compile(r"\b([A-Za-z0-9._-]+\.md)\b")
_META_OUTCOME_RE = re.compile(
    r"(?:i[’']ve\s+fixed.*revalidated\s+the\s+tests|next\s+i[’']ll\s+run\s+one\s+real)",
    re.IGNORECASE,
)
_OUTCOME_PREFIX_RE = re.compile(r"^\s*(?:[-*]|\d+\.)\s*(?:[-*]\s*)?")


@dataclass(slots=True)
class SignatureContext:
    category: str
    signature: str
    count: int
    file_paths: list[str]
    event_times: list[datetime]


def _pick_context(conn: sqlite3.Connection, target: str) -> SignatureContext | None:
    target_raw = target.strip()
    if not target_raw:
        return None

    target_norm = normalize_signature(target_raw)
    target_lower = target_raw.lower()

    category_placeholders = ", ".join("?" for _ in _LOG_CATEGORIES)
    rows = conn.execute(
        f"""
        SELECT category, snippet, ts_text, file_path
        FROM log_events
        WHERE category IN ({category_placeholders})
        """,
        tuple(_LOG_CATEGORIES),
    ).fetchall()

    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    exact_keys: set[tuple[str, str]] = set()
    fuzzy_keys: set[tuple[str, str]] = set()

    for row in rows:
        category = str(row["category"])
        snippet = str(row["snippet"])
        signature = normalize_signature(snippet)
        key = (category, signature)
        bucket = buckets.setdefault(
            key,
            {
                "count": 0,
                "file_counts": Counter(),
                "event_times": [],
            },
        )
        bucket["count"] += 1
        bucket["file_counts"][str(row["file_path"])] += 1

        parsed = parse_utc_datetime(row["ts_text"])
        if parsed is not None:
            bucket["event_times"].append(parsed)

        if signature == target_norm:
            exact_keys.add(key)

        if target_lower in str(row["file_path"]).lower() or target_lower in signature:
            fuzzy_keys.add(key)

    candidate_keys = exact_keys or fuzzy_keys
    if not candidate_keys:
        return None

    ranked = sorted(
        candidate_keys,
        key=lambda key: (
            -int(buckets[key]["count"]),
            key[0],
            key[1],
        ),
    )
    category, signature = ranked[0]
    bucket = buckets[(category, signature)]

    file_counts: Counter[str] = bucket["file_counts"]
    file_paths = [path for path, _ in sorted(file_counts.items(), key=lambda item: (-item[1], item[0]))]
    event_times = sorted(bucket["event_times"])

    return SignatureContext(
        category=category,
        signature=signature,
        count=int(bucket["count"]),
        file_paths=file_paths,
        event_times=event_times,
    )


def _query_related_signals(conn: sqlite3.Connection, signature: str) -> list[sqlite3.Row]:
    tokens = signature_tokens(signature, limit=8)
    where, args = where_like("sg.snippet", tokens)
    if not where:
        return []

    session_rows = conn.execute(
        f"""
        SELECT DISTINCT s.id AS session_pk
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE
            s.is_wicap = 1
            AND ({where})
        """,
        args,
    ).fetchall()

    if not session_rows:
        return []

    session_ids = [int(row["session_pk"]) for row in session_rows]
    placeholders = ", ".join("?" for _ in session_ids)

    return conn.execute(
        f"""
        SELECT
            s.session_id,
            s.ts_last,
            s.repo_url,
            s.branch,
            s.commit_hash,
            sg.category,
            sg.snippet,
            sg.ts
        FROM signals AS sg
        JOIN sessions AS s ON s.id = sg.session_pk
        WHERE
            s.id IN ({placeholders})
            AND sg.category IN ('outcomes', 'commands', 'file_paths', 'errors')
        ORDER BY coalesce(s.ts_last, '') DESC, sg.id DESC
        """,
        session_ids,
    ).fetchall()


def _parse_playbooks(rows: list[sqlite3.Row]) -> list[str]:
    out: set[str] = set()
    for row in rows:
        snippet = str(row["snippet"])
        for match in _MD_RE.findall(snippet):
            if "playbook" in match.lower() or match.lower().startswith(("error-", "docker_fail-", "pytest_fail-")):
                out.add(match)
    return sorted(out)


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _related_evidence(rows: list[sqlite3.Row]) -> dict[str, Any]:
    session_times: dict[str, datetime | None] = {}
    fix_session_ids: set[str] = set()
    fix_outcomes: list[tuple[datetime | None, str, str]] = []
    success_outcomes: list[tuple[datetime | None, str, str]] = []
    command_snippets: list[str] = []

    for row in rows:
        session_id = str(row["session_id"])
        ts_session = parse_utc_datetime(row["ts_last"])
        ts_signal = parse_utc_datetime(row["ts"])
        effective_ts = ts_signal or ts_session

        current = session_times.get(session_id)
        if current is None or (effective_ts is not None and (current is None or effective_ts > current)):
            session_times[session_id] = effective_ts

        category = str(row["category"])
        snippet = str(row["snippet"]).strip()
        if not snippet:
            continue

        if category == "commands":
            command_snippets.append(snippet)

        if category == "outcomes" and _SUCCESS_RE.search(snippet):
            if _META_OUTCOME_RE.search(snippet):
                continue
            success_outcomes.append((effective_ts, session_id, snippet))
            if _FIX_RE.search(snippet):
                fix_session_ids.add(session_id)
                fix_outcomes.append((effective_ts, session_id, snippet))

    fix_outcomes.sort(key=lambda item: ((item[0] or datetime.fromtimestamp(0, tz=timezone.utc)), item[1]), reverse=True)
    success_outcomes.sort(key=lambda item: ((item[0] or datetime.fromtimestamp(0, tz=timezone.utc)), item[1]), reverse=True)

    ordered_fix_sessions = sorted(
        list(fix_session_ids),
        key=lambda session_id: ((session_times.get(session_id) or datetime.fromtimestamp(0, tz=timezone.utc)), session_id),
        reverse=True,
    )

    return {
        "fix_sessions": ordered_fix_sessions,
        "fix_outcomes": fix_outcomes,
        "success_outcomes": success_outcomes,
        "commands": _dedupe_keep_order(command_snippets),
    }


def _empty_git_context() -> dict[str, Any]:
    return build_git_context([])


def _git_evidence_from_related_rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    by_session: dict[str, dict[str, Any]] = {}
    for row in rows:
        session_id = str(row["session_id"]).strip()
        if not session_id:
            continue
        repo_url = row["repo_url"]
        branch = row["branch"]
        commit_hash = row["commit_hash"]
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


def _clean_outcome_snippet(snippet: str) -> str:
    cleaned = _OUTCOME_PREFIX_RE.sub("", snippet.strip())
    return cleaned.strip()


def _empty_confidence_breakdown() -> dict[str, int]:
    return {
        "fix_success_count": 0,
        "session_evidence_score": 0,
        "recurrence_penalty": 0,
        "verification_signal_score": 0,
        "verification_outcome_score": 0,
        "verification_outcome_pass_count": 0,
        "verification_outcome_fail_count": 0,
        "verification_outcome_unknown_count": 0,
        "verification_success_score": 0,
        "high_confidence_criteria_met": 0,
        "confidence_cap_pct": 0,
    }


def _empty_recommendation_payload(target: str, *, git_context: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "input": target,
        "recommended_action": "insufficient historical evidence",
        "confidence": 0.0,
        "based_on_sessions": [],
        "related_playbooks": [],
        "harness_tests": [],
        "git_context": git_context if git_context is not None else _empty_git_context(),
        "confidence_breakdown": _empty_confidence_breakdown(),
        "verification_priority": [],
        "verification_step_safety": [],
        "risk_notes": "",
        "verification_steps": [],
    }


def build_recommendation(conn: sqlite3.Connection, target: str) -> dict[str, Any]:
    """Build deterministic recommendation JSON payload."""
    context = _pick_context(conn, target)
    if context is None:
        return _empty_recommendation_payload(target)

    related_rows = _query_related_signals(conn, context.signature)
    evidence = _related_evidence(related_rows)
    related_playbooks = _parse_playbooks(related_rows)
    based_on_sessions = [str(value) for value in evidence["fix_sessions"]]

    fix_steps = [f"Run `{cmd}`." for cmd in evidence["commands"][:8]]
    context_texts = [snippet for _, _, snippet in evidence["fix_outcomes"][:5]]
    harness_matches = find_relevant_harness_scripts(
        conn,
        category=context.category,
        signature=context.signature,
        fix_steps=fix_steps,
        context_texts=context_texts,
        top_n=3,
    )
    harness_tests = [
        {
            "script": str(entry.get("script_path", "")),
            "role": str(entry.get("role", "")),
            "commands": [str(value) for value in list(entry.get("commands", []))[:3]],
        }
        for entry in harness_matches
    ]

    candidate_verification_steps: list[str] = []
    for harness in harness_tests:
        if harness.get("role") == "verifier":
            candidate_verification_steps.extend([str(cmd) for cmd in harness.get("commands", []) if str(cmd).strip()])
    candidate_verification_steps.extend([str(cmd) for cmd in evidence["commands"] if str(cmd).strip()])

    phase4 = calibrate_phase4(
        related_rows=related_rows,
        context_event_times=context.event_times,
        fix_outcomes=evidence["fix_outcomes"],
        candidate_verification_steps=candidate_verification_steps,
        conn=conn,
        target_signature=context.signature,
    )
    confidence = phase4.confidence
    confidence_breakdown = phase4.confidence_breakdown
    antigravity_ids: list[str] = []
    related_git_evidence = _git_evidence_from_related_rows(related_rows)
    codex_git_evidence = load_codex_git_evidence(conn, based_on_sessions)
    reference_ts = context.event_times[0] if context.event_times else None
    fallback_git_evidence = load_codex_git_evidence_fallback(
        conn,
        reference_ts=reference_ts,
        window_days=7,
        exclude_session_ids=[
            *(item.get("source_id", "") for item in related_git_evidence),
            *(item.get("source_id", "") for item in codex_git_evidence),
        ],
    )
    antigravity_git_evidence = load_antigravity_git_evidence(conn, antigravity_ids)
    git_context = build_git_context(
        [
            *related_git_evidence,
            *codex_git_evidence,
            *fallback_git_evidence,
            *antigravity_git_evidence,
        ]
    )

    sufficient = bool(evidence["fix_sessions"] or related_playbooks or harness_tests)
    if not sufficient:
        return _empty_recommendation_payload(target, git_context=git_context)

    if evidence["fix_outcomes"]:
        top_outcome = _clean_outcome_snippet(str(evidence["fix_outcomes"][0][2]))
        recommended_action = f"Apply previously successful fix: {to_snippet(top_outcome, max_len=140)}"
    elif related_playbooks:
        recommended_action = f"Follow historical playbook: {related_playbooks[0]}"
    else:
        recommended_action = f"Run historical harness recovery path: {harness_tests[0]['script']}"

    verification_priority = _dedupe_keep_order(
        [
            normalize_verification_step(str(step))
            for step in phase4.verification_priority
            if normalize_verification_step(str(step))
        ]
    )
    verification_steps = verification_priority[:5]
    if not verification_steps:
        verification_steps = _dedupe_keep_order(
            [
                normalize_verification_step(str(cmd))
                for cmd in evidence["commands"][:3]
                if normalize_verification_step(str(cmd))
            ]
        )[:5]
    if not verification_priority:
        verification_priority = list(verification_steps)

    verification_step_safety = [
        {
            "step": step,
            "safety": classify_verification_step(step),
        }
        for step in verification_steps
    ]

    risk_notes = ""
    if int(confidence_breakdown.get("recurrence_penalty", 0)) > 0:
        risk_notes = "same failure recurred after a prior fix; validate root cause before rollout"
    elif context.count > 5:
        risk_notes = "high recurrence observed in historical logs"

    return {
        "input": target,
        "recommended_action": recommended_action,
        "confidence": confidence,
        "based_on_sessions": based_on_sessions,
        "related_playbooks": related_playbooks,
        "harness_tests": harness_tests,
        "git_context": git_context,
        "confidence_breakdown": confidence_breakdown,
        "verification_priority": verification_priority,
        "verification_step_safety": verification_step_safety,
        "risk_notes": risk_notes,
        "verification_steps": verification_steps,
    }


def recommendation_to_json(payload: dict[str, Any]) -> str:
    """Encode recommendation payload as JSON."""
    return json.dumps(payload, indent=2, sort_keys=False)
