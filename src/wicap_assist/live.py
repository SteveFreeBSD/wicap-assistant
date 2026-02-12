"""Read-only live runtime monitor with evidence correlation and persistence."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import time
from typing import Any

from wicap_assist.config import wicap_repo_root
from wicap_assist.db import (
    close_running_control_sessions,
    insert_control_episode,
    insert_control_event,
    insert_policy_decision,
    insert_control_session,
    insert_control_session_event,
    insert_decision_feature,
    insert_live_observation,
    insert_model_shadow_metric,
    insert_proactive_action_outcome,
    update_control_session,
)
from wicap_assist.action_ranker import rank_allowlisted_actions
from wicap_assist.decision_features import build_decision_feature_vector, query_prior_action_stats
from wicap_assist.failover_profiles import (
    apply_failover_transition,
    load_failover_state,
    persist_failover_state,
)
from wicap_assist.guardian import (
    GuardianState,
    PlaybookEntry,
    format_guardian_alert_text,
    load_playbook_entries,
    scan_guardian_once,
)
from wicap_assist.known_issues import match_known_issue
from wicap_assist.mission_graph import (
    finalize_live_mission_run,
    record_live_mission_step,
    start_live_mission_run,
)
from wicap_assist.playbooks import default_playbooks_dir
from wicap_assist.probes import probe_docker, probe_http_health, probe_network
from wicap_assist.policy_explain import collect_policy_explain
from wicap_assist.recommend import build_recommendation
from wicap_assist.soak_control import ControlPolicy
from wicap_assist.soak_manager import build_operator_guidance
from wicap_assist.telemetry import emit_control_cycle_telemetry
from wicap_assist.util.evidence import normalize_signature
from wicap_assist.util.redact import to_snippet
from wicap_assist.working_memory import (
    parse_working_memory,
    summarize_working_memory,
    update_working_memory,
)

_ERROR_LINE_RE = re.compile(
    r"(?:traceback|exception|error:|failed to|permission denied|econnrefused|etimedout|eacces|enoent|fatal|panic|critical)",
    re.IGNORECASE,
)
_PYTEST_FAIL_RE = re.compile(r"(?:\bFAILED\b|AssertionError|\bE\s{3})")
_DOCKER_FAIL_RE = re.compile(
    r"(?:\brestarting\b|\bexited\b|\bunhealthy\b|\bback-off\b|\bcrashloop\b|error response from daemon|no such container|cannot connect)",
    re.IGNORECASE,
)

_ERROR_SPIKE_THRESHOLD = 8
_LIVE_RESUME_WINDOW_SECONDS = 180
_NETWORK_SIGNATURE_LOOKBACK_MINUTES = 30


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_iso_utc(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _metadata_repo_root(raw_meta: object) -> str | None:
    if not isinstance(raw_meta, str) or not raw_meta.strip():
        return None
    try:
        payload = json.loads(raw_meta)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("repo_root")
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _metadata_working_memory(raw_meta: object) -> dict[str, Any]:
    return parse_working_memory(raw_meta)


def _infer_category(line: str) -> str:
    if _PYTEST_FAIL_RE.search(line):
        return "pytest_fail"
    if _DOCKER_FAIL_RE.search(line):
        return "docker_fail"
    return "error"


def extract_top_signatures(service_logs: dict[str, list[str]], *, limit: int = 3) -> list[dict[str, Any]]:
    """Extract top normalized failure signatures from observed service logs."""
    counts: Counter[tuple[str, str]] = Counter()
    examples: dict[tuple[str, str], dict[str, str]] = {}

    for service, lines in service_logs.items():
        for raw in lines:
            line = str(raw).strip()
            if not line:
                continue
            if not _ERROR_LINE_RE.search(line):
                continue

            snippet = to_snippet(line, max_len=200)
            signature = normalize_signature(snippet)
            if not signature:
                continue

            category = _infer_category(line)
            key = (category, signature)
            counts[key] += 1
            if key not in examples:
                examples[key] = {
                    "service": service,
                    "example": snippet,
                }

    ranked = sorted(
        counts.items(),
        key=lambda item: (-int(item[1]), item[0][0], item[0][1]),
    )

    top: list[dict[str, Any]] = []
    for (category, signature), count in ranked[: max(1, int(limit))]:
        meta = examples.get((category, signature), {})
        top.append(
            {
                "category": category,
                "signature": signature,
                "count": int(count),
                "service": str(meta.get("service", "")),
                "example": str(meta.get("example", "")),
            }
        )
    return top


def _recent_network_top_signatures(
    conn: sqlite3.Connection,
    *,
    limit: int = 2,
    lookback_minutes: int = _NETWORK_SIGNATURE_LOOKBACK_MINUTES,
) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc).timestamp() - max(1, int(lookback_minutes)) * 60
    rows = conn.execute(
        """
        SELECT category, snippet, ts_text, extra_json
        FROM log_events
        WHERE category IN ('network_anomaly', 'network_flow')
        ORDER BY id DESC
        LIMIT 2000
        """
    ).fetchall()

    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        ts_value = _parse_iso_utc(row["ts_text"])
        if ts_value is not None and ts_value.timestamp() < cutoff:
            continue
        category = str(row["category"]).strip()
        snippet = str(row["snippet"]).strip()
        signature = normalize_signature(snippet)
        if not signature:
            continue
        key = (category, signature)
        bucket = buckets.setdefault(
            key,
            {
                "category": category,
                "signature": signature,
                "count": 0,
                "service": "network-intel",
                "example": to_snippet(snippet, max_len=200),
                "attack_type": None,
            },
        )
        bucket["count"] = int(bucket["count"]) + 1

        extra_raw = row["extra_json"]
        if isinstance(extra_raw, str) and extra_raw.strip():
            try:
                extra = json.loads(extra_raw)
            except json.JSONDecodeError:
                extra = {}
            if isinstance(extra, dict):
                attack_type = extra.get("attack_type")
                if isinstance(attack_type, str) and attack_type.strip():
                    bucket["attack_type"] = attack_type.strip().lower()

    ranked = sorted(
        buckets.values(),
        key=lambda item: (-int(item["count"]), str(item["category"]), str(item["signature"])),
    )
    return ranked[: max(1, int(limit))]


def _match_playbook(
    entry: dict[str, Any],
    playbooks: dict[tuple[str, str], PlaybookEntry],
) -> str | None:
    category = str(entry.get("category", "")).strip()
    signature = str(entry.get("signature", "")).strip()
    if not category or not signature:
        return None

    direct = playbooks.get((category, signature))
    if direct is not None:
        return direct.filename

    for fallback in ("error", "docker_fail", "pytest_fail"):
        match = playbooks.get((fallback, signature))
        if match is not None:
            return match.filename
    return None


def _safe_verify_steps(recommend_payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    entries = recommend_payload.get("verification_step_safety", [])
    if isinstance(entries, list):
        for item in entries:
            if not isinstance(item, dict):
                continue
            if str(item.get("safety", "")) != "safe":
                continue
            step = str(item.get("step", "")).strip()
            if not step or step in seen:
                continue
            seen.add(step)
            out.append(step)
    return out


def _build_live_guidance(
    *,
    down_services: list[str],
    recommendations: list[dict[str, Any]],
    alert: str,
) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()

    def add(line: str) -> None:
        value = line.strip()
        if not value or value in seen:
            return
        seen.add(value)
        lines.append(value)

    if down_services:
        add("Services are down; verify docker container health and startup state.")

    for item in recommendations:
        if not isinstance(item, dict):
            continue
        safe_steps = item.get("safe_verify_steps", [])
        if isinstance(safe_steps, list) and safe_steps:
            add(f"Run verify step: {safe_steps[0]}")
        recommend_payload = item.get("recommendation", {})
        if isinstance(recommend_payload, dict):
            action = str(recommend_payload.get("recommended_action", "")).strip()
            if action and action != "insufficient historical evidence":
                add(action)
        known_issue = item.get("known_issue")
        if isinstance(known_issue, dict):
            known_action = str(known_issue.get("recommended_action", "")).strip()
            if known_action:
                add(known_action)

    if not lines and alert:
        add("Alert detected; check service status and review recent container logs.")
    if not lines:
        add("System appears stable; continue monitoring soak health signals.")
    return lines[:6]


def collect_live_cycle(
    conn: sqlite3.Connection,
    *,
    playbooks_dir: Path | None = None,
) -> dict[str, Any]:
    """Collect one live observation cycle and correlate with stored evidence."""
    ts = _utc_now_iso()

    docker = probe_docker()
    network = probe_network()
    http = probe_http_health()

    service_status = docker.get("services", {}) if isinstance(docker, dict) else {}
    service_logs = docker.get("logs", {}) if isinstance(docker, dict) else {}
    if not isinstance(service_status, dict):
        service_status = {}
    if not isinstance(service_logs, dict):
        service_logs = {}

    service_top_signatures = extract_top_signatures(service_logs, limit=3)
    network_top_signatures = _recent_network_top_signatures(conn, limit=2)
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in [*service_top_signatures, *network_top_signatures]:
        if not isinstance(entry, dict):
            continue
        category = str(entry.get("category", "")).strip()
        signature = str(entry.get("signature", "")).strip()
        if not category or not signature:
            continue
        key = (category, signature)
        bucket = merged.setdefault(
            key,
            {
                "category": category,
                "signature": signature,
                "count": 0,
                "service": str(entry.get("service", "")),
                "example": str(entry.get("example", "")),
            },
        )
        bucket["count"] = int(bucket.get("count", 0)) + int(entry.get("count", 0) or 0)
        if not bucket.get("service"):
            bucket["service"] = str(entry.get("service", ""))
        if not bucket.get("example"):
            bucket["example"] = str(entry.get("example", ""))
        attack_type = entry.get("attack_type")
        if isinstance(attack_type, str) and attack_type.strip():
            bucket["attack_type"] = attack_type.strip().lower()

    top_signatures = sorted(
        merged.values(),
        key=lambda item: (-int(item.get("count", 0)), str(item.get("category", "")), str(item.get("signature", ""))),
    )[:5]
    playbook_map = load_playbook_entries(playbooks_dir or default_playbooks_dir())

    recommendations: list[dict[str, Any]] = []
    for item in top_signatures:
        playbook = _match_playbook(item, playbook_map)
        item["playbook"] = playbook

        signature = str(item.get("signature", "")).strip()
        if not signature:
            continue
        recommend_payload = build_recommendation(conn, signature)
        known_issue = match_known_issue(
            signature=signature,
            category=str(item.get("category", "")),
            example=str(item.get("example", "")),
        )
        if (
            known_issue is not None
            and str(recommend_payload.get("recommended_action", "")).strip() == "insufficient historical evidence"
        ):
            recommend_payload = dict(recommend_payload)
            recommended_action = str(known_issue.get("recommended_action", "")).strip()
            if recommended_action:
                recommend_payload["recommended_action"] = recommended_action
            recommend_payload["confidence"] = round(
                max(float(recommend_payload.get("confidence", 0.0)), float(known_issue.get("confidence", 0.0))),
                3,
            )
            verify_steps = [str(step).strip() for step in list(known_issue.get("verification_steps", [])) if str(step).strip()]
            if verify_steps:
                recommend_payload["verification_priority"] = verify_steps[:5]
                recommend_payload["verification_steps"] = verify_steps[:5]
                recommend_payload["verification_step_safety"] = [
                    {"step": step, "safety": "safe"}
                    for step in verify_steps[:5]
                ]
            risk_notes = str(known_issue.get("risk_notes", "")).strip()
            if risk_notes:
                recommend_payload["risk_notes"] = risk_notes
        recommendations.append(
            {
                "signature": signature,
                "category": str(item.get("category", "")),
                "recommendation": recommend_payload,
                "safe_verify_steps": _safe_verify_steps(recommend_payload),
                "known_issue": known_issue,
            }
        )

    down_services: list[str] = []
    restarting_services: list[str] = []
    for service, info in service_status.items():
        if not isinstance(info, dict):
            continue
        state = str(info.get("state", "unknown"))
        if state == "restarting":
            restarting_services.append(str(service))
        elif state != "up":
            down_services.append(str(service))

    error_total = sum(int(item.get("count", 0)) for item in top_signatures)
    alert_parts: list[str] = []
    if down_services:
        alert_parts.append("services_down=" + ",".join(sorted(down_services)))
    if restarting_services:
        alert_parts.append("services_restarting=" + ",".join(sorted(restarting_services)))
    if error_total >= _ERROR_SPIKE_THRESHOLD:
        alert_parts.append(f"error_spike={error_total}")

    alert = "; ".join(alert_parts)
    operator_guidance = _build_live_guidance(
        down_services=down_services,
        recommendations=recommendations,
        alert=alert,
    )

    return {
        "ts": ts,
        "service_status": {
            "docker": {
                "services": service_status,
                "docker_ps_ok": bool(docker.get("docker_ps_ok")) if isinstance(docker, dict) else False,
            },
            "network": network,
            "http": http,
        },
        "top_signatures": top_signatures,
        "recommended": recommendations,
        "operator_guidance": operator_guidance,
        "alert": alert,
    }


def format_live_panel(observation: dict[str, Any]) -> str:
    """Render compact live status panel."""
    ts = observation.get("ts")
    status = observation.get("service_status", {})
    docker = status.get("docker", {}) if isinstance(status, dict) else {}
    services = docker.get("services", {}) if isinstance(docker, dict) else {}
    network = status.get("network", {}) if isinstance(status, dict) else {}
    http = status.get("http", {}) if isinstance(status, dict) else {}
    top_signatures = observation.get("top_signatures", [])
    recommended = observation.get("recommended", [])
    operator_guidance = observation.get("operator_guidance", [])

    rec_by_sig: dict[str, dict[str, Any]] = {}
    if isinstance(recommended, list):
        for item in recommended:
            if not isinstance(item, dict):
                continue
            sig = str(item.get("signature", "")).strip()
            if sig:
                rec_by_sig[sig] = item

    lines: list[str] = ["=== WICAP Live Status ===", f"ts={ts}", "services:"]
    if isinstance(services, dict) and services:
        for service in sorted(services.keys()):
            info = services.get(service)
            if not isinstance(info, dict):
                continue
            lines.append(
                f"- {service}: {info.get('state')} ({info.get('status')})"
            )
    else:
        lines.append("- (no docker service data)")

    lines.append("ports:")
    expected_ports = network.get("expected_ports", {}) if isinstance(network, dict) else {}
    if isinstance(expected_ports, dict) and expected_ports:
        for port in sorted(expected_ports.keys(), key=lambda value: int(value)):
            lines.append(f"- {port}: {'open' if expected_ports.get(port) else 'closed'}")
    else:
        lines.append("- (no network data)")

    http_status = "unknown"
    if isinstance(http, dict):
        if http.get("ok") is True:
            http_status = f"ok ({http.get('status_code')})"
        elif http.get("ok") is False:
            http_status = f"down ({http.get('error')})"
    lines.append(f"http: {http_status}")

    lines.append("top_signatures:")
    if not isinstance(top_signatures, list) or not top_signatures:
        lines.append("- (none)")
    else:
        for idx, item in enumerate(top_signatures, start=1):
            if not isinstance(item, dict):
                continue
            signature = str(item.get("signature", "")).strip()
            lines.append(
                f"{idx}. [{item.get('category')}] x{item.get('count')} {signature}"
            )
            lines.append(f"   playbook={item.get('playbook')}")
            rec = rec_by_sig.get(signature, {})
            safe_steps = rec.get("safe_verify_steps", []) if isinstance(rec, dict) else []
            if isinstance(safe_steps, list) and safe_steps:
                lines.append("   verify_steps:")
                for step in safe_steps[:3]:
                    lines.append(f"   - {step}")
            else:
                lines.append("   verify_steps: (none)")

    alert = str(observation.get("alert", "")).strip()
    if alert:
        lines.append(f"ALERT: {alert}")

    lines.append("operator_guidance:")
    if isinstance(operator_guidance, list) and operator_guidance:
        for line in operator_guidance[:5]:
            lines.append(f"- {line}")
    else:
        lines.append("- (none)")

    return "\n".join(lines)


def run_live_monitor(
    conn: sqlite3.Connection,
    *,
    interval: float = 10.0,
    once: bool = False,
    playbooks_dir: Path | None = None,
    control_mode: str = "observe",
    control_check_threshold: int | None = None,
    control_recover_threshold: int | None = None,
    control_max_recover_attempts: int | None = None,
    control_action_cooldown_cycles: int | None = None,
    stop_on_escalation: bool = False,
    resume_window_seconds: int = _LIVE_RESUME_WINDOW_SECONDS,
    repo_root: Path | None = None,
    control_runner=subprocess.run,
) -> int:
    """Run live monitor loop with optional allowlisted control actions."""
    sleep_seconds = max(0.1, float(interval))
    guardian_state = GuardianState()
    resolved_playbooks_dir = playbooks_dir or default_playbooks_dir()
    guardian_playbooks = load_playbook_entries(resolved_playbooks_dir)
    active_repo_root = (repo_root or wicap_repo_root()).resolve()
    policy = ControlPolicy(
        mode=str(control_mode),
        repo_root=active_repo_root,
        runner=control_runner,
        check_threshold=control_check_threshold,
        recover_threshold=control_recover_threshold,
        max_recover_attempts=control_max_recover_attempts,
        action_cooldown_cycles=control_action_cooldown_cycles,
    )
    resolved_check_threshold = int(policy.check_threshold)
    resolved_recover_threshold = int(policy.recover_threshold)
    resolved_max_recover_attempts = int(policy.max_recover_attempts)
    resolved_action_cooldown = int(policy.action_cooldown_cycles)
    resolved_profile_name = str(policy.profile_name)
    resolved_kill_switch_env = str(policy.kill_switch_env_var or "")
    resolved_kill_switch_file = str(policy.kill_switch_file) if policy.kill_switch_file is not None else None
    resolved_rollback_actions = list(policy.rollback_actions or ())
    policy_snapshot = collect_policy_explain(repo_root=active_repo_root, runner=control_runner)
    started_ts = _utc_now_iso()
    now_dt = _parse_iso_utc(started_ts) or datetime.now(timezone.utc)
    max_resume_age = max(30, int(resume_window_seconds))
    stale_closed = 0
    candidate_session_id: int | None = None
    candidate_rows = conn.execute(
        """
        SELECT id, mode, started_ts, last_heartbeat_ts, metadata_json
        FROM control_sessions
        WHERE ended_ts IS NULL
          AND status IN ('running', 'escalated')
        ORDER BY id DESC
        """
    ).fetchall()
    for row in candidate_rows:
        heartbeat_dt = _parse_iso_utc(row["last_heartbeat_ts"]) or _parse_iso_utc(row["started_ts"])
        if heartbeat_dt is None or (now_dt - heartbeat_dt).total_seconds() > max_resume_age:
            session_id = int(row["id"])
            update_control_session(
                conn,
                control_session_id=session_id,
                ended_ts=started_ts,
                status="interrupted",
                current_phase="interrupted",
                handoff_state="stale_closed",
                metadata_json={"interruption_reason": "stale_heartbeat"},
            )
            insert_control_session_event(
                conn,
                control_session_id=session_id,
                ts=started_ts,
                phase="interrupted",
                status="interrupted",
                detail_json={"reason": "stale_heartbeat"},
            )
            stale_closed += 1
            continue

        session_repo = _metadata_repo_root(row["metadata_json"])
        same_mode = str(row["mode"]) == str(control_mode)
        same_repo = False
        if session_repo is not None:
            try:
                same_repo = Path(session_repo).resolve() == active_repo_root
            except OSError:
                same_repo = False
        if candidate_session_id is None and same_mode and same_repo:
            candidate_session_id = int(row["id"])

    interrupted_sessions = stale_closed
    resumed = candidate_session_id is not None
    working_memory_state: dict[str, Any] = {
        "unresolved_signatures": [],
        "pending_actions": [],
        "recent_transitions": [],
        "down_services": [],
        "last_observation_ts": None,
    }
    if resumed:
        interrupted_sessions += close_running_control_sessions(
            conn,
            ended_ts=started_ts,
            reason="superseded_by_live_monitor_resume",
            exclude_session_id=int(candidate_session_id),
        )
        control_session_id = int(candidate_session_id)
        resume_row = conn.execute(
            "SELECT metadata_json FROM control_sessions WHERE id = ?",
            (int(control_session_id),),
        ).fetchone()
        if resume_row is not None:
            working_memory_state = _metadata_working_memory(resume_row["metadata_json"])
        working_summary = summarize_working_memory(working_memory_state)
        update_control_session(
            conn,
            control_session_id=int(control_session_id),
            status="running",
            current_phase="live_monitor",
            handoff_state="resumed",
            last_heartbeat_ts=started_ts,
            metadata_json={
                "interval": float(interval),
                "once": bool(once),
                "control_policy_profile": resolved_profile_name,
                "control_check_threshold": int(resolved_check_threshold),
                "control_recover_threshold": int(resolved_recover_threshold),
                "control_max_recover_attempts": int(resolved_max_recover_attempts),
                "control_action_cooldown_cycles": int(resolved_action_cooldown),
                "control_kill_switch_env_var": resolved_kill_switch_env or None,
                "control_kill_switch_file": resolved_kill_switch_file,
                "control_rollback_enabled": bool(policy.rollback_enabled),
                "control_rollback_actions": resolved_rollback_actions,
                "control_rollback_max_attempts": int(policy.rollback_max_attempts or 1),
                "stop_on_escalation": bool(stop_on_escalation),
                "repo_root": str(active_repo_root),
                "resume_window_seconds": int(max_resume_age),
                "interrupted_sessions_closed": int(interrupted_sessions),
                "working_memory": working_memory_state,
                "policy_explain": policy_snapshot,
            },
        )
        insert_control_session_event(
            conn,
            control_session_id=int(control_session_id),
            ts=started_ts,
            phase="live_monitor",
            status="resumed",
            detail_json={
                "mode": str(control_mode),
                "profile": resolved_profile_name,
                "working_memory": working_summary,
            },
        )
    else:
        interrupted_sessions += close_running_control_sessions(
            conn,
            ended_ts=started_ts,
            reason="superseded_by_live_monitor",
        )
        control_session_id = insert_control_session(
            conn,
            soak_run_id=None,
            started_ts=started_ts,
            last_heartbeat_ts=started_ts,
            mode=str(control_mode),
            status="running",
            current_phase="live_monitor",
            handoff_state="new",
            metadata_json={
                "interval": float(interval),
                "once": bool(once),
                "control_policy_profile": resolved_profile_name,
                "control_check_threshold": int(resolved_check_threshold),
                "control_recover_threshold": int(resolved_recover_threshold),
                "control_max_recover_attempts": int(resolved_max_recover_attempts),
                "control_action_cooldown_cycles": int(resolved_action_cooldown),
                "control_kill_switch_env_var": resolved_kill_switch_env or None,
                "control_kill_switch_file": resolved_kill_switch_file,
                "control_rollback_enabled": bool(policy.rollback_enabled),
                "control_rollback_actions": resolved_rollback_actions,
                "control_rollback_max_attempts": int(policy.rollback_max_attempts or 1),
                "stop_on_escalation": bool(stop_on_escalation),
                "repo_root": str(active_repo_root),
                "resume_window_seconds": int(max_resume_age),
                "interrupted_sessions_closed": int(interrupted_sessions),
                "working_memory": working_memory_state,
                "policy_explain": policy_snapshot,
            },
        )
        insert_control_session_event(
            conn,
            control_session_id=int(control_session_id),
            ts=started_ts,
            phase="live_monitor",
            status="started",
            detail_json={
                "mode": str(control_mode),
                "profile": resolved_profile_name,
            },
        )
    conn.commit()

    mission_state = start_live_mission_run(
        conn,
        control_session_id=int(control_session_id),
        mode=str(control_mode),
        started_ts=started_ts,
        metadata_json={
            "repo_root": str(active_repo_root),
            "policy_profile": resolved_profile_name,
            "resumed_session": bool(resumed),
        },
    )
    mission_run_id = int(mission_state["mission_run_id"])
    mission_run_key = str(mission_state["run_id"])
    mission_last_step = str(mission_state.get("last_step", "observe") or "observe")
    mission_step_index = int(mission_state.get("next_step_index", 0))
    mission_transition_violations = 0
    update_control_session(
        conn,
        control_session_id=int(control_session_id),
        metadata_json={
            "mission_run_id": mission_run_key,
            "mission_graph_id": "wicap-live-control-v1",
            "mission_graph_resumed": bool(mission_state.get("resumed", False)),
        },
    )
    conn.commit()

    return_code = 0
    final_status = "completed" if bool(once) else "interrupted"
    total_observations = 0
    total_control_events = 0
    escalated = False
    failover_state = load_failover_state(conn)

    try:
        while True:
            observation = collect_live_cycle(conn, playbooks_dir=resolved_playbooks_dir)
            alerts = scan_guardian_once(
                conn,
                state=guardian_state,
                path_specs=None,
                playbooks=guardian_playbooks,
                start_at_end_for_new=not bool(once),
            )
            cycle_control_events = policy.process_observation(observation)
            shadow_ranker = rank_allowlisted_actions(
                conn,
                observation=observation,
                mode=str(control_mode),
                policy_profile=resolved_profile_name,
                top_n=3,
            )
            ranking_rows = shadow_ranker.get("rankings", []) if isinstance(shadow_ranker, dict) else []
            gate_payload = shadow_ranker.get("shadow_gate", {}) if isinstance(shadow_ranker, dict) else {}
            agreement_rate = (
                _safe_float(gate_payload.get("agreement_rate")) if isinstance(gate_payload, dict) else None
            )
            top_action = str(shadow_ranker.get("top_action", "")).strip() if isinstance(shadow_ranker, dict) else ""
            if isinstance(ranking_rows, list):
                for rank in ranking_rows[:3]:
                    if not isinstance(rank, dict):
                        continue
                    candidate_action = str(rank.get("action", "")).strip()
                    if not candidate_action:
                        continue
                    insert_model_shadow_metric(
                        conn,
                        ts=str(observation.get("ts", _utc_now_iso())),
                        source="live_monitor",
                        decision="shadow_ranker",
                        action=candidate_action,
                        model_id=f"shadow_ranker:{candidate_action}",
                        score=_safe_float(rank.get("score")),
                        vote=bool(candidate_action == top_action),
                        agreement=agreement_rate,
                        payload_json={
                            "mode": str(control_mode),
                            "policy_profile": resolved_profile_name,
                            "rank": rank,
                            "shadow_gate": gate_payload if isinstance(gate_payload, dict) else {},
                        },
                    )
            cycle_actions_executed = 0
            for event in cycle_control_events:
                total_control_events += 1
                status = str(event.get("status", ""))
                if status.startswith("executed_"):
                    cycle_actions_executed += 1
                if status == "escalated":
                    escalated = True
                ts = str(event.get("ts", _utc_now_iso()))
                decision = str(event.get("decision", ""))
                action = str(event.get("action")) if event.get("action") is not None else None
                detail_payload = event.get("detail_json", {})
                if not isinstance(detail_payload, dict):
                    detail_payload = {}
                detail_payload = dict(detail_payload)
                detail_payload["shadow_ranker"] = shadow_ranker

                previous_mission_step = mission_last_step
                mission_step = record_live_mission_step(
                    conn,
                    mission_run_id=int(mission_run_id),
                    run_id=mission_run_key,
                    last_step=previous_mission_step,
                    ts=ts,
                    decision=decision,
                    action=action,
                    status=status,
                    detail_json={
                        "control_session_id": int(control_session_id),
                        "observation_cycle": int(total_observations) + 1,
                    },
                    step_index=int(mission_step_index),
                )
                mission_step_index += 1
                mission_last_step = str(mission_step.get("next_step", mission_last_step))
                transition_ok = bool(mission_step.get("transition_ok", False))
                if not transition_ok:
                    mission_transition_violations += 1
                    escalated = True
                detail_payload["mission"] = {
                    "run_id": mission_run_key,
                    "step_type": mission_step.get("step_type"),
                    "transition_ok": transition_ok,
                    "terminal_state": bool(mission_step.get("terminal_state", False)),
                    "previous_step": previous_mission_step,
                }
                event["detail_json"] = detail_payload
                episode_id = insert_control_episode(
                    conn,
                    control_session_id=int(control_session_id),
                    soak_run_id=None,
                    ts=ts,
                    decision=decision,
                    action=action,
                    status=status,
                    pre_state_json={
                        "alert": str(observation.get("alert", "")),
                        "service_status": observation.get("service_status", {}),
                        "top_signatures": observation.get("top_signatures", []),
                    },
                    post_state_json={
                        "control_status": status,
                        "escalated": bool(escalated),
                        "observation_cycle": int(total_observations) + 1,
                    },
                    detail_json=detail_payload,
                )
                insert_control_event(
                    conn,
                    soak_run_id=None,
                    ts=ts,
                    decision=decision,
                    action=action,
                    status=status,
                    episode_id=episode_id,
                    detail_json=detail_payload,
                )
                policy_trace = detail_payload.get("policy_trace")
                if action and isinstance(policy_trace, dict):
                    denied_by = policy_trace.get("denied_by")
                    reason = str(detail_payload.get("detail", "")).strip() or None
                    insert_policy_decision(
                        conn,
                        ts=ts,
                        control_session_id=int(control_session_id),
                        soak_run_id=None,
                        action=action,
                        mode=str(control_mode),
                        allowed=(str(status).strip().lower() not in {"rejected"}),
                        denied_by=(str(denied_by).strip() if denied_by is not None else None),
                        reason=reason,
                        trace_id=str(policy_trace.get("trace_id", "")).strip() or None,
                        policy_trace_json=policy_trace,
                    )

                failure_class = str(detail_payload.get("failure_class", "none")).strip().lower()
                if action and failure_class not in {"", "none"}:
                    failover_state = apply_failover_transition(
                        failover_state,
                        failure_class=failure_class,
                        now_ts=ts,
                    )
                    persist_failover_state(
                        conn,
                        state=failover_state,
                        control_session_id=int(control_session_id),
                        detail={
                            "decision": decision,
                            "action": action,
                            "status": status,
                        },
                    )
                elif action and failure_class in {"", "none"} and str(status).strip().lower() == "executed_ok":
                    if str(failover_state.failure_class).strip().lower() not in {"", "none"}:
                        failover_state = apply_failover_transition(
                            failover_state,
                            failure_class="success",
                            now_ts=ts,
                        )
                        persist_failover_state(
                            conn,
                            state=failover_state,
                            control_session_id=int(control_session_id),
                            detail={
                                "decision": decision,
                                "action": action,
                                "status": status,
                            },
                        )
                prior_stats = query_prior_action_stats(conn, action)
                feature_vector = build_decision_feature_vector(
                    event=event,
                    mode=str(control_mode),
                    policy_profile=resolved_profile_name,
                    prior_stats=prior_stats,
                )
                insert_decision_feature(
                    conn,
                    control_session_id=int(control_session_id),
                    soak_run_id=None,
                    episode_id=int(episode_id),
                    ts=ts,
                    mode=str(control_mode),
                    policy_profile=resolved_profile_name,
                    decision=decision,
                    action=action,
                    status=status,
                    feature_json=feature_vector,
                )
                insert_control_session_event(
                    conn,
                    control_session_id=int(control_session_id),
                    ts=ts,
                    phase="live_cycle",
                    status=status,
                    detail_json=detail_payload,
                )
                reasoning_class = str(detail_payload.get("reasoning_class", "")).strip().lower()
                if action and (
                    reasoning_class == "forecast_preemption"
                    or decision.startswith("anomaly_")
                    or "forecast" in decision
                ):
                    insert_proactive_action_outcome(
                        conn,
                        ts=ts,
                        control_session_id=int(control_session_id),
                        action=action,
                        decision=decision,
                        status=status,
                        trigger_risk_score=_safe_float(detail_payload.get("risk_score")),
                        horizon_sec=_safe_int(detail_payload.get("horizon_sec")),
                        payload_json=detail_payload,
                    )

            working_memory_state = update_working_memory(
                working_memory_state,
                observation=observation,
                cycle_control_events=cycle_control_events,
            )
            working_summary = summarize_working_memory(working_memory_state)

            total_observations += 1
            anomaly_events = 0
            top_signatures = observation.get("top_signatures", [])
            if isinstance(top_signatures, list):
                for item in top_signatures:
                    if not isinstance(item, dict):
                        continue
                    anomaly_events += int(item.get("count", 0) or 0)
            shadow_gate_payload = shadow_ranker.get("shadow_gate", {}) if isinstance(shadow_ranker, dict) else {}
            if not isinstance(shadow_gate_payload, dict):
                shadow_gate_payload = {}
            try:
                emit_control_cycle_telemetry(
                    mode=str(control_mode),
                    profile=resolved_profile_name,
                    decision="live_cycle",
                    observation_cycle=int(total_observations),
                    actions_executed=int(cycle_actions_executed),
                    anomaly_events=int(anomaly_events),
                    message=str(observation.get("alert", "")),
                    attributes={
                        "source": "live_monitor",
                        "guardian_alert_count": int(len(alerts)),
                        "shadow_gate_samples": int(shadow_gate_payload.get("samples", 0) or 0),
                        "shadow_gate_passes": bool(shadow_gate_payload.get("passes", False)),
                        "shadow_gate_agreement_rate": float(shadow_gate_payload.get("agreement_rate", 0.0) or 0.0),
                        "shadow_gate_success_rate": float(shadow_gate_payload.get("success_rate", 0.0) or 0.0),
                    },
                )
            except Exception:
                # Telemetry must never break control loop execution.
                pass
            recommended_payload = observation.get("recommended", [])
            if not isinstance(recommended_payload, list):
                recommended_payload = []
            if alerts:
                recommended_payload = [
                    *recommended_payload,
                    {"guardian_alerts": [alert.to_dict() for alert in alerts[:10]]},
                ]
            row_id = insert_live_observation(
                conn,
                ts=str(observation.get("ts")),
                service_status_json=observation.get("service_status", {}),
                top_signatures_json=observation.get("top_signatures", []),
                recommended_json=recommended_payload,
            )
            update_control_session(
                conn,
                control_session_id=int(control_session_id),
                status="escalated" if escalated else "running",
                current_phase="live_cycle",
                handoff_state="active",
                last_heartbeat_ts=str(observation.get("ts", _utc_now_iso())),
                metadata_json={
                    "observations": int(total_observations),
                    "control_events": int(total_control_events),
                    "working_memory": working_memory_state,
                    "policy_explain": policy_snapshot,
                    "mission_run_id": mission_run_key,
                    "mission_steps_recorded": int(mission_step_index),
                    "mission_last_step": mission_last_step,
                    "mission_transition_violations": int(mission_transition_violations),
                },
            )
            conn.commit()

            print(format_live_panel(observation))
            print(
                "working_memory: "
                f"unresolved={working_summary['unresolved_count']} "
                f"pending={working_summary['pending_count']} "
                f"transitions={working_summary['transition_count']}"
            )
            if alerts:
                print(f"guardian_alerts={len(alerts)}")
                for alert in alerts[:2]:
                    print(format_guardian_alert_text(alert))
            if cycle_control_events:
                guidance = build_operator_guidance(
                    manager_actions=[],
                    control_events=cycle_control_events,
                    control_mode=str(control_mode),
                )
                for line in guidance[:5]:
                    print(f"[control] {line}")
            print(f"observation_id={row_id}")

            if stop_on_escalation and escalated:
                return_code = 2
                final_status = "escalated"
                break

            if once:
                final_status = "escalated" if escalated else "completed"
                break

            try:
                time.sleep(sleep_seconds)
            except KeyboardInterrupt:
                return_code = 0
                final_status = "interrupted"
                break
    finally:
        ended_ts = _utc_now_iso()
        mission_final_status = str(final_status)
        if mission_transition_violations > 0 and mission_final_status == "completed":
            mission_final_status = "failed"
        finalize_live_mission_run(
            conn,
            mission_run_id=int(mission_run_id),
            status=mission_final_status,
            ended_ts=ended_ts,
            metadata_json={
                "control_session_id": int(control_session_id),
                "observations": int(total_observations),
                "control_events": int(total_control_events),
                "transition_violations": int(mission_transition_violations),
                "steps_recorded": int(mission_step_index),
                "final_step": mission_last_step,
                "return_code": int(return_code),
            },
        )
        update_control_session(
            conn,
            control_session_id=int(control_session_id),
            ended_ts=ended_ts,
            status=final_status,
            current_phase="stopped",
            handoff_state=final_status,
            last_heartbeat_ts=ended_ts,
            metadata_json={
                "observations": int(total_observations),
                "control_events": int(total_control_events),
                "escalated": bool(escalated),
                "return_code": int(return_code),
                "working_memory": working_memory_state,
                "control_policy_profile": resolved_profile_name,
                "control_kill_switch_env_var": resolved_kill_switch_env or None,
                "control_kill_switch_file": resolved_kill_switch_file,
                "control_rollback_enabled": bool(policy.rollback_enabled),
                "control_rollback_actions": resolved_rollback_actions,
                "control_rollback_max_attempts": int(policy.rollback_max_attempts or 1),
                "policy_explain": policy_snapshot,
                "mission_run_id": mission_run_key,
                "mission_steps_recorded": int(mission_step_index),
                "mission_last_step": mission_last_step,
                "mission_transition_violations": int(mission_transition_violations),
                "mission_status": mission_final_status,
            },
        )
        insert_control_session_event(
            conn,
            control_session_id=int(control_session_id),
            ts=ended_ts,
            phase="live_monitor",
            status=final_status,
            detail_json={"return_code": int(return_code)},
        )
        conn.commit()

    return return_code
