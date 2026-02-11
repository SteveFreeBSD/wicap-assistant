"""Interactive operator console for the WICAP live control assistant."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable

from wicap_assist.bundle import build_bundle
from wicap_assist.config import wicap_repo_root
from wicap_assist.db import insert_live_observation
from wicap_assist.guardian import (
    GuardianState,
    format_guardian_alert_text,
    load_playbook_entries,
    scan_guardian_once,
)
from wicap_assist.incident import write_incident_report
from wicap_assist.live import collect_live_cycle, format_live_panel
from wicap_assist.recommend import build_recommendation
from wicap_assist.soak_run import run_supervised_soak
from wicap_assist.util.time import utc_now_iso

_MINUTES_RE = re.compile(r"\b(\d+)\s*(?:minutes?|mins?|m)\b", re.IGNORECASE)
_INTERVAL_RE = re.compile(
    r"(?:every|interval|playwright(?:\s+interval)?)\s*(\d+)\s*(?:minutes?|mins?|m)\b",
    re.IGNORECASE,
)


@dataclass(slots=True)
class AgentIntent:
    kind: str
    target: str | None = None
    duration_minutes: int | None = None
    playwright_interval_minutes: int | None = None
    dry_run: bool = False
    control_mode: str = "observe"


def parse_agent_prompt(text: str) -> AgentIntent:
    """Parse a natural-language agent prompt into a deterministic intent."""
    raw = text.strip()
    lower = raw.lower()

    if not raw:
        return AgentIntent(kind="unknown")
    if lower in {"quit", "exit", "q"}:
        return AgentIntent(kind="quit")
    if "help" in lower:
        return AgentIntent(kind="help")

    if "recommend" in lower:
        target = raw.split("recommend", 1)[1].strip() if "recommend" in raw else ""
        return AgentIntent(kind="recommend", target=target or None)

    if "incident" in lower:
        target = raw.split("incident", 1)[1].strip() if "incident" in raw else ""
        return AgentIntent(kind="incident", target=target or None)

    if re.search(r"\b(?:start soak|run soak|soak run|soak-run)\b", lower):
        minutes_match = _MINUTES_RE.search(lower)
        interval_match = _INTERVAL_RE.search(lower)
        mode = "observe"
        if "autonomous" in lower:
            mode = "autonomous"
        elif "assist" in lower:
            mode = "assist"
        return AgentIntent(
            kind="soak",
            duration_minutes=int(minutes_match.group(1)) if minutes_match else None,
            playwright_interval_minutes=int(interval_match.group(1)) if interval_match else None,
            dry_run=("dry-run" in lower or "dry run" in lower),
            control_mode=mode,
        )

    if any(token in lower for token in ("live", "status", "health", "monitor once")):
        return AgentIntent(kind="live")

    if "what should" in lower or "next step" in lower or "what now" in lower:
        return AgentIntent(kind="recommend", target=None)

    return AgentIntent(kind="unknown")


def newest_soak_target(repo_root: Path | None = None) -> str | None:
    """Return newest logs_soak_* directory name or None."""
    resolved_repo_root = (repo_root or wicap_repo_root()).resolve()
    dirs = [path for path in resolved_repo_root.glob("logs_soak_*") if path.is_dir()]
    if not dirs:
        return None
    dirs.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
    return dirs[0].name


def _format_soak_summary(summary: dict[str, Any]) -> list[str]:
    lines = [
        (
            f"soak_run: run_id={summary.get('run_id')} "
            f"control_session_id={summary.get('control_session_id')} "
            f"exit_code={summary.get('exit_code')} control_mode={summary.get('control_mode')}"
        ),
        f"soak_run: newest_soak_dir={summary.get('newest_soak_dir')}",
        f"soak_run: incident_path={summary.get('incident_path')}",
        (
            "soak_run: metrics "
            f"observation_cycles={summary.get('observation_cycles')} "
            f"alert_cycles={summary.get('alert_cycles')} "
            f"down_service_cycles={summary.get('down_service_cycles')} "
            f"control_actions_executed={summary.get('control_actions_executed')} "
            f"control_escalations={summary.get('control_escalations')} "
            f"snapshot_count={summary.get('snapshot_count')} "
            f"escalation_hard_stop={summary.get('escalation_hard_stop')}"
        ),
    ]
    if summary.get("snapshot_dir"):
        lines.append(f"soak_run: snapshot_dir={summary.get('snapshot_dir')}")
    if summary.get("escalation_reason"):
        lines.append(f"soak_run: escalation_reason={summary.get('escalation_reason')}")
    guidance = summary.get("operator_guidance", [])
    if isinstance(guidance, list):
        for line in guidance[:5]:
            lines.append(f"guide: {line}")
    return lines


def _planned_next_action(observation: dict[str, Any]) -> str:
    recommended = observation.get("recommended", [])
    if isinstance(recommended, list):
        for item in recommended:
            if not isinstance(item, dict):
                continue
            safe_steps = item.get("safe_verify_steps", [])
            if isinstance(safe_steps, list) and safe_steps:
                return str(safe_steps[0])
            payload = item.get("recommendation", {})
            if isinstance(payload, dict):
                action = str(payload.get("recommended_action", "")).strip()
                if action and action != "insufficient historical evidence":
                    return action
    alert = str(observation.get("alert", "")).strip()
    if alert:
        return "Run `status` again in 10s and inspect live service/container state."
    return "Continue monitoring."


def _latest_control_session_summary(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        """
        SELECT id, status, current_phase, started_ts, ended_ts
        FROM control_sessions
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return "control_session: (none)"
    return (
        "control_session: "
        f"id={row['id']} status={row['status']} phase={row['current_phase']} "
        f"started={row['started_ts']} ended={row['ended_ts']}"
    )


def run_agent_console(
    conn: sqlite3.Connection,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    default_control_mode: str = "observe",
    default_observe_interval_seconds: float = 10.0,
    live_once_fn: Callable[[sqlite3.Connection], str] | None = None,
    soak_run_fn: Callable[..., dict[str, Any]] | None = None,
    recommend_fn: Callable[[sqlite3.Connection, str], dict[str, Any]] | None = None,
    incident_fn: Callable[[sqlite3.Connection, str], str] | None = None,
) -> int:
    """Run interactive deterministic agent console."""
    output_fn("WICAP Live Control Agent")
    output_fn("Type: status | start soak for 10 minutes assist/autonomous | recommend <target> | incident <target> | quit")
    guardian_state = GuardianState()
    guardian_playbooks = load_playbook_entries()

    def default_live_once(local_conn: sqlite3.Connection) -> str:
        observation = collect_live_cycle(local_conn)
        row_id = insert_live_observation(
            local_conn,
            ts=str(observation.get("ts", utc_now_iso())),
            service_status_json=observation.get("service_status", {}),
            top_signatures_json=observation.get("top_signatures", []),
            recommended_json=observation.get("recommended", []),
        )
        alerts = scan_guardian_once(
            local_conn,
            state=guardian_state,
            path_specs=None,
            playbooks=guardian_playbooks,
            start_at_end_for_new=True,
        )
        local_conn.commit()
        lines = [format_live_panel(observation), f"observation_id={row_id}"]
        lines.append(_latest_control_session_summary(local_conn))
        lines.append(f"planned_next_action={_planned_next_action(observation)}")
        lines.append(f"guardian_alerts={len(alerts)}")
        for alert in alerts[:2]:
            lines.append(format_guardian_alert_text(alert))
        return "\n".join(lines)

    def default_soak_run(local_conn: sqlite3.Connection, *, intent: AgentIntent) -> dict[str, Any]:
        def progress(event: dict[str, Any]) -> None:
            kind = str(event.get("event", "")).strip()
            if kind == "observe_cycle":
                output_fn(
                    f"[agent] cycle={event.get('cycle')} alert={event.get('alert')} "
                    f"down_services={len(event.get('down_services', [])) if isinstance(event.get('down_services'), list) else 0}"
                )
            elif kind == "control_event":
                output_fn(
                    f"[agent] control action={event.get('action')} status={event.get('status')}"
                )
            elif kind == "phase":
                output_fn(f"[agent] phase {event.get('phase')} -> {event.get('status')}")

        return run_supervised_soak(
            local_conn,
            duration_minutes=int(intent.duration_minutes) if intent.duration_minutes is not None else None,
            playwright_interval_minutes=(
                int(intent.playwright_interval_minutes)
                if intent.playwright_interval_minutes is not None
                else None
            ),
            baseline_path=None,
            baseline_update=None,
            dry_run=bool(intent.dry_run),
            managed_observe=True,
            observe_interval_seconds=float(default_observe_interval_seconds),
            control_mode=str(intent.control_mode or default_control_mode),
            progress_hook=progress,
        )

    live_once_impl = live_once_fn or default_live_once
    soak_run_impl = soak_run_fn or default_soak_run
    recommend_impl = recommend_fn or build_recommendation

    def default_incident(local_conn: sqlite3.Connection, target: str) -> str:
        bundle = build_bundle(local_conn, target)
        path = write_incident_report(local_conn, target=target, bundle=bundle, overwrite=True)
        local_conn.commit()
        return str(path)

    incident_impl = incident_fn or default_incident

    while True:
        try:
            prompt = input_fn("wicap-agent> ")
        except EOFError:
            output_fn("agent: exit")
            return 0

        intent = parse_agent_prompt(prompt)
        if intent.kind == "quit":
            output_fn("agent: exit")
            return 0
        if intent.kind == "help":
            output_fn("agent help:")
            output_fn("- status")
            output_fn("- start soak for 10 minutes assist")
            output_fn("- start soak dry-run")
            output_fn("- recommend <logs_soak_dir|signature>")
            output_fn("- incident <logs_soak_dir|file>")
            output_fn("- quit")
            continue
        if intent.kind == "live":
            output_fn(live_once_impl(conn))
            continue
        if intent.kind == "soak":
            if intent.control_mode not in {"observe", "assist", "autonomous"}:
                intent.control_mode = default_control_mode
            summary = soak_run_impl(conn, intent=intent)
            if not intent.dry_run:
                conn.commit()
            for line in _format_soak_summary(summary):
                output_fn(line)
            continue
        if intent.kind == "recommend":
            target = intent.target or newest_soak_target()
            if not target:
                output_fn("agent: no target available. provide one explicitly.")
                continue
            payload = recommend_impl(conn, target)
            output_fn(f"recommend: target={target}")
            output_fn(f"recommend: action={payload.get('recommended_action')}")
            output_fn(f"recommend: confidence={payload.get('confidence')}")
            guidance = payload.get("verification_priority", [])
            if isinstance(guidance, list):
                for step in guidance[:3]:
                    output_fn(f"verify: {step}")
            continue
        if intent.kind == "incident":
            target = intent.target or newest_soak_target()
            if not target:
                output_fn("agent: no incident target available. provide one explicitly.")
                continue
            path = incident_impl(conn, target)
            output_fn(f"incident: target={target}")
            output_fn(f"incident: path={path}")
            continue

        output_fn("agent: unrecognized prompt. type 'help' for supported prompts.")
