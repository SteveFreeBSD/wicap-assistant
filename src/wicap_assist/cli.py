"""CLI entrypoint for wicap-assistant."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from wicap_assist.backfill_report import (
    backfill_report_to_json,
    format_backfill_report_text,
    generate_backfill_report,
)
from wicap_assist.agent_console import run_agent_console
from wicap_assist.autopilot import run_autopilot_supervisor
from wicap_assist.bundle import build_bundle, bundle_to_json, format_bundle_text
from wicap_assist.changelog_stats import collect_changelog_stats, format_changelog_stats_text
from wicap_assist.daily_report import (
    daily_report_to_json,
    format_daily_report_text,
    generate_daily_report,
)
from wicap_assist.confidence_audit import (
    confidence_audit_to_json,
    format_confidence_audit_text,
    run_confidence_audit,
)
from wicap_assist.control_center import (
    build_control_center_snapshot,
    control_center_to_json,
    format_control_center_text,
)
from wicap_assist.db import (
    DEFAULT_DB_PATH,
    connect_db,
    finish_ingest,
    insert_session,
    insert_signal,
    search_signals,
    start_ingest,
    upsert_source,
)
from wicap_assist.fix_lineage import (
    fix_lineage_to_json,
    format_fix_lineage_text,
    resolve_fix_lineage,
)
from wicap_assist.failover_profiles import failover_state_snapshot
from wicap_assist.forecast import (
    forecast_to_json,
    format_forecast_text,
    summarize_forecasts,
)
from wicap_assist.ingest.codex_jsonl import parse_codex_file, scan_codex_paths, source_kind_for
from wicap_assist.ingest.harness_scripts import ingest_harness_scripts
from wicap_assist.ingest.network_events import ingest_network_events
from wicap_assist.ingest.soak_logs import ingest_soak_logs
from wicap_assist.ingest.antigravity_logs import ingest_antigravity_logs
from wicap_assist.ingest.changelog import ingest_changelog
from wicap_assist.cross_pattern import (
    chronic_patterns_to_json,
    detect_chronic_patterns,
    format_chronic_patterns_text,
)
from wicap_assist.incident import load_bundle_json, write_incident_report
from wicap_assist.live import run_live_monitor
from wicap_assist.memory_maintenance import run_memory_maintenance, write_memory_maintenance_report
from wicap_assist.mission_graph import mission_graph_snapshot
from wicap_assist.guardian import run_guardian
from wicap_assist.playbooks import generate_playbooks
from wicap_assist.policy_explain import (
    collect_policy_explain,
    collect_sandbox_explain,
    format_policy_explain_text,
    policy_explain_to_json,
)
from wicap_assist.recommend import build_recommendation, recommendation_to_json
from wicap_assist.certification import certification_history, run_chaos_certification, run_replay_certification
from wicap_assist.rollout_gates import evaluate_rollout_gates
from wicap_assist.rollout_gates import (
    append_rollout_gate_history,
    evaluate_promotion_readiness,
    load_rollout_gate_history,
)
from wicap_assist.runtime_contract import (
    evaluate_runtime_contract_report,
    format_runtime_contract_report_text,
    run_runtime_contract_check,
    runtime_contract_report_to_json,
)
from wicap_assist.rollup import format_rollup_text, generate_rollup, rollup_to_json
from wicap_assist.scheduler_runtime import run_scheduler_loop
from wicap_assist.soak_run import run_supervised_soak
from wicap_assist.settings import wicap_repo_root
from wicap_assist.wicap_env_setup import SetupAbortedError, run_wicap_env_setup, validate_wicap_env
from wicap_assist.util.time import utc_now_iso


def _normalize_control_mode(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "monitor":
        return "observe"
    if normalized in {"observe", "assist", "autonomous"}:
        return normalized
    raise ValueError(f"invalid control mode: {value}")


def _run_ingest(
    db_path: Path,
    *,
    scan_codex: bool,
    scan_soaks: bool,
    scan_harness: bool,
    scan_antigravity: bool,
    scan_changelog: bool,
    scan_network_events: bool = False,
) -> int:
    conn = connect_db(db_path)
    started_ts = utc_now_iso()
    ingest_id = start_ingest(conn, started_ts)

    files_seen = 0
    sessions_added = 0
    signals_added = 0
    log_events_added = 0
    conversations_added = 0
    conversation_signals_added = 0
    verification_outcomes_added = 0
    changelog_entries_added = 0
    changelog_entries_total = 0
    changelog_sources_seen = 0
    network_events_added = 0
    harness_summary = None

    if scan_codex:
        files = scan_codex_paths()
        files_seen += len(files)
        for source_path in files:
            stat = source_path.stat()
            source_id = upsert_source(
                conn,
                kind=source_kind_for(source_path),
                path=str(source_path),
                mtime=stat.st_mtime,
                size=stat.st_size,
            )

            for session in parse_codex_file(source_path):
                if not session.is_wicap:
                    continue

                session_pk, inserted = insert_session(
                    conn,
                    source_id=source_id,
                    session_id=session.session_id,
                    cwd=session.cwd,
                    ts_first=session.ts_first,
                    ts_last=session.ts_last,
                    repo_url=session.repo_url,
                    branch=session.branch,
                    commit_hash=session.commit_hash,
                    is_wicap=session.is_wicap,
                    raw_path=session.raw_path,
                )
                if inserted:
                    sessions_added += 1

                for signal in session.signals:
                    inserted_signal = insert_signal(
                        conn,
                        session_pk=session_pk,
                        ts=signal.ts,
                        category=signal.category,
                        fingerprint=signal.fingerprint,
                        snippet=signal.snippet,
                        extra_json=signal.extra,
                    )
                    if inserted_signal:
                        signals_added += 1

    if scan_soaks:
        soak_files_seen, soak_events_added = ingest_soak_logs(conn)
        files_seen += soak_files_seen
        log_events_added += soak_events_added

    if scan_harness:
        harness_files_seen, harness_summary = ingest_harness_scripts(conn)
        files_seen += harness_files_seen

    if scan_network_events:
        network_files_seen, network_events_added = ingest_network_events(conn)
        files_seen += network_files_seen

    if scan_antigravity:
        ag_dirs, ag_convs, ag_signals, ag_outcomes = ingest_antigravity_logs(conn)
        files_seen += ag_dirs
        conversations_added += ag_convs
        conversation_signals_added += ag_signals
        verification_outcomes_added += ag_outcomes

    if scan_changelog:
        cl_files, cl_entries = ingest_changelog(conn)
        files_seen += cl_files
        changelog_entries_added += cl_entries

    finished_ts = utc_now_iso()
    finish_ingest(
        conn,
        ingest_id,
        finished_ts=finished_ts,
        files_seen=files_seen,
        sessions_added=sessions_added,
        signals_added=signals_added + log_events_added,
    )

    if scan_changelog:
        row = conn.execute("SELECT count(*) AS cnt FROM changelog_entries").fetchone()
        changelog_entries_total = int(row["cnt"]) if row is not None else 0
        src_row = conn.execute("SELECT count(*) AS cnt FROM sources WHERE kind = 'changelog'").fetchone()
        changelog_sources_seen = int(src_row["cnt"]) if src_row is not None else 0

    conn.commit()
    conn.close()

    print(
        f"Ingest complete: files_seen={files_seen} "
        f"sessions_added={sessions_added} signals_added={signals_added} "
        f"log_events_added={log_events_added} network_events_added={network_events_added} db={db_path}"
    )
    if scan_antigravity:
        print(
            "Antigravity: "
            f"conversations_added={conversations_added} "
            f"conversation_signals_added={conversation_signals_added} "
            f"verification_outcomes_added={verification_outcomes_added} "
            f"changelog_entries_added={changelog_entries_added}"
        )
    if scan_harness and harness_summary is not None:
        print(f"Harness scripts: total={harness_summary.total_scripts}")
        print("Harness roles:")
        if harness_summary.roles:
            for role, count in harness_summary.roles.items():
                print(f"- {role}: {count}")
        else:
            print("- (none)")

        print("Top referenced commands:")
        if harness_summary.top_commands:
            for command, count in harness_summary.top_commands:
                print(f"- {count}x {command}")
        else:
            print("- (none)")
    if scan_changelog:
        print(
            "Changelog: "
            f"entries_added={changelog_entries_added} "
            f"entries_total={changelog_entries_total} "
            f"sources_seen={changelog_sources_seen}"
        )
    return 0


def _run_triage(db_path: Path, query: str, top_sessions: int, per_category: int, limit: int) -> int:
    conn = connect_db(db_path)
    rows = search_signals(conn, query=query, limit=limit)
    conn.close()

    if not rows:
        print("No matches found.")
        return 0

    grouped: dict[int, dict[str, object]] = {}
    for row in rows:
        session_pk = int(row["session_pk"])
        bucket = grouped.setdefault(
            session_pk,
            {
                "session_id": row["session_id"],
                "cwd": row["cwd"],
                "ts_last": row["ts_last"],
                "repo_url": row["repo_url"],
                "branch": row["branch"],
                "commit_hash": row["commit_hash"],
                "raw_path": row["raw_path"],
                "by_category": defaultdict(list),
                "count": 0,
            },
        )
        category_map = bucket["by_category"]
        assert isinstance(category_map, defaultdict)
        category_map[row["category"]].append(
            {
                "snippet": row["snippet"],
                "fingerprint": row["fingerprint"],
            }
        )
        bucket["count"] = int(bucket["count"]) + 1

    ordered = sorted(grouped.values(), key=lambda item: int(item["count"]), reverse=True)

    print(f"Query: {query}")
    for idx, session in enumerate(ordered[:top_sessions], start=1):
        print(
            f"\n{idx}. session_id={session['session_id']} ts_last={session['ts_last']} "
            f"cwd={session['cwd']}"
        )
        print(
            f"   repo={session['repo_url']} branch={session['branch']} "
            f"commit={session['commit_hash']}"
        )
        print(f"   source={session['raw_path']}")

        category_map = session["by_category"]
        assert isinstance(category_map, defaultdict)
        for category in ("errors", "commands", "file_paths", "outcomes"):
            entries = category_map.get(category, [])
            if not entries:
                continue
            print(f"   {category}:")
            for entry in entries[:per_category]:
                print(f"   - {entry['snippet']} [{entry['fingerprint'][:10]}]")

    return 0


def _run_changelog_stats(db_path: Path) -> int:
    conn = connect_db(db_path)
    try:
        stats = collect_changelog_stats(conn)
    finally:
        conn.close()
    print(format_changelog_stats_text(stats))
    return 0


def _run_contract_check(
    *,
    contract_path: Path | None,
    as_json: bool,
    enforce: bool,
    require_scout: bool,
) -> int:
    raw_report = run_runtime_contract_check(contract_path=contract_path)
    effective_ok, eval_detail = evaluate_runtime_contract_report(
        raw_report,
        require_scout=bool(require_scout),
    )
    report = dict(raw_report)
    report["raw_status"] = str(raw_report.get("status"))
    report["runtime_contract_require_scout"] = bool(require_scout)
    report["runtime_contract_eval"] = eval_detail
    if effective_ok:
        report["status"] = "pass"
    if as_json:
        print(runtime_contract_report_to_json(report))
    else:
        print(format_runtime_contract_report_text(report))
    if enforce and not bool(effective_ok):
        return 2
    return 0


def _run_soak_run(
    db_path: Path,
    *,
    duration_minutes: int | None,
    playwright_interval_minutes: int | None,
    baseline_path: Path | None,
    baseline_update: bool | None,
    dry_run: bool,
    observe_interval_seconds: float,
    control_mode: str,
    control_check_threshold: int | None,
    control_recover_threshold: int | None,
    control_max_recover_attempts: int | None,
    control_action_cooldown_cycles: int | None,
    stop_on_escalation: bool,
    require_runtime_contract: bool,
    runtime_contract_path: Path | None,
) -> int:
    normalized_control_mode = _normalize_control_mode(control_mode)
    contract_report = run_runtime_contract_check(contract_path=runtime_contract_path)
    print(
        "[soak-run] runtime_contract "
        f"status={contract_report.get('status')} "
        f"version={contract_report.get('contract_version')} "
        f"path={contract_report.get('contract_path')}",
        flush=True,
    )
    if bool(require_runtime_contract) and str(contract_report.get("status")) != "pass":
        print(
            "[soak-run][guide] Runtime contract gate failed; refusing to start soak.",
            flush=True,
        )
        return 2

    def _progress(event: dict[str, object]) -> None:
        kind = str(event.get("event", "")).strip()
        if not kind:
            return

        if kind == "phase":
            print(
                f"[soak-run] phase={event.get('phase')} status={event.get('status')} ts={event.get('ts')}",
                flush=True,
            )
            return

        if kind == "runner_start":
            print(
                f"[soak-run] runner_start timeout_seconds={event.get('timeout_seconds')} "
                f"managed_observe={event.get('managed_observe')}",
                flush=True,
            )
            return

        if kind == "observe_cycle":
            cycle = event.get("cycle")
            alert = bool(event.get("alert"))
            down_services = event.get("down_services", [])
            top_signature = str(event.get("top_signature", "")).strip()
            top_piece = f" top_signature={top_signature}" if top_signature else ""
            print(
                f"[soak-run] observe cycle={cycle} alert={alert} down_services={len(down_services) if isinstance(down_services, list) else 0}{top_piece}",
                flush=True,
            )
            return

        if kind == "run_complete":
            print(
                f"[soak-run] run_complete run_id={event.get('run_id')} "
                f"control_session_id={event.get('control_session_id')} "
                f"exit_code={event.get('exit_code')}",
                flush=True,
            )
            return

        if kind == "escalation_stop":
            print(
                f"[soak-run] escalation_stop cycle={event.get('cycle')} reason={event.get('reason')}",
                flush=True,
            )
            print(
                "[soak-run][guide] Escalation hard-stop triggered; inspect runner log and latest snapshot pack.",
                flush=True,
            )
            return

        if kind == "dry_run_plan":
            phases = event.get("phase_plan", [])
            phase_text = " -> ".join(str(value) for value in phases) if isinstance(phases, list) else ""
            print(f"[soak-run] dry_run_plan phases={phase_text}", flush=True)
            return

        if kind == "control_event":
            action = str(event.get("action", "")).strip()
            status = str(event.get("status", "")).strip()
            service = event.get("service")
            svc = f" service={service}" if service else ""
            print(
                f"[soak-run] control decision={event.get('decision')} action={action or None} status={status}{svc}",
                flush=True,
            )
            guidance = ""
            if action == "status_check" and status == "executed_ok":
                guidance = "Status check passed; continue observing service health."
            elif action == "status_check" and status in {"executed_fail", "missing_script"}:
                guidance = "Status check failed; inspect runner log and check_wicap_status output."
            elif action == "compose_up" and status == "executed_ok":
                guidance = "Compose recovery succeeded; verify services stay up in next cycles."
            elif action == "compose_up" and status == "executed_fail":
                guidance = "Compose recovery failed; inspect docker compose logs."
            elif action.startswith("restart_service:") and status == "executed_ok":
                guidance = "Service restart succeeded; verify service health in next cycles."
            elif action.startswith("restart_service:") and status == "executed_fail":
                guidance = "Service restart failed; inspect docker compose logs."
            elif action == "rollback_sequence" and status == "executed_ok":
                guidance = "Rollback sequence completed; verify services stabilize in subsequent cycles."
            elif action == "rollback_sequence" and status in {"executed_fail", "escalated"}:
                guidance = "Rollback sequence failed; manual operator intervention required."
            elif status == "down_detected":
                guidance = "Service degradation detected; waiting control thresholds for action."
            elif status == "stable":
                guidance = "Services stable; continue monitoring."
            elif status == "escalated":
                guidance = "Service recovery escalated; immediate operator intervention required."
            elif status == "cooldown":
                guidance = "Control policy cooldown active; re-evaluating next cycle."
            elif status == "skipped_observe_mode":
                guidance = "Observe mode skipped recovery action; use --control-mode assist/autonomous to execute it."
            if guidance:
                print(f"[soak-run][guide] {guidance}", flush=True)
            return

    conn = connect_db(db_path)
    try:
        summary = run_supervised_soak(
            conn,
            duration_minutes=duration_minutes,
            playwright_interval_minutes=playwright_interval_minutes,
            baseline_path=baseline_path,
            baseline_update=baseline_update,
            dry_run=dry_run,
            managed_observe=True,
            observe_interval_seconds=observe_interval_seconds,
            control_mode=normalized_control_mode,
            control_check_threshold=control_check_threshold,
            control_recover_threshold=control_recover_threshold,
            control_max_recover_attempts=control_max_recover_attempts,
            control_action_cooldown_cycles=control_action_cooldown_cycles,
            stop_on_escalation=bool(stop_on_escalation),
            progress_hook=_progress,
        )
        if not dry_run:
            conn.commit()
    finally:
        conn.close()

    if dry_run:
        print("Soak run dry-run")
        print(f"runner_path={summary['runner_path']}")
        if summary.get("learned_profile"):
            learned = summary["learned_profile"]
            print(
                "learned_profile="
                f"score={learned.get('score')} "
                f"evidence_count={learned.get('evidence_count')} "
                f"success_count={learned.get('success_count')} "
                f"fail_count={learned.get('fail_count')}"
            )
        print(f"command={' '.join(summary['command'])}")
        print(f"timeout_seconds={summary['timeout_seconds']}")
        print(f"managed_observe={summary.get('managed_observe')}")
        print(f"observe_interval_seconds={summary.get('observe_interval_seconds')}")
        print(f"control_mode={summary.get('control_mode')}")
        print(f"control_policy_profile={summary.get('control_policy_profile')}")
        print(f"control_kill_switch_env_var={summary.get('control_kill_switch_env_var')}")
        print(f"control_kill_switch_file={summary.get('control_kill_switch_file')}")
        print(f"control_rollback_enabled={summary.get('control_rollback_enabled')}")
        print(f"stop_on_escalation={summary.get('stop_on_escalation')}")
        print(f"post_run_cleanup={summary.get('post_run_cleanup')}")
        phase_plan = summary.get("phase_plan", [])
        if isinstance(phase_plan, list) and phase_plan:
            print("phase_plan=" + " -> ".join(str(value) for value in phase_plan))
        learning = summary.get("learning_readiness", {})
        if isinstance(learning, dict) and learning:
            print(
                "learning_readiness="
                f"status={learning.get('status')} "
                f"score={learning.get('score')}/{learning.get('max_score')} "
                f"profile_success_count={learning.get('profile_success_count')} "
                f"runbook_steps_count={learning.get('runbook_steps_count')}"
            )
        print(
            "effective_args="
            f"duration_minutes={summary.get('effective_duration_minutes')} "
            f"playwright_interval_minutes={summary.get('effective_playwright_interval_minutes')}"
        )
        runbook = summary.get("learned_runbook", {})
        if isinstance(runbook, dict):
            print(
                "learned_runbook="
                f"success_session_count={runbook.get('success_session_count', 0)} "
                f"steps={len(runbook.get('steps', [])) if isinstance(runbook.get('steps'), list) else 0}"
            )
            steps = runbook.get("steps", [])
            if isinstance(steps, list):
                for step in steps[:5]:
                    print(f"runbook_step={step}")
        actions = summary.get("manager_actions", [])
        if isinstance(actions, list):
            for action in actions[:8]:
                print(f"manager_action={action}")
        guidance = summary.get("operator_guidance", [])
        if isinstance(guidance, list):
            for line in guidance[:8]:
                print(f"operator_guidance={line}")
        print(f"snapshot_count={summary.get('snapshot_count')}")
        print(f"snapshot_dir={summary.get('snapshot_dir')}")
        print(f"run_dir={summary['run_dir']}")
        print(f"runner_log={summary['runner_log']}")
        print("post_steps=ingest --scan-soaks, incident <newest logs_soak_*> --overwrite")
        print(f"newest_soak_dir_now={summary['newest_soak_dir']}")
        return 0

    print(
        "Soak run complete: "
        f"run_id={summary['run_id']} "
        f"control_session_id={summary.get('control_session_id')} "
        f"exit_code={summary['exit_code']} "
        f"newest_soak_dir={summary['newest_soak_dir']} "
        f"incident_path={summary['incident_path']}"
    )
    print(
        "Soak run live metrics: "
        f"observation_cycles={summary.get('observation_cycles')} "
        f"alert_cycles={summary.get('alert_cycles')} "
        f"down_service_cycles={summary.get('down_service_cycles')} "
        f"control_policy_profile={summary.get('control_policy_profile')} "
        f"control_actions_executed={summary.get('control_actions_executed')} "
        f"control_escalations={summary.get('control_escalations')} "
        f"snapshot_count={summary.get('snapshot_count')} "
        f"escalation_hard_stop={summary.get('escalation_hard_stop')} "
        f"cleanup_status={summary.get('cleanup_status')}"
    )
    if summary.get("escalation_reason"):
        print(f"Soak run escalation reason: {summary.get('escalation_reason')}")
    if summary.get("snapshot_dir"):
        print(f"Soak run snapshot dir: {summary.get('snapshot_dir')}")
    learning = summary.get("learning_readiness", {})
    if isinstance(learning, dict) and learning:
        print(
            "Soak run learning readiness: "
            f"status={learning.get('status')} "
            f"score={learning.get('score')}/{learning.get('max_score')} "
            f"startup_step={learning.get('has_startup_step')} "
            f"verify_step={learning.get('has_verify_step')}"
        )
    phase_trace = summary.get("phase_trace", [])
    if isinstance(phase_trace, list) and phase_trace:
        compact = ", ".join(
            f"{item.get('phase')}:{item.get('status')}"
            for item in phase_trace
            if isinstance(item, dict)
        )
        print(f"Soak run phases: {compact}")
    runbook = summary.get("learned_runbook", {})
    if isinstance(runbook, dict):
        print(
            "Soak run learned runbook: "
            f"success_session_count={runbook.get('success_session_count', 0)} "
            f"steps={len(runbook.get('steps', [])) if isinstance(runbook.get('steps'), list) else 0}"
        )
    actions = summary.get("manager_actions", [])
    if isinstance(actions, list) and actions:
        print("Soak run manager actions:")
        for action in actions[:8]:
            print(f"- {action}")
    guidance = summary.get("operator_guidance", [])
    if isinstance(guidance, list) and guidance:
        print("Soak run operator guidance:")
        for line in guidance[:8]:
            print(f"- {line}")
    return 0


def _run_agent(
    db_path: Path,
    *,
    control_mode: str,
    observe_interval_seconds: float,
) -> int:
    normalized_control_mode = _normalize_control_mode(control_mode)
    conn = connect_db(db_path)
    try:
        return run_agent_console(
            conn,
            default_control_mode=str(normalized_control_mode),
            default_observe_interval_seconds=float(observe_interval_seconds),
        )
    finally:
        conn.close()


def _run_agent_explain_policy(*, as_json: bool) -> int:
    payload = collect_policy_explain(repo_root=wicap_repo_root())
    if as_json:
        print(policy_explain_to_json(payload))
    else:
        print(format_policy_explain_text(payload))
    return 0


def _run_agent_sandbox_explain(
    *,
    action: str,
    mode: str,
    as_json: bool,
) -> int:
    payload = collect_sandbox_explain(
        action=str(action).strip(),
        mode=_normalize_control_mode(str(mode)),
    )
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        trace = payload.get("policy_trace", {})
        if not isinstance(trace, dict):
            trace = {}
        print(
            "sandbox_explain: "
            f"action={payload.get('action')} mode={payload.get('mode')} "
            f"allowed={payload.get('allowed')} denied_by={payload.get('denied_by')}"
        )
        print(f"reason: {payload.get('reason') or '(none)'}")
        print(
            "budget: "
            f"actions={trace.get('budget_state', {}).get('action_budget_used')}/"
            f"{trace.get('budget_state', {}).get('action_budget_max')} "
            f"elevated={trace.get('budget_state', {}).get('elevated_action_budget_used')}/"
            f"{trace.get('budget_state', {}).get('elevated_action_budget_max')}"
        )
        deny_reasons = trace.get("deny_reasons", [])
        if isinstance(deny_reasons, list):
            for reason in deny_reasons:
                print(f"- deny: {reason}")
    return 0


def _run_agent_forecast(
    db_path: Path,
    *,
    lookback_hours: int,
    as_json: bool,
) -> int:
    conn = connect_db(db_path)
    try:
        payload = summarize_forecasts(
            conn,
            lookback_hours=max(1, int(lookback_hours)),
        )
    finally:
        conn.close()
    if as_json:
        print(forecast_to_json(payload))
    else:
        print(format_forecast_text(payload))
    return 0


def _run_agent_control_center(
    db_path: Path,
    *,
    control_mode: str,
    lookback_hours: int,
    as_json: bool,
) -> int:
    conn = connect_db(db_path)
    try:
        payload = build_control_center_snapshot(
            conn,
            mode=str(control_mode),
            repo_root=wicap_repo_root(),
            forecast_lookback_hours=max(1, int(lookback_hours)),
        )
    finally:
        conn.close()
    if as_json:
        print(control_center_to_json(payload))
    else:
        print(format_control_center_text(payload))
    return 0


def _run_agent_failover_state(
    db_path: Path,
    *,
    as_json: bool,
) -> int:
    conn = connect_db(db_path)
    try:
        payload = failover_state_snapshot(conn)
        payload["history"] = certification_history(conn, cert_type=None).get("rows", [])[:5]
    finally:
        conn.close()
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            "failover_state: "
            f"profile={payload.get('auth_profile')} attempt={payload.get('attempt')} "
            f"class={payload.get('failure_class')} cooldown_until={payload.get('cooldown_until')}"
        )
    return 0


def _run_agent_mission_graph(
    db_path: Path,
    *,
    run_id: int,
    as_json: bool,
) -> int:
    conn = connect_db(db_path)
    try:
        payload = mission_graph_snapshot(conn, run_id=f"soak-{int(run_id)}")
    finally:
        conn.close()
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            "mission_graph: "
            f"run_id={payload.get('run_id')} found={payload.get('found')} "
            f"steps={len(payload.get('steps', [])) if isinstance(payload.get('steps'), list) else 0}"
        )
    return 0


def _run_agent_replay_certify(
    db_path: Path,
    *,
    profile: str,
    as_json: bool,
) -> int:
    conn = connect_db(db_path)
    try:
        payload = run_replay_certification(conn, profile=str(profile))
        conn.commit()
    finally:
        conn.close()
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            "replay_certify: "
            f"profile={payload.get('profile')} pass={payload.get('pass')} "
            f"score={payload.get('score')} samples={payload.get('sample_count')}"
        )
    return 0 if bool(payload.get("pass")) else 2


def _run_agent_chaos_certify(
    db_path: Path,
    *,
    profile: str,
    as_json: bool,
) -> int:
    conn = connect_db(db_path)
    try:
        payload = run_chaos_certification(conn, profile=str(profile))
        conn.commit()
    finally:
        conn.close()
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            "chaos_certify: "
            f"profile={payload.get('profile')} pass={payload.get('pass')} "
            f"score={payload.get('score')} degraded_rate={payload.get('degraded_rate')}"
        )
    return 0 if bool(payload.get("pass")) else 2


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(prog="wicap-assist")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")

    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Ingest Codex/soak logs into SQLite")
    ingest_parser.add_argument("--scan-codex", action="store_true", help="Scan configured Codex paths")
    ingest_parser.add_argument("--scan-soaks", action="store_true", help="Scan WICAP soak log paths")
    ingest_parser.add_argument("--scan-harness", action="store_true", help="Scan WICAP harness scripts")
    ingest_parser.add_argument(
        "--scan-network-events",
        action="store_true",
        help="Scan WiCAP network event contract artifacts (wicap.event.v1 JSONL)",
    )
    ingest_parser.add_argument("--scan-antigravity", action="store_true", help="Scan Antigravity conversation artifacts")
    ingest_parser.add_argument("--scan-changelog", action="store_true", help="Scan WICAP CHANGELOG.md")

    setup_env_parser = subparsers.add_parser(
        "setup-wicap-env",
        help="Interactive WiCAP .env bootstrap for fresh systems",
    )
    setup_env_parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Override WiCAP repo root (default: WICAP_REPO_ROOT or auto-discovered /wicap, ../wicap, ~/apps/wicap)",
    )
    setup_env_parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Override target .env path (default: <repo-root>/.env)",
    )
    setup_env_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip final confirmation prompt and write immediately",
    )
    setup_env_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render planned .env content without writing the file",
    )
    setup_env_parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create timestamped .env backup before overwriting",
    )

    validate_env_parser = subparsers.add_parser(
        "validate-wicap-env",
        help="Validate WiCAP .env safety/readiness before runtime startup",
    )
    validate_env_parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Override WiCAP repo root (default: WICAP_REPO_ROOT or auto-discovered)",
    )
    validate_env_parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Override target .env path (default: <repo-root>/.env)",
    )
    validate_env_parser.add_argument(
        "--no-live-probe",
        action="store_true",
        help="Skip live UI TCP/internal emit probes (static config validation only)",
    )
    validate_env_parser.add_argument(
        "--require-live",
        action="store_true",
        help="Treat live probe failures as hard errors (exit non-zero)",
    )
    validate_env_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON validation report",
    )

    triage_parser = subparsers.add_parser("triage", help="Search stored signals")
    triage_parser.add_argument("query", help="Search phrase")
    triage_parser.add_argument("--top-sessions", type=int, default=5)
    triage_parser.add_argument("--per-category", type=int, default=3)
    triage_parser.add_argument("--limit", type=int, default=200)

    bundle_parser = subparsers.add_parser("bundle", help="Correlate soak logs with Codex sessions")
    bundle_parser.add_argument("target", help="Soak dir, log filename, or full WICAP log path")
    bundle_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON bundle")

    incident_parser = subparsers.add_parser("incident", help="Generate markdown incident report from bundle")
    incident_parser.add_argument("target", help="Soak dir, log filename, or full WICAP log path")
    incident_parser.add_argument("--json-input", type=Path, dest="json_input", help="Use existing bundle JSON")
    incident_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing report file")

    playbooks_parser = subparsers.add_parser("playbooks", help="Generate repair playbooks from recurring failures")
    playbooks_parser.add_argument("--top", type=int, default=5, help="Number of top clusters to generate")

    daily_parser = subparsers.add_parser(
        "daily-report",
        help="Detect upward-trending soak failures over recent days",
    )
    daily_parser.add_argument("--days", type=int, default=3, help="Days per comparison window")
    daily_parser.add_argument("--top", type=int, default=10, help="Max signatures to output")
    daily_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON report")

    guardian_parser = subparsers.add_parser("guardian", help="Monitor soak logs and alert on known signatures")
    guardian_parser.add_argument(
        "--path",
        action="append",
        help="Log file, directory, or glob to monitor (repeatable)",
    )
    guardian_parser.add_argument("--interval", type=float, default=10.0, help="Polling interval in seconds")
    guardian_parser.add_argument("--once", action="store_true", help="Run one scan and exit")
    guardian_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON alerts")

    recommend_parser = subparsers.add_parser("recommend", help="Generate deterministic historical recommendation")
    recommend_parser.add_argument("target", help="Incident id or normalized failure signature")

    rollup_parser = subparsers.add_parser("rollup", help="Roll up recurring failures across incidents")
    rollup_parser.add_argument("--days", type=int, default=30, help="Lookback window in days")
    rollup_parser.add_argument("--top", type=int, default=10, help="Max signatures to output")
    rollup_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    subparsers.add_parser("changelog-stats", help="Print deterministic changelog ingest statistics")

    contract_parser = subparsers.add_parser(
        "contract-check",
        help="Validate live WICAP runtime against versioned runtime contract",
    )
    contract_parser.add_argument(
        "--contract-path",
        type=Path,
        default=None,
        help="Override runtime contract JSON path (default: <WICAP_REPO_ROOT>/ops/runtime-contract.v1.json)",
    )
    contract_parser.add_argument(
        "--require-scout",
        dest="require_scout",
        action="store_true",
        help="Treat wicap-scout as required in runtime contract evaluation (default)",
    )
    contract_parser.add_argument(
        "--allow-scout-down",
        dest="require_scout",
        action="store_false",
        help="Allow runtime contract pass when only wicap-scout is down",
    )
    contract_parser.set_defaults(require_scout=True)
    contract_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    contract_gate_group = contract_parser.add_mutually_exclusive_group()
    contract_gate_group.add_argument(
        "--enforce",
        dest="enforce",
        action="store_true",
        help="Exit non-zero when contract check does not pass",
    )
    contract_gate_group.add_argument(
        "--no-enforce",
        dest="enforce",
        action="store_false",
        help="Always exit zero (informational mode)",
    )
    contract_parser.set_defaults(enforce=True)

    cross_parser = subparsers.add_parser("cross-patterns", help="Detect chronic recurring failure patterns")
    cross_parser.add_argument("--min-occurrences", type=int, default=3, help="Minimum source count")
    cross_parser.add_argument("--min-span-days", type=float, default=7.0, help="Minimum time span in days")
    cross_parser.add_argument("--top", type=int, default=20, help="Max patterns to output")
    cross_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    backfill_parser = subparsers.add_parser("backfill-report", help="Show data completeness metrics")
    backfill_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    fix_lineage_parser = subparsers.add_parser("fix-lineage", help="Trace resolution history for a signature")
    fix_lineage_parser.add_argument("signature", help="Failure signature to trace")
    fix_lineage_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    audit_parser = subparsers.add_parser("confidence-audit", help="Audit confidence score distribution")
    audit_parser.add_argument("--limit", type=int, default=100, help="Number of patterns to analyze")
    audit_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    maintenance_parser = subparsers.add_parser(
        "memory-maintenance",
        help="Run deterministic memory maintenance/reflection job",
    )
    maintenance_parser.add_argument("--lookback-days", type=int, default=14, help="Decision lookback window")
    maintenance_parser.add_argument("--stale-days", type=int, default=7, help="Working-memory stale threshold")
    maintenance_parser.add_argument("--max-decision-rows", type=int, default=5000, help="Decision rows scan cap")
    maintenance_parser.add_argument("--max-session-rows", type=int, default=500, help="Control session scan cap")
    maintenance_parser.add_argument(
        "--max-recent-transitions",
        type=int,
        default=24,
        help="Compaction target for per-session working-memory transition history",
    )
    maintenance_parser.add_argument(
        "--prune-stale",
        action="store_true",
        help="Clear unresolved/pending working-memory state for stale ended sessions",
    )
    maintenance_parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/reports/memory_maintenance_latest.json"),
        help="Write JSON maintenance report to this path",
    )
    maintenance_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    scheduler_parser = subparsers.add_parser(
        "scheduler",
        help="Run lease-guarded heartbeat + cron loop for live control and maintenance",
    )
    scheduler_parser.add_argument(
        "--owner",
        default=None,
        help="Lease owner id (default: <hostname>:<pid>)",
    )
    scheduler_parser.add_argument(
        "--lock-dir",
        type=Path,
        default=Path("data/locks"),
        help="Directory for scheduler lease lock files",
    )
    scheduler_parser.add_argument(
        "--state-path",
        type=Path,
        default=None,
        help="Scheduler state JSON path (default: <lock-dir>/scheduler_state.json)",
    )
    scheduler_parser.add_argument(
        "--control-mode",
        choices=("monitor", "observe", "assist", "autonomous"),
        default="observe",
        help="Heartbeat control mode (monitor aliases observe)",
    )
    scheduler_parser.add_argument(
        "--heartbeat-interval-seconds",
        type=float,
        default=10.0,
        help="Heartbeat loop interval in seconds",
    )
    scheduler_parser.add_argument(
        "--heartbeat-lease-seconds",
        type=int,
        default=20,
        help="Heartbeat lease duration in seconds",
    )
    scheduler_parser.add_argument(
        "--memory-maintenance-interval-seconds",
        type=int,
        default=900,
        help="Cron interval for memory maintenance",
    )
    scheduler_parser.add_argument(
        "--rollout-gates-interval-seconds",
        type=int,
        default=300,
        help="Cron interval for rollout gate snapshots",
    )
    scheduler_parser.add_argument(
        "--rollout-history-file",
        type=Path,
        default=Path("data/reports/rollout_gates_history.jsonl"),
        help="Append rollout gate snapshots to this JSONL file",
    )
    scheduler_parser.add_argument(
        "--memory-report-output",
        type=Path,
        default=Path("data/reports/memory_maintenance_latest.json"),
        help="Write latest memory maintenance report to this path",
    )
    scheduler_parser.add_argument(
        "--no-memory-prune-stale",
        action="store_true",
        help="Disable stale working-memory pruning in scheduler maintenance runs",
    )
    scheduler_parser.add_argument(
        "--once",
        action="store_true",
        help="Run one scheduler iteration and exit",
    )
    scheduler_parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Maximum loop iterations before exit (default: unbounded)",
    )
    scheduler_parser.add_argument(
        "--stop-on-escalation",
        action="store_true",
        help="Use stop-on-escalation behavior for heartbeat live cycle",
    )
    scheduler_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    autopilot_parser = subparsers.add_parser(
        "autopilot",
        help="Run end-to-end supervisor state machine (preflight/start/operate/verify/promote-or-rollback/report)",
    )
    autopilot_parser.add_argument(
        "--control-mode",
        choices=("monitor", "observe", "assist", "autonomous"),
        default="assist",
        help="Control mode used during operate phase (monitor aliases observe)",
    )
    autopilot_parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Override WiCAP repo root (default: auto-detected)",
    )
    autopilot_parser.add_argument(
        "--contract-path",
        type=Path,
        default=None,
        help="Override runtime contract JSON path",
    )
    autopilot_parser.add_argument(
        "--no-require-runtime-contract",
        action="store_true",
        help="Do not fail preflight/start when runtime contract check fails",
    )
    autopilot_parser.add_argument(
        "--require-scout",
        action="store_true",
        help="Require wicap-scout to be up in runtime contract checks (disabled by default for SSH-safe boot)",
    )
    autopilot_parser.add_argument(
        "--no-startup",
        action="store_true",
        help="Skip startup actions in start phase",
    )
    autopilot_parser.add_argument(
        "--startup-actions",
        default="compose_up_core",
        help="Comma-separated allowlisted startup actions (default: compose_up_core)",
    )
    autopilot_parser.add_argument(
        "--operate-cycles",
        type=int,
        default=6,
        help="Number of once-cycles to execute during operate phase",
    )
    autopilot_parser.add_argument(
        "--operate-interval-seconds",
        type=float,
        default=5.0,
        help="Observation interval for each operate/start cycle",
    )
    autopilot_parser.add_argument(
        "--stop-on-escalation",
        action="store_true",
        help="Treat escalation as immediate operate failure",
    )
    autopilot_parser.add_argument(
        "--verify-replay",
        action="store_true",
        help="Require replay certification pass in verify phase",
    )
    autopilot_parser.add_argument(
        "--verify-chaos",
        action="store_true",
        help="Require chaos certification pass in verify phase",
    )
    autopilot_parser.add_argument(
        "--profile",
        default="default",
        help="Certification profile for replay/chaos verify steps",
    )
    autopilot_parser.add_argument(
        "--gate-history-file",
        type=Path,
        default=Path("data/reports/rollout_gates_history.jsonl"),
        help="Rollout gate history JSONL used for promotion readiness",
    )
    autopilot_parser.add_argument(
        "--required-consecutive-passes",
        type=int,
        default=2,
        help="Consecutive rollout-gate passes required before promotion decision",
    )
    autopilot_parser.add_argument(
        "--no-rollback-on-verify-failure",
        action="store_true",
        help="Disable rollback phase when verify fails",
    )
    autopilot_parser.add_argument(
        "--rollback-actions",
        default="shutdown,compose_up_core",
        help="Comma-separated allowlisted rollback actions",
    )
    autopilot_parser.add_argument(
        "--report-path",
        type=Path,
        default=Path("data/reports/autopilot_latest.json"),
        help="Write latest autopilot summary report to this path",
    )
    autopilot_parser.add_argument(
        "--max-runs",
        type=int,
        default=1,
        help="Number of supervisor runs to execute (0 means unbounded)",
    )
    autopilot_parser.add_argument(
        "--pause-seconds-between-runs",
        type=float,
        default=10.0,
        help="Pause between supervisor runs when max-runs > 1 or unbounded",
    )
    autopilot_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    rollout_parser = subparsers.add_parser(
        "rollout-gates",
        help="Evaluate deterministic autonomous rollout/canary promotion gates",
    )
    rollout_parser.add_argument("--lookback-days", type=int, default=14, help="Lookback window in days")
    rollout_parser.add_argument("--min-shadow-samples", type=int, default=200)
    rollout_parser.add_argument("--min-shadow-agreement-rate", type=float, default=0.82)
    rollout_parser.add_argument("--min-shadow-success-rate", type=float, default=0.72)
    rollout_parser.add_argument("--min-reward-avg", type=float, default=0.05)
    rollout_parser.add_argument("--max-autonomous-escalation-rate", type=float, default=0.08)
    rollout_parser.add_argument("--min-autonomous-runs", type=int, default=5)
    rollout_parser.add_argument("--max-rollback-failures", type=int, default=1)
    rollout_parser.add_argument("--min-proactive-samples", type=int, default=0)
    rollout_parser.add_argument("--min-proactive-success-rate", type=float, default=0.0)
    rollout_parser.add_argument("--max-proactive-relapse-rate", type=float, default=1.0)
    rollout_parser.add_argument(
        "--history-file",
        type=Path,
        default=Path("data/reports/rollout_gates_history.jsonl"),
        help="Append gate snapshots to JSONL history for promotion readiness checks",
    )
    rollout_parser.add_argument(
        "--required-consecutive-passes",
        type=int,
        default=2,
        help="Consecutive overall gate passes required for promotion readiness",
    )
    rollout_parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero if promotion readiness is not met",
    )
    rollout_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    soak_run_parser = subparsers.add_parser("soak-run", help="Run supervised WICAP soak and auto-capture context")
    soak_run_parser.add_argument("--duration-minutes", type=int, default=None, help="Soak duration in minutes")
    soak_run_parser.add_argument(
        "--playwright-interval-minutes",
        type=int,
        default=None,
        help="Playwright check interval in minutes",
    )
    soak_run_parser.add_argument("--baseline-path", type=Path, default=None, help="Optional baseline JSON path")
    baseline_update_group = soak_run_parser.add_mutually_exclusive_group()
    baseline_update_group.add_argument(
        "--baseline-update",
        dest="baseline_update",
        action="store_true",
        help="Update baseline JSON from run",
    )
    baseline_update_group.add_argument(
        "--no-baseline-update",
        dest="baseline_update",
        action="store_false",
        help="Do not update baseline JSON from run",
    )
    soak_run_parser.set_defaults(baseline_update=None)
    soak_run_parser.add_argument("--dry-run", action="store_true", help="Print plan without executing soak")
    soak_run_parser.add_argument(
        "--observe-interval-seconds",
        type=float,
        default=10.0,
        help="Live observation interval during supervised soak",
    )
    soak_run_parser.add_argument(
        "--control-mode",
        choices=("monitor", "observe", "assist", "autonomous"),
        default="observe",
        help="Control policy mode: monitor/observe, assist, or autonomous (with rollback + kill-switch checks)",
    )
    soak_run_parser.add_argument(
        "--control-check-threshold",
        type=int,
        default=None,
        help="Cycles down before status check action (profile default when omitted)",
    )
    soak_run_parser.add_argument(
        "--control-recover-threshold",
        type=int,
        default=None,
        help="Cycles down before compose recovery action",
    )
    soak_run_parser.add_argument(
        "--control-max-recover-attempts",
        type=int,
        default=None,
        help="Maximum compose recovery attempts per service",
    )
    soak_run_parser.add_argument(
        "--control-action-cooldown-cycles",
        type=int,
        default=None,
        help="Cooldown cycles between control actions",
    )
    soak_stop_group = soak_run_parser.add_mutually_exclusive_group()
    soak_stop_group.add_argument(
        "--stop-on-escalation",
        dest="stop_on_escalation",
        action="store_true",
        help="Stop soak run when control policy escalates",
    )
    soak_stop_group.add_argument(
        "--no-stop-on-escalation",
        dest="stop_on_escalation",
        action="store_false",
        help="Keep soak runner active even if control policy escalates",
    )
    soak_run_parser.set_defaults(stop_on_escalation=True)
    soak_contract_group = soak_run_parser.add_mutually_exclusive_group()
    soak_contract_group.add_argument(
        "--require-runtime-contract",
        dest="require_runtime_contract",
        action="store_true",
        help="Fail fast when runtime contract check does not pass before starting soak",
    )
    soak_contract_group.add_argument(
        "--no-require-runtime-contract",
        dest="require_runtime_contract",
        action="store_false",
        help="Do not gate soak launch on runtime contract check",
    )
    soak_run_parser.set_defaults(require_runtime_contract=True)
    soak_run_parser.add_argument(
        "--runtime-contract-path",
        type=Path,
        default=None,
        help="Override runtime contract JSON path for soak preflight gate",
    )

    live_parser = subparsers.add_parser("live", help="Live monitor loop with optional assist/autonomous control actions")
    live_parser.add_argument("--interval", type=float, default=10.0, help="Observation interval in seconds")
    live_parser.add_argument("--once", action="store_true", help="Run one observation cycle and exit")
    live_parser.add_argument(
        "--control-mode",
        choices=("monitor", "observe", "assist", "autonomous"),
        default="observe",
        help="Control policy mode for live loop: monitor/observe, assist, or autonomous",
    )
    live_parser.add_argument(
        "--control-check-threshold",
        type=int,
        default=None,
        help="Cycles down before status check action (profile default when omitted)",
    )
    live_parser.add_argument(
        "--control-recover-threshold",
        type=int,
        default=None,
        help="Cycles down before compose recovery action",
    )
    live_parser.add_argument(
        "--control-max-recover-attempts",
        type=int,
        default=None,
        help="Maximum compose recovery attempts per service",
    )
    live_parser.add_argument(
        "--control-action-cooldown-cycles",
        type=int,
        default=None,
        help="Cooldown cycles between control actions",
    )
    live_parser.add_argument(
        "--stop-on-escalation",
        action="store_true",
        help="Exit with code 2 when control policy escalates",
    )

    agent_parser = subparsers.add_parser("agent", help="Interactive live control agent console")
    agent_parser.add_argument(
        "agent_subcommand",
        nargs="?",
        choices=(
            "console",
            "explain-policy",
            "sandbox-explain",
            "forecast",
            "control-center",
            "failover-state",
            "mission-graph",
            "replay-certify",
            "chaos-certify",
        ),
        default="console",
        help=(
            "Agent surface: console (default), explain-policy, sandbox-explain, "
            "forecast, control-center, failover-state, mission-graph, replay-certify, chaos-certify"
        ),
    )
    agent_parser.add_argument(
        "--control-mode",
        choices=("monitor", "observe", "assist", "autonomous"),
        default="observe",
        help="Default control mode used for soak requests in the console (monitor aliases observe)",
    )
    agent_parser.add_argument(
        "--observe-interval-seconds",
        type=float,
        default=10.0,
        help="Default observation interval used for soak requests in the console",
    )
    agent_parser.add_argument(
        "--lookback-hours",
        type=int,
        default=6,
        help="Lookback window for agent forecast/control-center summaries",
    )
    agent_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit JSON for explain-policy/forecast/control-center surfaces",
    )
    agent_parser.add_argument(
        "--action",
        default="status_check",
        help="Action to evaluate for sandbox-explain (for example: status_check, compose_up_core, compose_up, restart_service:wicap-ui)",
    )
    agent_parser.add_argument(
        "--mode",
        choices=("monitor", "observe", "assist", "autonomous"),
        default="observe",
        help="Control mode context for sandbox-explain",
    )
    agent_parser.add_argument(
        "--profile",
        default="default",
        help="Profile selector used by replay-certify/chaos-certify",
    )
    agent_parser.add_argument(
        "--run-id",
        type=int,
        default=0,
        help="Mission run id for mission-graph inspection",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if args.command == "setup-wicap-env":
        try:
            report = run_wicap_env_setup(
                repo_root=args.repo_root or wicap_repo_root(),
                env_path=args.env_file,
                assume_yes=bool(args.yes),
                dry_run=bool(args.dry_run),
                backup_existing=not bool(args.no_backup),
            )
        except SetupAbortedError as exc:
            print(str(exc))
            return 2
        except (EOFError, KeyboardInterrupt):
            print("setup-wicap-env aborted.")
            return 2
        except ValueError as exc:
            print(f"setup-wicap-env error: {exc}")
            return 2
        print(
            "WiCAP env setup complete: "
            f"path={report['env_path']} "
            f"changed_keys={len(report.get('changed_keys', []))} "
            f"dry_run={bool(report.get('dry_run', False))}"
        )
        return 0

    if args.command == "validate-wicap-env":
        try:
            report = validate_wicap_env(
                repo_root=args.repo_root or wicap_repo_root(),
                env_path=args.env_file,
                probe_live=not bool(args.no_live_probe),
                require_live=bool(args.require_live),
            )
        except ValueError as exc:
            print(f"validate-wicap-env error: {exc}")
            return 2

        if args.as_json:
            print(json.dumps(report, sort_keys=True))
        else:
            print(f"Validation target: {report['env_path']}")
            errors = list(report.get("errors", []))
            warnings = list(report.get("warnings", []))
            if errors:
                print("Errors:")
                for item in errors:
                    print(f"- {item}")
            if warnings:
                print("Warnings:")
                for item in warnings:
                    print(f"- {item}")
            checks = report.get("checks", {})
            if isinstance(checks, dict) and checks:
                print("Checks:")
                for key in sorted(checks.keys()):
                    print(f"- {key}: {checks[key]}")
            if not errors:
                print("Validation passed.")
        return 0 if bool(report.get("ok")) else 2

    if args.command == "ingest":
        scan_flags = [
            args.scan_codex, args.scan_soaks, args.scan_harness,
            args.scan_antigravity, args.scan_changelog, args.scan_network_events,
        ]
        if not any(scan_flags):
            parser.error(
                "ingest requires at least one --scan-* flag "
                "(--scan-codex, --scan-soaks, --scan-harness, "
                "--scan-network-events, --scan-antigravity, --scan-changelog)"
            )
        return _run_ingest(
            db_path,
            scan_codex=args.scan_codex,
            scan_soaks=args.scan_soaks,
            scan_harness=args.scan_harness,
            scan_antigravity=args.scan_antigravity,
            scan_changelog=args.scan_changelog,
            scan_network_events=args.scan_network_events,
        )

    if args.command == "triage":
        return _run_triage(
            db_path,
            query=args.query,
            top_sessions=args.top_sessions,
            per_category=args.per_category,
            limit=args.limit,
        )

    if args.command == "bundle":
        conn = connect_db(db_path)
        bundle = build_bundle(conn, args.target)
        conn.close()
        if args.as_json:
            print(bundle_to_json(bundle))
        else:
            print(format_bundle_text(bundle))
        return 0

    if args.command == "incident":
        conn = connect_db(db_path)
        try:
            if args.json_input is not None:
                bundle = load_bundle_json(args.json_input)
                bundle.setdefault("target", args.target)
            else:
                bundle = build_bundle(conn, args.target)
            report_path = write_incident_report(
                conn,
                target=args.target,
                bundle=bundle,
                overwrite=bool(args.overwrite),
            )
            conn.commit()
        finally:
            conn.close()
        print(f"Incident report written: {report_path}")
        return 0

    if args.command == "playbooks":
        conn = connect_db(db_path)
        try:
            generated = generate_playbooks(conn, top_n=max(1, int(args.top)))
        finally:
            conn.close()

        if not generated:
            print("No playbooks generated (no matching failure clusters).")
            return 0

        print(f"Generated {len(generated)} playbooks:")
        for path in generated:
            print(f"- {path}")
        return 0

    if args.command == "daily-report":
        conn = connect_db(db_path)
        try:
            report = generate_daily_report(
                conn,
                days=max(1, int(args.days)),
                top=max(1, int(args.top)),
            )
        finally:
            conn.close()

        if args.as_json:
            print(daily_report_to_json(report))
        else:
            print(format_daily_report_text(report))
        return 0

    if args.command == "guardian":
        conn = connect_db(db_path)
        try:
            run_guardian(
                conn,
                path_specs=args.path,
                interval=max(0.1, float(args.interval)),
                once=bool(args.once),
                as_json=bool(args.as_json),
            )
        finally:
            conn.close()
        return 0

    if args.command == "recommend":
        conn = connect_db(db_path)
        try:
            payload = build_recommendation(conn, args.target)
        finally:
            conn.close()
        print(recommendation_to_json(payload))
        return 0

    if args.command == "rollup":
        conn = connect_db(db_path)
        try:
            report = generate_rollup(
                conn,
                days=max(1, int(args.days)),
                top=max(1, int(args.top)),
            )
        finally:
            conn.close()
        if args.as_json:
            print(rollup_to_json(report))
        else:
            print(format_rollup_text(report))
        return 0

    if args.command == "changelog-stats":
        return _run_changelog_stats(db_path)

    if args.command == "contract-check":
        return _run_contract_check(
            contract_path=args.contract_path,
            as_json=bool(args.as_json),
            enforce=bool(args.enforce),
            require_scout=bool(args.require_scout),
        )

    if args.command == "cross-patterns":
        conn = connect_db(db_path)
        try:
            patterns = detect_chronic_patterns(
                conn,
                min_occurrences=max(1, int(args.min_occurrences)),
                min_span_days=max(0.0, float(args.min_span_days)),
                top_n=max(1, int(args.top)),
            )
        finally:
            conn.close()
        if args.as_json:
            print(chronic_patterns_to_json(patterns))
        else:
            print(format_chronic_patterns_text(patterns))
        return 0

    if args.command == "backfill-report":
        conn = connect_db(db_path)
        try:
            report = generate_backfill_report(conn)
        finally:
            conn.close()
        if args.as_json:
            print(backfill_report_to_json(report))
        else:
            print(format_backfill_report_text(report))
        return 0

    if args.command == "fix-lineage":
        conn = connect_db(db_path)
        try:
            lineage = resolve_fix_lineage(conn, args.signature)
        finally:
            conn.close()
        if args.as_json:
            print(fix_lineage_to_json(lineage))
        else:
            print(format_fix_lineage_text(lineage))
        return 0

    if args.command == "confidence-audit":
        report = run_confidence_audit(db_path, limit=args.limit)
        if args.as_json:
            print(confidence_audit_to_json(report))
        else:
            print(format_confidence_audit_text(report))
        return 0

    if args.command == "memory-maintenance":
        conn = connect_db(db_path)
        try:
            report = run_memory_maintenance(
                conn,
                lookback_days=max(1, int(args.lookback_days)),
                stale_days=max(1, int(args.stale_days)),
                max_decision_rows=max(1, int(args.max_decision_rows)),
                max_session_rows=max(1, int(args.max_session_rows)),
                max_recent_transitions=max(1, int(args.max_recent_transitions)),
                prune_stale=bool(args.prune_stale),
            )
            output_path = write_memory_maintenance_report(report, Path(args.output))
            conn.commit()
        finally:
            conn.close()
        if args.as_json:
            import json as _json

            print(_json.dumps(report, sort_keys=True))
        else:
            print(
                "Memory maintenance: "
                f"decisions={report['decision_rows_analyzed']} "
                f"stale_sessions={report['stale_session_count']} "
                f"pruned={report['pruned_session_count']} "
                f"avg_reward={report['avg_reward']}"
            )
            print(f"Report written: {output_path}")
        return 0

    if args.command == "scheduler":
        conn = connect_db(db_path)
        try:
            report = run_scheduler_loop(
                conn,
                owner=args.owner,
                lock_dir=Path(args.lock_dir),
                state_path=Path(args.state_path) if args.state_path is not None else None,
                control_mode=_normalize_control_mode(str(args.control_mode)),
                heartbeat_interval_seconds=max(0.1, float(args.heartbeat_interval_seconds)),
                heartbeat_lease_seconds=max(1, int(args.heartbeat_lease_seconds)),
                memory_maintenance_interval_seconds=max(0, int(args.memory_maintenance_interval_seconds)),
                rollout_gates_interval_seconds=max(0, int(args.rollout_gates_interval_seconds)),
                rollout_history_file=Path(args.rollout_history_file),
                memory_report_output=Path(args.memory_report_output),
                memory_prune_stale=not bool(args.no_memory_prune_stale),
                once=bool(args.once),
                max_iterations=(
                    max(1, int(args.max_iterations))
                    if args.max_iterations is not None
                    else None
                ),
                stop_on_escalation=bool(args.stop_on_escalation),
            )
        finally:
            conn.close()
        if args.as_json:
            import json as _json

            print(_json.dumps(report, sort_keys=True))
        else:
            print(
                "Scheduler: "
                f"iterations={report['iterations']} "
                f"heartbeat_executed={report['heartbeat_executed']} "
                f"heartbeat_skipped={report['heartbeat_skipped']} "
                f"heartbeat_escalations={report['heartbeat_escalations']}"
            )
            print(
                "Cron: "
                f"memory-maintenance executed={report['cron_executed']['memory-maintenance']} "
                f"skipped={report['cron_skipped']['memory-maintenance']}; "
                f"rollout-gates executed={report['cron_executed']['rollout-gates']} "
                f"skipped={report['cron_skipped']['rollout-gates']}"
            )
            print(f"State path: {report['state_path']}")
        return 0

    if args.command == "autopilot":
        conn = connect_db(db_path)
        try:
            report = run_autopilot_supervisor(
                conn,
                mode=_normalize_control_mode(str(args.control_mode)),
                repo_root=Path(args.repo_root) if args.repo_root is not None else None,
                contract_path=Path(args.contract_path) if args.contract_path is not None else None,
                require_runtime_contract=not bool(args.no_require_runtime_contract),
                require_scout=bool(args.require_scout),
                startup_actions=tuple(
                    item.strip().lower()
                    for item in str(args.startup_actions).split(",")
                    if item.strip()
                )
                or ("compose_up_core",),
                perform_startup=not bool(args.no_startup),
                operate_cycles=max(1, int(args.operate_cycles)),
                operate_interval_seconds=max(0.1, float(args.operate_interval_seconds)),
                stop_on_escalation=bool(args.stop_on_escalation),
                verify_replay=bool(args.verify_replay),
                verify_chaos=bool(args.verify_chaos),
                certification_profile=str(args.profile),
                gate_history_file=Path(args.gate_history_file),
                required_consecutive_passes=max(1, int(args.required_consecutive_passes)),
                rollback_on_verify_failure=not bool(args.no_rollback_on_verify_failure),
                rollback_actions=tuple(
                    item.strip().lower()
                    for item in str(args.rollback_actions).split(",")
                    if item.strip()
                )
                or ("shutdown", "compose_up_core"),
                report_path=Path(args.report_path) if args.report_path is not None else None,
                max_runs=int(args.max_runs),
                pause_seconds_between_runs=max(0.1, float(args.pause_seconds_between_runs)),
            )
        finally:
            conn.close()
        latest = report.get("latest", {}) if isinstance(report, dict) else {}
        latest_status = str(latest.get("status", "")).strip().lower() if isinstance(latest, dict) else ""
        if args.as_json:
            import json as _json

            print(_json.dumps(report, sort_keys=True))
        else:
            print(
                "Autopilot: "
                f"runs={report.get('run_count')} "
                f"latest_status={latest.get('status')} "
                f"decision={latest.get('promotion_decision')} "
                f"run_id={latest.get('run_id')}"
            )
            report_path = latest.get("report_path")
            if report_path:
                print(f"Report written: {report_path}")
        return 0 if latest_status in {"promoted", "hold", "rolled_back", "completed"} else 2

    if args.command == "rollout-gates":
        conn = connect_db(db_path)
        try:
            report = evaluate_rollout_gates(
                conn,
                lookback_days=max(1, int(args.lookback_days)),
                min_shadow_samples=max(1, int(args.min_shadow_samples)),
                min_shadow_agreement_rate=float(args.min_shadow_agreement_rate),
                min_shadow_success_rate=float(args.min_shadow_success_rate),
                min_reward_avg=float(args.min_reward_avg),
                max_autonomous_escalation_rate=float(args.max_autonomous_escalation_rate),
                min_autonomous_runs=max(1, int(args.min_autonomous_runs)),
                max_rollback_failures=max(0, int(args.max_rollback_failures)),
                min_proactive_samples=max(0, int(args.min_proactive_samples)),
                min_proactive_success_rate=float(args.min_proactive_success_rate),
                max_proactive_relapse_rate=float(args.max_proactive_relapse_rate),
            )
        finally:
            conn.close()
        history_file = Path(args.history_file)
        append_rollout_gate_history(history_file, report)
        history = load_rollout_gate_history(history_file)
        promotion = evaluate_promotion_readiness(
            history,
            required_consecutive_passes=max(1, int(args.required_consecutive_passes)),
        )
        report["history_file"] = str(history_file)
        report["history_count"] = int(len(history))
        report["promotion"] = promotion
        if bool(args.enforce) and not bool(promotion.get("ready")):
            exit_code = 2
        else:
            exit_code = 0
        if args.as_json:
            import json as _json

            print(_json.dumps(report, sort_keys=True))
        else:
            status = "PASS" if bool(report.get("overall_pass")) else "FAIL"
            promotion_status = "READY" if bool(promotion.get("ready")) else "NOT_READY"
            print(f"Rollout gates: {status} (promotion={promotion_status})")
            gates = report.get("gates", {})
            if isinstance(gates, dict):
                for name in sorted(gates.keys()):
                    value = gates.get(name, {})
                    if not isinstance(value, dict):
                        continue
                    print(f"- {name}: {value.get('status')} (pass={bool(value.get('pass'))})")
            print(
                "- promotion: "
                f"consecutive_passes={promotion.get('consecutive_passes')} "
                f"required={promotion.get('required_consecutive_passes')}"
            )
        return int(exit_code)

    if args.command == "soak-run":
        return _run_soak_run(
            db_path,
            duration_minutes=max(1, int(args.duration_minutes)) if args.duration_minutes is not None else None,
            playwright_interval_minutes=(
                max(1, int(args.playwright_interval_minutes))
                if args.playwright_interval_minutes is not None
                else None
            ),
            baseline_path=args.baseline_path,
            baseline_update=args.baseline_update,
            dry_run=bool(args.dry_run),
            observe_interval_seconds=max(0.1, float(args.observe_interval_seconds)),
            control_mode=_normalize_control_mode(str(args.control_mode)),
            control_check_threshold=(
                max(1, int(args.control_check_threshold))
                if args.control_check_threshold is not None
                else None
            ),
            control_recover_threshold=(
                max(1, int(args.control_recover_threshold))
                if args.control_recover_threshold is not None
                else None
            ),
            control_max_recover_attempts=(
                max(1, int(args.control_max_recover_attempts))
                if args.control_max_recover_attempts is not None
                else None
            ),
            control_action_cooldown_cycles=(
                max(0, int(args.control_action_cooldown_cycles))
                if args.control_action_cooldown_cycles is not None
                else None
            ),
            stop_on_escalation=bool(args.stop_on_escalation),
            require_runtime_contract=bool(args.require_runtime_contract),
            runtime_contract_path=args.runtime_contract_path,
        )

    if args.command == "live":
        conn = connect_db(db_path)
        try:
            return run_live_monitor(
                conn,
                interval=max(0.1, float(args.interval)),
                once=bool(args.once),
                control_mode=_normalize_control_mode(str(args.control_mode)),
                control_check_threshold=(
                    max(1, int(args.control_check_threshold))
                    if args.control_check_threshold is not None
                    else None
                ),
                control_recover_threshold=(
                    max(1, int(args.control_recover_threshold))
                    if args.control_recover_threshold is not None
                    else None
                ),
                control_max_recover_attempts=(
                    max(1, int(args.control_max_recover_attempts))
                    if args.control_max_recover_attempts is not None
                    else None
                ),
                control_action_cooldown_cycles=(
                    max(0, int(args.control_action_cooldown_cycles))
                    if args.control_action_cooldown_cycles is not None
                    else None
                ),
                stop_on_escalation=bool(args.stop_on_escalation),
            )
        finally:
            conn.close()

    if args.command == "agent":
        subcommand = str(getattr(args, "agent_subcommand", "console") or "console").strip().lower()
        normalized_mode = _normalize_control_mode(str(args.control_mode))
        if subcommand == "console":
            return _run_agent(
                db_path,
                control_mode=normalized_mode,
                observe_interval_seconds=max(0.1, float(args.observe_interval_seconds)),
            )
        if subcommand == "explain-policy":
            return _run_agent_explain_policy(as_json=bool(args.as_json))
        if subcommand == "sandbox-explain":
            return _run_agent_sandbox_explain(
                action=str(args.action),
                mode=str(args.mode),
                as_json=bool(args.as_json),
            )
        if subcommand == "forecast":
            return _run_agent_forecast(
                db_path,
                lookback_hours=max(1, int(args.lookback_hours)),
                as_json=bool(args.as_json),
            )
        if subcommand == "control-center":
            return _run_agent_control_center(
                db_path,
                control_mode=normalized_mode,
                lookback_hours=max(1, int(args.lookback_hours)),
                as_json=bool(args.as_json),
            )
        if subcommand == "failover-state":
            return _run_agent_failover_state(
                db_path,
                as_json=bool(args.as_json),
            )
        if subcommand == "mission-graph":
            return _run_agent_mission_graph(
                db_path,
                run_id=max(0, int(args.run_id)),
                as_json=bool(args.as_json),
            )
        if subcommand == "replay-certify":
            return _run_agent_replay_certify(
                db_path,
                profile=str(args.profile),
                as_json=bool(args.as_json),
            )
        if subcommand == "chaos-certify":
            return _run_agent_chaos_certify(
                db_path,
                profile=str(args.profile),
                as_json=bool(args.as_json),
            )
        parser.error(f"Unknown agent subcommand: {subcommand}")
        return 2

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
