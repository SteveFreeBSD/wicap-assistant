"""CLI entrypoint for wicap-assistant."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from wicap_assist.backfill_report import (
    backfill_report_to_json,
    format_backfill_report_text,
    generate_backfill_report,
)
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
from wicap_assist.ingest.codex_jsonl import parse_codex_file, scan_codex_paths, source_kind_for
from wicap_assist.ingest.harness_scripts import ingest_harness_scripts
from wicap_assist.ingest.soak_logs import ingest_soak_logs
from wicap_assist.ingest.antigravity_logs import ingest_antigravity_logs
from wicap_assist.ingest.changelog import ingest_changelog
from wicap_assist.cross_pattern import (
    chronic_patterns_to_json,
    detect_chronic_patterns,
    format_chronic_patterns_text,
)
from wicap_assist.incident import load_bundle_json, write_incident_report
from wicap_assist.guardian import run_guardian
from wicap_assist.playbooks import generate_playbooks
from wicap_assist.recommend import build_recommendation, recommendation_to_json
from wicap_assist.rollup import format_rollup_text, generate_rollup, rollup_to_json
from wicap_assist.util.time import utc_now_iso


def _run_ingest(
    db_path: Path,
    *,
    scan_codex: bool,
    scan_soaks: bool,
    scan_harness: bool,
    scan_antigravity: bool,
    scan_changelog: bool,
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
        f"log_events_added={log_events_added} db={db_path}"
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


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(prog="wicap-assist")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")

    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Ingest Codex/soak logs into SQLite")
    ingest_parser.add_argument("--scan-codex", action="store_true", help="Scan configured Codex paths")
    ingest_parser.add_argument("--scan-soaks", action="store_true", help="Scan WICAP soak log paths")
    ingest_parser.add_argument("--scan-harness", action="store_true", help="Scan WICAP harness scripts")
    ingest_parser.add_argument("--scan-antigravity", action="store_true", help="Scan Antigravity conversation artifacts")
    ingest_parser.add_argument("--scan-changelog", action="store_true", help="Scan WICAP CHANGELOG.md")

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

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if args.command == "ingest":
        scan_flags = [
            args.scan_codex, args.scan_soaks, args.scan_harness,
            args.scan_antigravity, args.scan_changelog,
        ]
        if not any(scan_flags):
            parser.error(
                "ingest requires at least one --scan-* flag "
                "(--scan-codex, --scan-soaks, --scan-harness, "
                "--scan-antigravity, --scan-changelog)"
            )
        return _run_ingest(
            db_path,
            scan_codex=args.scan_codex,
            scan_soaks=args.scan_soaks,
            scan_harness=args.scan_harness,
            scan_antigravity=args.scan_antigravity,
            scan_changelog=args.scan_changelog,
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

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
