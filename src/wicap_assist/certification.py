"""Replay/chaos certification helpers for rollout gates."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from typing import Any

from wicap_assist.db import insert_certification_run, list_recent_certification_runs
from wicap_assist.soak_control import ControlPolicy
from wicap_assist.util.time import utc_now_iso

_DEGRADED_STATUSES = {"executed_fail", "escalated", "rejected", "failed", "missing_script"}
_ALLOWLISTED_ACTION_BASES = {"status_check", "compose_up", "shutdown", "restart_service"}


def _safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _fixture_root(kind: str) -> Path:
    env_name = f"WICAP_ASSIST_{str(kind).strip().upper()}_FIXTURE_ROOT"
    raw = str(os.environ.get(env_name, "")).strip()
    if raw:
        return Path(raw)
    return _repo_root() / "tests" / str(kind).strip().lower() / "fixtures"


def _resolve_fixture_path(kind: str, profile: str) -> Path | None:
    root = _fixture_root(kind)
    normalized_profile = str(profile).strip() or "default"
    candidates = [root / f"{normalized_profile}.json"]
    if normalized_profile != "default":
        candidates.append(root / "default.json")
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _load_fixture_object(kind: str, profile: str) -> tuple[Path | None, dict[str, Any]]:
    path = _resolve_fixture_path(kind, profile)
    if path is None:
        return None, {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return path, {}
    if isinstance(payload, dict):
        return path, payload
    return path, {}


def _command_to_action(command: list[str]) -> str:
    if not isinstance(command, list) or not command:
        return ""
    if len(command) >= 2 and command[0] == "docker" and command[1] == "restart" and len(command) >= 3:
        return f"restart_service:{command[2]}"
    if len(command) >= 4 and command[:4] == ["docker", "compose", "down", "--remove-orphans"]:
        return "shutdown"
    if len(command) >= 3 and command[:3] == ["docker", "compose", "up"]:
        return "compose_up"
    joined = " ".join(command)
    if "check_wicap_status" in joined:
        return "status_check"
    if "stop_wicap.py" in joined:
        return "shutdown"
    return joined


def _runner_from_plan(plan: dict[str, Any]):
    normalized_plan = {str(k).strip(): v for k, v in dict(plan or {}).items()}

    def _runner(command, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        action = _command_to_action(list(command) if isinstance(command, list) else [])
        entry = normalized_plan.get(action)
        if entry is None and action.startswith("restart_service:"):
            entry = normalized_plan.get("restart_service")
        if entry is None:
            entry = normalized_plan.get("*")

        rc = 0
        out = ""
        err = ""
        if isinstance(entry, dict):
            rc = _safe_int(entry.get("returncode"), default=0)
            out = str(entry.get("stdout", ""))
            err = str(entry.get("stderr", ""))
        elif isinstance(entry, int):
            rc = int(entry)

        return subprocess.CompletedProcess(
            args=list(command) if isinstance(command, list) else [str(command)],
            returncode=int(rc),
            stdout=out,
            stderr=err,
        )

    return _runner


def _observation_from_case(raw: dict[str, Any], *, idx: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    ts = str(raw.get("ts") or f"2026-02-12T00:00:{idx:02d}Z")
    if isinstance(raw.get("service_status"), dict):
        return {
            "ts": ts,
            "service_status": raw.get("service_status", {}),
            "top_signatures": raw.get("top_signatures", []),
            "alert": raw.get("alert", ""),
        }

    down_services = raw.get("down_services")
    down = set()
    if isinstance(down_services, list):
        for item in down_services:
            text = str(item).strip()
            if text:
                down.add(text)

    services: dict[str, dict[str, str]] = {}
    for service in ("wicap-ui", "wicap-processor", "wicap-scout", "wicap-redis"):
        if service in down:
            services[service] = {"state": "down", "status": "not running"}
        else:
            services[service] = {"state": "up", "status": "Up (healthy)"}

    return {
        "ts": ts,
        "service_status": {"docker": {"services": services}},
        "top_signatures": raw.get("top_signatures", []),
        "alert": raw.get("alert", ""),
    }


def _event_signature(event: dict[str, Any]) -> dict[str, Any]:
    detail = event.get("detail_json")
    detail_dict = detail if isinstance(detail, dict) else {}
    action_value = event.get("action")
    action = str(action_value).strip() if action_value is not None else None
    return {
        "decision": str(event.get("decision", "")).strip(),
        "action": action,
        "status": str(event.get("status", "")).strip(),
        "service": str(detail_dict.get("service", "")).strip() or None,
    }


def _match_event_subset(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    if not isinstance(expected, dict):
        return False
    for key, value in expected.items():
        if key not in actual:
            return False
        if actual[key] != value:
            return False
    return True


def _simulate_policy_case(case: dict[str, Any]) -> dict[str, Any]:
    case_id = str(case.get("id") or "case")
    mode = str(case.get("mode") or "assist").strip().lower() or "assist"
    runner_plan = case.get("runner_plan") if isinstance(case.get("runner_plan"), dict) else {}
    observations = case.get("observations") if isinstance(case.get("observations"), list) else []
    expected_events = case.get("expected_events") if isinstance(case.get("expected_events"), list) else []

    check_threshold = case.get("check_threshold")
    recover_threshold = case.get("recover_threshold")
    max_recover_attempts = case.get("max_recover_attempts")
    action_cooldown_cycles = case.get("action_cooldown_cycles")

    include_service_health = bool(case.get("include_service_health", True))

    with tempfile.TemporaryDirectory(prefix="wicap-replay-") as tmp_dir:
        repo_root = Path(tmp_dir)
        status_script = repo_root / "scripts" / "check_wicap_status.py"
        status_script.parent.mkdir(parents=True, exist_ok=True)
        status_script.write_text("print('{}')\n", encoding="utf-8")

        policy = ControlPolicy(
            mode=mode,
            repo_root=repo_root,
            runner=_runner_from_plan(runner_plan),
            check_threshold=_safe_int(check_threshold, default=1) if check_threshold is not None else None,
            recover_threshold=_safe_int(recover_threshold, default=1) if recover_threshold is not None else None,
            max_recover_attempts=(
                _safe_int(max_recover_attempts, default=1)
                if max_recover_attempts is not None
                else None
            ),
            action_cooldown_cycles=(
                _safe_int(action_cooldown_cycles, default=0)
                if action_cooldown_cycles is not None
                else None
            ),
        )

        actual_sequence: list[dict[str, Any]] = []
        for idx, raw_obs in enumerate(observations):
            obs = _observation_from_case(raw_obs if isinstance(raw_obs, dict) else {}, idx=idx)
            events = policy.process_observation(obs)
            for event in events:
                signature = _event_signature(event)
                if not include_service_health and signature.get("decision") == "service_health":
                    continue
                actual_sequence.append(signature)

    expected_sequence: list[dict[str, Any]] = []
    for item in expected_events:
        if isinstance(item, dict):
            expected_sequence.append(dict(item))

    matches = bool(
        len(expected_sequence) == len(actual_sequence)
        and all(_match_event_subset(exp, act) for exp, act in zip(expected_sequence, actual_sequence))
    )

    return {
        "id": case_id,
        "pass": bool(matches),
        "expected_count": int(len(expected_sequence)),
        "actual_count": int(len(actual_sequence)),
        "expected_events": expected_sequence,
        "actual_events": actual_sequence,
    }


def _run_replay_from_fixture(*, fixture: dict[str, Any]) -> dict[str, Any]:
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        cases = []

    results: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        results.append(_simulate_policy_case(case))

    total = len(results)
    passed_count = sum(1 for item in results if bool(item.get("pass")))
    score = 0.0 if total <= 0 else float(passed_count) / float(total)
    return {
        "sample_count": int(total),
        "passed_count": int(passed_count),
        "score": round(score, 6),
        "target": 0.99,
        "pass": bool(total > 0 and score >= 0.99),
        "case_results": results,
    }


def run_replay_certification(conn: sqlite3.Connection, *, profile: str) -> dict[str, Any]:
    """Run deterministic fixture-based replay certification."""
    fixture_path, fixture = _load_fixture_object("replay", str(profile))
    ts = utc_now_iso()

    if fixture_path is None or not fixture:
        payload = {
            "ts": ts,
            "cert_type": "replay",
            "profile": str(profile),
            "pass": False,
            "score": 0.0,
            "sample_count": 0,
            "target": 0.99,
            "reason": "replay_fixture_missing_or_invalid",
            "fixture_path": str(fixture_path) if fixture_path is not None else None,
        }
        insert_certification_run(
            conn,
            ts=ts,
            cert_type="replay",
            profile=str(profile),
            passed=False,
            score=0.0,
            detail_json=payload,
        )
        return payload

    replay = _run_replay_from_fixture(fixture=fixture)
    passed = bool(replay.get("pass"))
    payload = {
        "ts": ts,
        "cert_type": "replay",
        "profile": str(profile),
        "pass": passed,
        "score": _safe_float(replay.get("score", 0.0)),
        "sample_count": _safe_int(replay.get("sample_count", 0)),
        "target": 0.99,
        "fixture_path": str(fixture_path),
    }
    insert_certification_run(
        conn,
        ts=ts,
        cert_type="replay",
        profile=str(profile),
        passed=passed,
        score=float(payload["score"]),
        detail_json={
            "fixture_path": str(fixture_path),
            "target": 0.99,
            "sample_count": int(payload["sample_count"]),
            "passed_count": _safe_int(replay.get("passed_count", 0)),
            "case_results": replay.get("case_results", []),
        },
    )
    return payload


def _chaos_action_allowed(action: str | None) -> bool:
    text = str(action or "").strip().lower()
    if not text:
        return True
    base = text.split(":", 1)[0]
    return base in _ALLOWLISTED_ACTION_BASES


def _check_required_actions(required: list[Any], actual_events: list[dict[str, Any]]) -> bool:
    for item in required:
        if isinstance(item, str):
            target_action = item.strip()
            if not target_action:
                continue
            if not any(str(event.get("action") or "").strip() == target_action for event in actual_events):
                return False
            continue
        if isinstance(item, dict):
            matched = False
            for event in actual_events:
                if _match_event_subset(item, event):
                    matched = True
                    break
            if not matched:
                return False
    return True


def _run_chaos_from_fixture(*, fixture: dict[str, Any]) -> dict[str, Any]:
    scenarios = fixture.get("scenarios")
    if not isinstance(scenarios, list):
        scenarios = []

    max_degraded_rate = _safe_float(fixture.get("max_degraded_rate", 0.05), default=0.05)
    scenario_results: list[dict[str, Any]] = []
    degraded_events_total = 0
    total_events = 0
    critical_safety_regressions = 0

    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        result = _simulate_policy_case(scenario)
        actual_events = result.get("actual_events", []) if isinstance(result.get("actual_events"), list) else []

        escalations = 0
        degraded = 0
        executed_actions = 0
        for event in actual_events:
            if not isinstance(event, dict):
                continue
            status = str(event.get("status", "")).strip().lower()
            action = str(event.get("action") or "").strip()
            if status == "escalated":
                escalations += 1
            if status in _DEGRADED_STATUSES:
                degraded += 1
            if action:
                executed_actions += 1
                if not _chaos_action_allowed(action):
                    critical_safety_regressions += 1

        expect = scenario.get("expect") if isinstance(scenario.get("expect"), dict) else {}
        required_actions = expect.get("required_actions") if isinstance(expect.get("required_actions"), list) else []
        max_escalations = _safe_int(expect.get("max_escalations", 0), default=0)
        max_degraded_events = _safe_int(expect.get("max_degraded_events", degraded), default=degraded)
        max_executed_actions = expect.get("max_executed_actions")

        scenario_pass = bool(result.get("pass"))
        scenario_pass = scenario_pass and bool(_check_required_actions(required_actions, actual_events))
        scenario_pass = scenario_pass and int(escalations) <= int(max_escalations)
        scenario_pass = scenario_pass and int(degraded) <= int(max_degraded_events)
        if max_executed_actions is not None:
            scenario_pass = scenario_pass and int(executed_actions) <= _safe_int(max_executed_actions, default=executed_actions)

        degraded_events_total += int(degraded)
        total_events += int(len(actual_events))

        scenario_results.append(
            {
                "id": str(scenario.get("id") or "scenario"),
                "pass": bool(scenario_pass),
                "escalations": int(escalations),
                "degraded_events": int(degraded),
                "executed_actions": int(executed_actions),
                "max_escalations": int(max_escalations),
                "max_degraded_events": int(max_degraded_events),
                "required_actions": required_actions,
                "expected_count": result.get("expected_count"),
                "actual_count": result.get("actual_count"),
            }
        )

    scenario_count = len(scenario_results)
    scenario_pass_count = sum(1 for item in scenario_results if bool(item.get("pass")))
    degraded_rate = float(degraded_events_total) / float(total_events) if total_events > 0 else 0.0
    scenario_pass_rate = float(scenario_pass_count) / float(scenario_count) if scenario_count > 0 else 0.0

    passed = bool(
        scenario_count > 0
        and scenario_pass_count == scenario_count
        and critical_safety_regressions == 0
        and degraded_rate <= float(max_degraded_rate)
    )

    score = max(0.0, min(1.0, scenario_pass_rate * (1.0 - degraded_rate)))
    return {
        "sample_count": int(total_events),
        "scenario_count": int(scenario_count),
        "scenario_pass_count": int(scenario_pass_count),
        "critical_safety_regressions": int(critical_safety_regressions),
        "degraded_events": int(degraded_events_total),
        "degraded_rate": round(float(degraded_rate), 6),
        "max_degraded_rate": round(float(max_degraded_rate), 6),
        "score": round(float(score), 6),
        "pass": bool(passed),
        "scenario_results": scenario_results,
    }


def run_chaos_certification(conn: sqlite3.Connection, *, profile: str) -> dict[str, Any]:
    """Run deterministic fixture-based chaos certification."""
    fixture_path, fixture = _load_fixture_object("chaos", str(profile))
    ts = utc_now_iso()

    if fixture_path is None or not fixture:
        payload = {
            "ts": ts,
            "cert_type": "chaos",
            "profile": str(profile),
            "pass": False,
            "score": 0.0,
            "sample_count": 0,
            "degraded_rate": 1.0,
            "max_degraded_rate": 0.05,
            "critical_safety_regressions": 1,
            "reason": "chaos_fixture_missing_or_invalid",
            "fixture_path": str(fixture_path) if fixture_path is not None else None,
        }
        insert_certification_run(
            conn,
            ts=ts,
            cert_type="chaos",
            profile=str(profile),
            passed=False,
            score=0.0,
            detail_json=payload,
        )
        return payload

    chaos = _run_chaos_from_fixture(fixture=fixture)
    passed = bool(chaos.get("pass"))
    payload = {
        "ts": ts,
        "cert_type": "chaos",
        "profile": str(profile),
        "pass": passed,
        "score": _safe_float(chaos.get("score", 0.0)),
        "sample_count": _safe_int(chaos.get("sample_count", 0)),
        "degraded_rate": _safe_float(chaos.get("degraded_rate", 1.0), default=1.0),
        "max_degraded_rate": _safe_float(chaos.get("max_degraded_rate", 0.05), default=0.05),
        "critical_safety_regressions": _safe_int(chaos.get("critical_safety_regressions", 0)),
        "fixture_path": str(fixture_path),
    }
    insert_certification_run(
        conn,
        ts=ts,
        cert_type="chaos",
        profile=str(profile),
        passed=passed,
        score=float(payload["score"]),
        detail_json={
            "fixture_path": str(fixture_path),
            "scenario_count": _safe_int(chaos.get("scenario_count", 0)),
            "scenario_pass_count": _safe_int(chaos.get("scenario_pass_count", 0)),
            "sample_count": int(payload["sample_count"]),
            "degraded_events": _safe_int(chaos.get("degraded_events", 0)),
            "degraded_rate": float(payload["degraded_rate"]),
            "max_degraded_rate": float(payload["max_degraded_rate"]),
            "critical_safety_regressions": int(payload["critical_safety_regressions"]),
            "scenario_results": chaos.get("scenario_results", []),
        },
    )
    return payload


def certification_history(conn: sqlite3.Connection, *, cert_type: str | None = None, profile: str | None = None) -> dict[str, Any]:
    """Return latest certification runs for CLI surfaces."""
    rows = list_recent_certification_runs(conn, cert_type=cert_type, profile=profile, limit=50)
    out: list[dict[str, Any]] = []
    for row in rows:
        detail = {}
        raw = row["detail_json"]
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                detail = parsed
        out.append(
            {
                "ts": row["ts"],
                "cert_type": row["cert_type"],
                "profile": row["profile"],
                "pass": bool(row["pass"]),
                "score": _safe_float(row["score"]),
                "detail": detail,
            }
        )
    return {
        "count": int(len(out)),
        "rows": out,
    }
