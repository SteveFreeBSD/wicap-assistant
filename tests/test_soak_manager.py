from __future__ import annotations

from pathlib import Path

import pytest

from wicap_assist.soak_manager import (
    allowed_runner_paths,
    build_manager_actions,
    build_operator_guidance,
    evaluate_learning_readiness,
    planned_phases,
    validate_runner_command,
    validate_runner_path,
)
from wicap_assist.soak_profiles import SoakProfile, SoakRunbook


def test_validate_runner_path_accepts_canonical_paths(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred = repo_root / "tests" / "soak_test.py"
    fallback = repo_root / "scripts" / "run_live_soak.py"
    preferred.parent.mkdir(parents=True)
    fallback.parent.mkdir(parents=True)
    preferred.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    fallback.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    for path in allowed_runner_paths(repo_root):
        validate_runner_path(path, repo_root=repo_root)


def test_validate_runner_path_rejects_non_allowlisted_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    bad = repo_root / "scripts" / "arbitrary_exec.py"
    bad.parent.mkdir(parents=True)
    bad.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    with pytest.raises(ValueError):
        validate_runner_path(bad, repo_root=repo_root)


def test_validate_runner_command_accepts_expected_flags(tmp_path: Path) -> None:
    runner_path = (tmp_path / "wicap" / "tests" / "soak_test.py").resolve()
    runner_path.parent.mkdir(parents=True)
    runner_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    command = [
        "/usr/bin/python3",
        str(runner_path),
        "--duration-minutes",
        "10",
        "--playwright-interval-minutes",
        "2",
        "--baseline-path",
        "/tmp/base.json",
        "--baseline-update",
    ]
    validate_runner_command(command, runner_path=runner_path)


def test_validate_runner_command_rejects_unexpected_flag(tmp_path: Path) -> None:
    runner_path = (tmp_path / "wicap" / "tests" / "soak_test.py").resolve()
    runner_path.parent.mkdir(parents=True)
    runner_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    command = [
        "/usr/bin/python3",
        str(runner_path),
        "--duration-minutes",
        "10",
        "--shell-cmd",
        "whoami",
    ]
    with pytest.raises(ValueError):
        validate_runner_command(command, runner_path=runner_path)


def test_planned_phases_include_observe_only_for_managed() -> None:
    assert planned_phases(managed_observe=False) == [
        "preflight_init",
        "soak_execute",
        "ingest_soaks",
        "incident_report",
        "finalize",
    ]
    assert planned_phases(managed_observe=True) == [
        "preflight_init",
        "soak_execute",
        "observe",
        "ingest_soaks",
        "incident_report",
        "finalize",
    ]


def test_evaluate_learning_readiness_ready_case() -> None:
    profile = SoakProfile(
        runner_path="/home/steve/apps/wicap/tests/soak_test.py",
        duration_minutes=30,
        playwright_interval_minutes=5,
        baseline_path=None,
        baseline_update=False,
        score=10,
        evidence_count=5,
        success_count=4,
        fail_count=0,
        session_ids=["s1", "s2", "s3", "s4"],
    )
    runbook = SoakRunbook(
        steps=[
            "docker compose up -d",
            "python start_wicap.py",
            "python scripts/check_wicap_status.py --local-only",
        ],
        session_ids=["s1", "s2"],
        success_session_count=3,
    )
    readiness = evaluate_learning_readiness(profile, runbook)
    assert readiness["status"] == "ready"
    assert int(readiness["score"]) >= 7
    assert readiness["has_startup_step"] is True
    assert readiness["has_verify_step"] is True


def test_evaluate_learning_readiness_insufficient_case() -> None:
    profile = SoakProfile(
        runner_path=None,
        duration_minutes=None,
        playwright_interval_minutes=None,
        baseline_path=None,
        baseline_update=None,
        score=0,
        evidence_count=0,
        success_count=0,
        fail_count=1,
        session_ids=[],
    )
    runbook = SoakRunbook(
        steps=["echo hello"],
        session_ids=[],
        success_session_count=0,
    )
    readiness = evaluate_learning_readiness(profile, runbook)
    assert readiness["status"] == "insufficient"
    assert int(readiness["score"]) <= 2
    assert readiness["has_startup_step"] is False


def test_build_manager_actions_orders_guidance_and_runbook_steps() -> None:
    readiness = {
        "status": "ready",
        "score": 8,
        "max_score": 8,
    }
    actions = build_manager_actions(
        learning_readiness=readiness,
        runbook_steps=[
            "docker compose up -d",
            "python start_wicap.py",
            "python scripts/check_wicap_status.py --local-only",
        ],
        dry_run=False,
        exit_code=0,
        runner_log="data/soak_runs/r1/runner.log",
        newest_soak_dir="/home/steve/apps/wicap/logs_soak_123",
        incident_path="/home/steve/apps/wicap/docs/incidents/2026-02-11-test.md",
    )
    assert actions
    assert actions[0].startswith("Use learned startup runbook")
    assert any(value.startswith("Runbook step: docker compose up -d") for value in actions)
    assert any("Review newest soak artifacts" in value for value in actions)
    assert any("Review generated incident report" in value for value in actions)


def test_build_operator_guidance_from_control_events() -> None:
    manager_actions = [
        "Use learned startup runbook as primary execution guide.",
        "Runbook step: docker compose up -d",
    ]
    control_events = [
        {"action": "status_check", "status": "executed_ok"},
        {"action": "compose_up", "status": "executed_fail"},
    ]
    guidance = build_operator_guidance(
        manager_actions=manager_actions,
        control_events=control_events,
        control_mode="assist",
    )
    assert guidance
    assert guidance[0].startswith("Use learned startup runbook")
    assert any("Status check succeeded" in value for value in guidance)
    assert any("Compose recovery failed" in value for value in guidance)
