from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.actuators import ActuatorResult
from wicap_assist.autopilot import run_autopilot_supervisor
from wicap_assist.db import connect_db


def test_autopilot_supervisor_promotes_when_verify_and_promotion_ready(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr("wicap_assist.autopilot.shutil.which", lambda _name: "/usr/bin/fake")

    def fake_allowlisted_action(*, action, mode, repo_root, runner):  # type: ignore[no-untyped-def]
        _ = mode
        _ = repo_root
        _ = runner
        return ActuatorResult(
            status="executed_ok",
            commands=[["echo", str(action)]],
            detail="ok",
            policy_trace={"trace_id": "test"},
        )

    monkeypatch.setattr("wicap_assist.autopilot.run_allowlisted_action", fake_allowlisted_action)

    report = run_autopilot_supervisor(
        conn,
        mode="assist",
        repo_root=repo_root,
        require_runtime_contract=True,
        operate_cycles=2,
        operate_interval_seconds=0.1,
        gate_history_file=tmp_path / "rollout_history.jsonl",
        required_consecutive_passes=1,
        report_path=tmp_path / "autopilot_latest.json",
        max_runs=1,
        action_runner=lambda *args, **kwargs: None,  # type: ignore[arg-type]
        live_runner=lambda *args, **kwargs: 0,  # type: ignore[no-untyped-def]
        contract_runner=lambda **kwargs: {"status": "pass", "checks": []},  # type: ignore[no-untyped-def]
        rollout_runner=lambda _conn: {"overall_pass": True, "generated_ts": "2026-02-12T00:00:00Z", "gates": {}},  # type: ignore[no-untyped-def]
    )

    latest = report["latest"]
    assert latest["status"] == "promoted"
    assert latest["promotion_decision"] == "promote"
    assert Path(str(latest["report_path"])).exists()

    run_row = conn.execute(
        "SELECT status FROM autopilot_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert run_row is not None
    assert str(run_row["status"]) == "promoted"

    step_rows = conn.execute(
        "SELECT phase, status FROM autopilot_steps ORDER BY id ASC"
    ).fetchall()
    assert [str(row["phase"]) for row in step_rows] == [
        "preflight",
        "start",
        "operate",
        "verify",
        "promote_or_rollback",
        "report",
    ]
    assert all(str(row["status"]) == "pass" for row in step_rows)
    conn.close()


def test_autopilot_supervisor_rolls_back_on_verify_failure(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr("wicap_assist.autopilot.shutil.which", lambda _name: "/usr/bin/fake")

    actions: list[str] = []

    def fake_allowlisted_action(*, action, mode, repo_root, runner):  # type: ignore[no-untyped-def]
        _ = mode
        _ = repo_root
        _ = runner
        actions.append(str(action))
        return ActuatorResult(
            status="executed_ok",
            commands=[["echo", str(action)]],
            detail="ok",
            policy_trace={"trace_id": "test"},
        )

    monkeypatch.setattr("wicap_assist.autopilot.run_allowlisted_action", fake_allowlisted_action)

    report = run_autopilot_supervisor(
        conn,
        mode="assist",
        repo_root=repo_root,
        require_runtime_contract=True,
        perform_startup=False,
        operate_cycles=1,
        operate_interval_seconds=0.1,
        gate_history_file=tmp_path / "rollout_history.jsonl",
        required_consecutive_passes=1,
        report_path=tmp_path / "autopilot_latest.json",
        max_runs=1,
        action_runner=lambda *args, **kwargs: None,  # type: ignore[arg-type]
        live_runner=lambda *args, **kwargs: 0,  # type: ignore[no-untyped-def]
        contract_runner=lambda **kwargs: {"status": "pass", "checks": []},  # type: ignore[no-untyped-def]
        rollout_runner=lambda _conn: {"overall_pass": False, "generated_ts": "2026-02-12T00:00:00Z", "gates": {}},  # type: ignore[no-untyped-def]
    )

    latest = report["latest"]
    assert latest["status"] == "rolled_back"
    assert latest["promotion_decision"] == "rollback"
    assert actions == ["shutdown", "compose_up_core"]

    run_row = conn.execute(
        "SELECT status, summary_json FROM autopilot_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert run_row is not None
    assert str(run_row["status"]) == "rolled_back"
    summary = json.loads(str(run_row["summary_json"]))
    assert summary["promotion_decision"] == "rollback"
    conn.close()


def test_autopilot_ignores_missing_scout_by_default(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr("wicap_assist.autopilot.shutil.which", lambda _name: "/usr/bin/fake")

    contract_report = {
        "status": "fail",
        "checks": [
            {"kind": "service_state", "name": "wicap-scout", "severity": "fail", "ok": False, "critical": True},
        ],
    }

    monkeypatch.setattr("wicap_assist.autopilot.run_allowlisted_action", lambda **kwargs: ActuatorResult(status="executed_ok", commands=[], detail="ok", policy_trace={}))  # type: ignore[no-untyped-def]

    report = run_autopilot_supervisor(
        conn,
        mode="assist",
        repo_root=repo_root,
        require_runtime_contract=True,
        require_scout=False,
        perform_startup=False,
        operate_cycles=1,
        operate_interval_seconds=0.1,
        required_consecutive_passes=1,
        gate_history_file=tmp_path / "rollout_history.jsonl",
        report_path=tmp_path / "autopilot_latest.json",
        max_runs=1,
        live_runner=lambda *args, **kwargs: 0,  # type: ignore[no-untyped-def]
        contract_runner=lambda **kwargs: dict(contract_report),  # type: ignore[no-untyped-def]
        rollout_runner=lambda _conn: {"overall_pass": True, "generated_ts": "2026-02-12T00:00:00Z", "gates": {}},  # type: ignore[no-untyped-def]
    )

    assert report["latest"]["status"] in {"hold", "promoted"}
    assert report["latest"]["phase_results"][0]["status"] == "pass"
    conn.close()


def test_autopilot_requires_scout_when_flag_enabled(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr("wicap_assist.autopilot.shutil.which", lambda _name: "/usr/bin/fake")

    contract_report = {
        "status": "fail",
        "checks": [
            {"kind": "service_state", "name": "wicap-scout", "severity": "fail", "ok": False, "critical": True},
        ],
    }

    monkeypatch.setattr("wicap_assist.autopilot.run_allowlisted_action", lambda **kwargs: ActuatorResult(status="executed_ok", commands=[], detail="ok", policy_trace={}))  # type: ignore[no-untyped-def]

    report = run_autopilot_supervisor(
        conn,
        mode="assist",
        repo_root=repo_root,
        require_runtime_contract=True,
        require_scout=True,
        perform_startup=False,
        operate_cycles=1,
        operate_interval_seconds=0.1,
        required_consecutive_passes=1,
        gate_history_file=tmp_path / "rollout_history.jsonl",
        report_path=tmp_path / "autopilot_latest.json",
        max_runs=1,
        live_runner=lambda *args, **kwargs: 0,  # type: ignore[no-untyped-def]
        contract_runner=lambda **kwargs: dict(contract_report),  # type: ignore[no-untyped-def]
        rollout_runner=lambda _conn: {"overall_pass": True, "generated_ts": "2026-02-12T00:00:00Z", "gates": {}},  # type: ignore[no-untyped-def]
    )

    assert report["latest"]["status"] == "failed_preflight"
    assert report["latest"]["phase_results"][0]["status"] == "fail"
    conn.close()
