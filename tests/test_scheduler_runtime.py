from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.db import connect_db
from wicap_assist.scheduler_runtime import run_scheduler_loop


def test_scheduler_once_executes_heartbeat_and_cron(tmp_path: Path, monkeypatch) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    memory_report = tmp_path / "memory_latest.json"
    rollout_history = tmp_path / "rollout_history.jsonl"

    monkeypatch.setattr("wicap_assist.scheduler_runtime.run_live_monitor", lambda *args, **kwargs: 0)

    report = run_scheduler_loop(
        conn,
        owner="worker-a",
        lock_dir=tmp_path / "locks",
        state_path=tmp_path / "state.json",
        control_mode="observe",
        heartbeat_interval_seconds=0.1,
        memory_maintenance_interval_seconds=0,
        rollout_gates_interval_seconds=0,
        memory_report_output=memory_report,
        rollout_history_file=rollout_history,
        once=True,
    )

    assert report["heartbeat_executed"] == 1
    assert report["heartbeat_skipped"] == 0
    assert report["cron_executed"]["memory-maintenance"] == 1
    assert report["cron_executed"]["rollout-gates"] == 1
    assert memory_report.exists()
    assert rollout_history.exists()
    assert (tmp_path / "state.json").exists()
    conn.close()


def test_scheduler_skips_cron_when_interval_not_elapsed(tmp_path: Path, monkeypatch) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    monkeypatch.setattr("wicap_assist.scheduler_runtime.run_live_monitor", lambda *args, **kwargs: 0)

    state_path = tmp_path / "state.json"
    lock_dir = tmp_path / "locks"

    first = run_scheduler_loop(
        conn,
        owner="worker-a",
        lock_dir=lock_dir,
        state_path=state_path,
        control_mode="observe",
        heartbeat_interval_seconds=0.1,
        memory_maintenance_interval_seconds=3600,
        rollout_gates_interval_seconds=3600,
        once=True,
        now_fn=lambda: "2026-02-12T00:00:00Z",
    )
    second = run_scheduler_loop(
        conn,
        owner="worker-a",
        lock_dir=lock_dir,
        state_path=state_path,
        control_mode="observe",
        heartbeat_interval_seconds=0.1,
        memory_maintenance_interval_seconds=3600,
        rollout_gates_interval_seconds=3600,
        once=True,
        now_fn=lambda: "2026-02-12T00:00:10Z",
    )

    assert first["cron_executed"]["memory-maintenance"] == 1
    assert first["cron_executed"]["rollout-gates"] == 1
    assert second["cron_executed"]["memory-maintenance"] == 0
    assert second["cron_executed"]["rollout-gates"] == 0
    assert second["cron_skipped"]["memory-maintenance"] >= 1
    assert second["cron_skipped"]["rollout-gates"] >= 1
    conn.close()


def test_scheduler_heartbeat_lease_conflict_skips_execution(tmp_path: Path, monkeypatch) -> None:
    conn = connect_db(tmp_path / "assistant.db")

    def _fail_if_called(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("run_live_monitor should not run when heartbeat lease is held by another owner")

    monkeypatch.setattr("wicap_assist.scheduler_runtime.run_live_monitor", _fail_if_called)

    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    (lock_dir / "heartbeat.lock.json").write_text(
        json.dumps(
            {
                "name": "heartbeat",
                "owner": "worker-a",
                "acquired_at": "2026-02-12T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    report = run_scheduler_loop(
        conn,
        owner="worker-b",
        lock_dir=lock_dir,
        state_path=tmp_path / "state.json",
        once=True,
        memory_maintenance_interval_seconds=3600,
        rollout_gates_interval_seconds=3600,
        now_fn=lambda: "2026-02-12T00:00:01Z",
    )

    assert report["heartbeat_executed"] == 0
    assert report["heartbeat_skipped"] == 1
    conn.close()
