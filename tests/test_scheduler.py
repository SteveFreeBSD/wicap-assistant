from __future__ import annotations

from pathlib import Path

from wicap_assist.scheduler import acquire_scheduler_lease, run_cron_job


def test_acquire_scheduler_lease_blocks_other_owner_until_expiry(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    first = acquire_scheduler_lease(
        lock_dir=lock_dir,
        name="memory-maintenance",
        owner="worker-a",
        lease_seconds=60,
        now_ts="2026-02-12T00:00:00Z",
    )
    second = acquire_scheduler_lease(
        lock_dir=lock_dir,
        name="memory-maintenance",
        owner="worker-b",
        lease_seconds=60,
        now_ts="2026-02-12T00:00:10Z",
    )
    assert first.acquired is True
    assert second.acquired is False


def test_run_cron_job_executes_once_with_lease(tmp_path: Path) -> None:
    lock_dir = tmp_path / "locks"
    call_count = {"n": 0}

    def _job():
        call_count["n"] += 1
        return {"ok": True}

    first = run_cron_job(
        job_name="memory-maintenance",
        owner="worker-a",
        job_fn=_job,
        lock_dir=lock_dir,
        lease_seconds=120,
        now_ts="2026-02-12T00:00:00Z",
    )
    second = run_cron_job(
        job_name="memory-maintenance",
        owner="worker-b",
        job_fn=_job,
        lock_dir=lock_dir,
        lease_seconds=120,
        now_ts="2026-02-12T00:00:30Z",
    )
    assert first.executed is True
    assert second.executed is False
    assert call_count["n"] == 1
