"""Deterministic heartbeat/cron scheduling helpers with lease-based dedupe."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Callable, Iterator

from wicap_assist.util.time import utc_now_iso


@dataclass(slots=True)
class SchedulerLease:
    name: str
    lock_path: Path
    owner: str
    acquired: bool
    expires_at: str | None


@dataclass(slots=True)
class CronResult:
    job_name: str
    executed: bool
    skipped_reason: str | None
    lease: SchedulerLease
    payload: dict[str, Any]


def _parse_utc(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _lease_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _write_lease(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def acquire_scheduler_lease(
    *,
    lock_dir: Path,
    name: str,
    owner: str,
    lease_seconds: int = 60,
    now_ts: str | None = None,
) -> SchedulerLease:
    """Acquire a lease for one scheduler job and return lock metadata."""
    now_text = str(now_ts or utc_now_iso())
    now_dt = _parse_utc(now_text) or datetime.now(timezone.utc)
    lock_path = Path(lock_dir) / f"{name}.lock.json"
    current = _lease_payload(lock_path)
    current_owner = str(current.get("owner", "")).strip()
    current_exp = _parse_utc(current.get("expires_at"))

    if current_owner and current_exp is not None and current_exp > now_dt and current_owner != owner:
        return SchedulerLease(
            name=str(name),
            lock_path=lock_path,
            owner=owner,
            acquired=False,
            expires_at=current.get("expires_at"),
        )

    expires_dt = now_dt + timedelta(seconds=max(1, int(lease_seconds)))
    expires_at = expires_dt.isoformat().replace("+00:00", "Z")
    _write_lease(
        lock_path,
        {
            "name": str(name),
            "owner": str(owner),
            "acquired_at": now_text,
            "expires_at": expires_at,
        },
    )
    return SchedulerLease(
        name=str(name),
        lock_path=lock_path,
        owner=str(owner),
        acquired=True,
        expires_at=expires_at,
    )


@contextmanager
def scheduler_lease(
    *,
    lock_dir: Path,
    name: str,
    owner: str,
    lease_seconds: int = 60,
    now_ts: str | None = None,
) -> Iterator[SchedulerLease]:
    lease = acquire_scheduler_lease(
        lock_dir=lock_dir,
        name=name,
        owner=owner,
        lease_seconds=lease_seconds,
        now_ts=now_ts,
    )
    try:
        yield lease
    finally:
        if lease.acquired and lease.lock_path.exists():
            payload = _lease_payload(lease.lock_path)
            if str(payload.get("owner", "")).strip() == str(owner):
                lease.lock_path.unlink(missing_ok=True)


def run_cron_job(
    *,
    job_name: str,
    owner: str,
    job_fn: Callable[[], dict[str, Any]],
    lock_dir: Path,
    lease_seconds: int = 300,
    now_ts: str | None = None,
) -> CronResult:
    """Run one cron job only if lease acquisition succeeds."""
    lease = acquire_scheduler_lease(
        lock_dir=lock_dir,
        name=job_name,
        owner=owner,
        lease_seconds=lease_seconds,
        now_ts=now_ts,
    )
    if not lease.acquired:
        return CronResult(
            job_name=str(job_name),
            executed=False,
            skipped_reason="lease_held",
            lease=lease,
            payload={},
        )
    payload = job_fn()
    return CronResult(
        job_name=str(job_name),
        executed=True,
        skipped_reason=None,
        lease=lease,
        payload=payload if isinstance(payload, dict) else {},
    )


def run_heartbeat_loop(
    *,
    owner: str,
    heartbeat_fn: Callable[[], dict[str, Any]],
    lock_dir: Path,
    iterations: int = 1,
    lease_seconds: int = 20,
) -> list[dict[str, Any]]:
    """Run deterministic heartbeat iterations guarded by lease ownership."""
    out: list[dict[str, Any]] = []
    for idx in range(max(1, int(iterations))):
        with scheduler_lease(
            lock_dir=lock_dir,
            name="heartbeat",
            owner=owner,
            lease_seconds=max(1, int(lease_seconds)),
        ) as lease:
            if not lease.acquired:
                out.append({"iteration": idx, "executed": False, "reason": "lease_held"})
                continue
            payload = heartbeat_fn()
            out.append(
                {
                    "iteration": idx,
                    "executed": True,
                    "payload": payload if isinstance(payload, dict) else {},
                }
            )
    return out
