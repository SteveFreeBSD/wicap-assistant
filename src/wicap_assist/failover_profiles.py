"""Deterministic auth-profile failover classification and state transitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from wicap_assist.db import (
    insert_failover_event,
    latest_failover_event,
    load_auth_profile_state,
    upsert_auth_profile_state,
)
from wicap_assist.util.time import utc_now_iso


def _parse_utc(ts: str | None) -> datetime | None:
    if not isinstance(ts, str) or not ts.strip():
        return None
    text = ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def classify_failover_failure(*, status: str, detail: str) -> str:
    """Map actuator/runtime failures into stable failover classes."""
    normalized_status = str(status).strip().lower()
    text = f"{normalized_status} {str(detail or '').strip().lower()}"
    if "429" in text or "rate limit" in text:
        return "rate_limit"
    if "auth" in text or "token" in text or "unauthorized" in text or "forbidden" in text:
        return "auth"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if any(token in text for token in ("dns", "connection reset", "refused", "unreachable", "transport", "socket")):
        return "transport"
    if "policy" in text or normalized_status == "rejected":
        return "policy"
    if normalized_status in {"executed_fail", "failed", "error"}:
        return "runtime"
    return "unknown"


@dataclass(slots=True)
class FailoverState:
    auth_profiles: tuple[str, ...] = ("primary", "backup", "safe")
    active_profile: str = "primary"
    attempt: int = 0
    cooldown_until: str | None = None
    disabled_until: str | None = None
    failure_class: str = "none"
    updated_ts: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "auth_profiles": list(self.auth_profiles),
            "auth_profile": self.active_profile,
            "attempt": int(self.attempt),
            "cooldown_until": self.cooldown_until,
            "disabled_until": self.disabled_until,
            "failure_class": self.failure_class,
            "updated_ts": self.updated_ts,
        }


def _next_profile(current: str, profiles: tuple[str, ...]) -> str:
    if not profiles:
        return current
    try:
        idx = profiles.index(current)
    except ValueError:
        return profiles[0]
    return profiles[(idx + 1) % len(profiles)]


def apply_failover_transition(
    state: FailoverState,
    *,
    failure_class: str,
    max_attempts_per_profile: int = 2,
    cooldown_seconds: int = 60,
    disable_seconds: int = 300,
    now_ts: str | None = None,
) -> FailoverState:
    """Apply one deterministic failover transition and return the updated state."""
    now_text = str(now_ts or utc_now_iso())
    now_dt = _parse_utc(now_text) or datetime.now(timezone.utc)
    next_state = FailoverState(
        auth_profiles=tuple(state.auth_profiles),
        active_profile=str(state.active_profile),
        attempt=int(state.attempt),
        cooldown_until=state.cooldown_until,
        disabled_until=state.disabled_until,
        failure_class=str(failure_class).strip() or "unknown",
        updated_ts=now_text,
    )

    if failure_class in {"none", "success"}:
        next_state.attempt = 0
        next_state.cooldown_until = None
        next_state.disabled_until = None
        next_state.failure_class = "none"
        return next_state

    next_state.attempt += 1
    cooldown_dt = now_dt + timedelta(seconds=max(1, int(cooldown_seconds)))
    next_state.cooldown_until = cooldown_dt.isoformat().replace("+00:00", "Z")

    if next_state.attempt >= max(1, int(max_attempts_per_profile)) and failure_class != "policy":
        disable_dt = now_dt + timedelta(seconds=max(1, int(disable_seconds)))
        next_state.disabled_until = disable_dt.isoformat().replace("+00:00", "Z")
        next_state.active_profile = _next_profile(next_state.active_profile, next_state.auth_profiles)
        next_state.attempt = 0

    if failure_class == "policy":
        # Policy denials should not rotate auth profile; they are control-plane issues.
        next_state.cooldown_until = next_state.cooldown_until

    return next_state


def persist_failover_state(
    conn,
    *,
    state: FailoverState,
    control_session_id: int | None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Persist failover transition into state and event tables."""
    upsert_auth_profile_state(
        conn,
        profile=state.active_profile,
        attempt=state.attempt,
        failure_class=state.failure_class,
        cooldown_until=state.cooldown_until,
        disabled_until=state.disabled_until,
        state_json=state.as_dict(),
        updated_ts=state.updated_ts,
    )
    insert_failover_event(
        conn,
        ts=state.updated_ts or utc_now_iso(),
        control_session_id=control_session_id,
        auth_profile=state.active_profile,
        attempt=state.attempt,
        failure_class=state.failure_class,
        cooldown_until=state.cooldown_until,
        disabled_until=state.disabled_until,
        detail_json=detail or {},
    )


def load_failover_state(conn) -> FailoverState:
    """Load latest failover state from DB or return defaults."""
    latest = latest_failover_event(conn)
    if latest is None:
        rows = load_auth_profile_state(conn)
        if rows:
            row = rows[0]
            return FailoverState(
                active_profile=str(row["profile"]),
                attempt=int(row["attempt"] or 0),
                cooldown_until=row["cooldown_until"],
                disabled_until=row["disabled_until"],
                failure_class=str(row["failure_class"] or "none"),
                updated_ts=str(row["updated_ts"] or ""),
            )
        return FailoverState(updated_ts=utc_now_iso())

    return FailoverState(
        active_profile=str(latest["auth_profile"] or "primary"),
        attempt=int(latest["attempt"] or 0),
        cooldown_until=latest["cooldown_until"],
        disabled_until=latest["disabled_until"],
        failure_class=str(latest["failure_class"] or "none"),
        updated_ts=str(latest["ts"] or ""),
    )


def failover_state_snapshot(conn) -> dict[str, Any]:
    """Build JSON-ready failover state snapshot for CLI surfaces."""
    state = load_failover_state(conn)
    payload = state.as_dict()
    payload["generated_ts"] = utc_now_iso()
    return payload
