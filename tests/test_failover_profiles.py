from __future__ import annotations

from wicap_assist.db import connect_db
from wicap_assist.failover_profiles import (
    FailoverState,
    apply_failover_transition,
    classify_failover_failure,
    load_failover_state,
    persist_failover_state,
)


def test_classify_failover_failure_maps_common_cases() -> None:
    assert classify_failover_failure(status="executed_fail", detail="HTTP 429 rate limit") == "rate_limit"
    assert classify_failover_failure(status="executed_fail", detail="auth token expired") == "auth"
    assert classify_failover_failure(status="executed_fail", detail="socket timeout") == "timeout"
    assert classify_failover_failure(status="rejected", detail="policy denied") == "policy"


def test_apply_failover_transition_rotates_profile_after_attempt_budget() -> None:
    state = FailoverState(active_profile="primary", attempt=1)
    updated = apply_failover_transition(
        state,
        failure_class="rate_limit",
        max_attempts_per_profile=2,
        now_ts="2026-02-12T00:00:00Z",
    )
    assert updated.active_profile == "backup"
    assert updated.attempt == 0
    assert updated.failure_class == "rate_limit"


def test_persist_and_load_failover_state_roundtrip(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        state = FailoverState(
            active_profile="backup",
            attempt=1,
            cooldown_until="2026-02-12T00:05:00Z",
            disabled_until=None,
            failure_class="timeout",
            updated_ts="2026-02-12T00:00:00Z",
        )
        persist_failover_state(conn, state=state, control_session_id=None, detail={"k": "v"})
        conn.commit()

        loaded = load_failover_state(conn)
        assert loaded.active_profile == "backup"
        assert loaded.attempt == 1
        assert loaded.failure_class == "timeout"
    finally:
        conn.close()
