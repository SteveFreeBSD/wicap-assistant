from __future__ import annotations

from wicap_assist.db import (
    connect_db,
    insert_control_event,
    insert_control_session,
    insert_decision_feature,
    update_control_session,
)
from wicap_assist.rollout_gates import evaluate_rollout_gates
from wicap_assist.rollout_gates import evaluate_promotion_readiness


def test_evaluate_rollout_gates_passes_with_healthy_metrics(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        for idx in range(220):
            minute = idx // 60
            second = idx % 60
            insert_decision_feature(
                conn,
                control_session_id=None,
                soak_run_id=None,
                episode_id=None,
                ts=f"2026-02-11T00:{minute:02d}:{second:02d}+00:00",
                mode="autonomous",
                policy_profile="autonomous-v1",
                decision="threshold_recover",
                action="restart_service:wicap-redis",
                status="executed_ok",
                feature_json={
                    "reward_value": 0.2,
                    "shadow_gate_samples": 220,
                    "shadow_gate_agreement_rate": 0.82,
                    "shadow_gate_success_rate": 0.74,
                    "shadow_gate_passes": True,
                },
            )

        for idx in range(13):
            session_id = insert_control_session(
                conn,
                soak_run_id=None,
                started_ts=f"2026-02-11T01:00:{idx:02d}+00:00",
                mode="autonomous",
                status="running",
                current_phase="finalize",
                metadata_json={},
            )
            update_control_session(
                conn,
                control_session_id=session_id,
                ended_ts=f"2026-02-11T01:10:{idx:02d}+00:00",
                status="escalated" if idx == 0 else "completed",
            )

        insert_control_event(
            conn,
            soak_run_id=None,
            ts="2026-02-11T02:00:00+00:00",
            decision="rollback_rule",
            action="rollback_sequence",
            status="executed_fail",
            episode_id=None,
            detail_json={},
        )
        conn.commit()

        report = evaluate_rollout_gates(conn, lookback_days=14, now_ts="2026-02-12T00:00:00+00:00")
        assert bool(report["overall_pass"]) is True
        gates = report["gates"]
        assert gates["shadow_quality"]["status"] == "pass"
        assert gates["autonomous_escalation"]["status"] == "pass"
        assert gates["rollback_budget"]["status"] == "pass"
        assert gates["reward_stability"]["status"] == "pass"
    finally:
        conn.close()


def test_evaluate_rollout_gates_fails_with_insufficient_shadow_data(tmp_path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        report = evaluate_rollout_gates(
            conn,
            lookback_days=14,
            min_shadow_samples=10,
            min_autonomous_runs=2,
            now_ts="2026-02-12T00:00:00+00:00",
        )
        assert bool(report["overall_pass"]) is False
        gates = report["gates"]
        assert gates["shadow_quality"]["status"] == "insufficient_data"
        assert gates["autonomous_escalation"]["status"] == "insufficient_data"
    finally:
        conn.close()


def test_evaluate_promotion_readiness_requires_consecutive_passes() -> None:
    history = [
        {"generated_ts": "2026-02-10T00:00:00+00:00", "overall_pass": True},
        {"generated_ts": "2026-02-11T00:00:00+00:00", "overall_pass": True},
    ]
    report = evaluate_promotion_readiness(history, required_consecutive_passes=2)
    assert bool(report["ready"]) is True
    assert int(report["consecutive_passes"]) == 2

    history_with_fail = [
        {"generated_ts": "2026-02-10T00:00:00+00:00", "overall_pass": True},
        {"generated_ts": "2026-02-11T00:00:00+00:00", "overall_pass": False},
        {"generated_ts": "2026-02-12T00:00:00+00:00", "overall_pass": True},
    ]
    report2 = evaluate_promotion_readiness(history_with_fail, required_consecutive_passes=2)
    assert bool(report2["ready"]) is False
    assert int(report2["consecutive_passes"]) == 1
