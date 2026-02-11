from __future__ import annotations

from wicap_assist.reward_model import compute_reward_signal


def test_compute_reward_signal_positive_for_fast_success() -> None:
    payload = compute_reward_signal(
        event={
            "status": "executed_ok",
            "detail_json": {"max_down_streak": 1, "verification_passed": True},
            "pre_state_json": {"down_services": [], "top_signatures": []},
        },
        prior_stats={"prior_fail": 0, "prior_success_rate": 1.0},
    )
    assert float(payload["reward"]) > 0.35
    assert payload["label"] == "positive"
    components = payload["components"]
    assert float(components["outcome"]) > 0.0
    assert float(components["verification"]) > 0.0


def test_compute_reward_signal_negative_for_failed_recurrence() -> None:
    payload = compute_reward_signal(
        event={
            "status": "executed_fail",
            "detail_json": {"max_down_streak": 7, "verification_failed": True},
            "pre_state_json": {
                "down_services": ["wicap-ui", "wicap-redis"],
                "top_signatures": [{"signature": "error timeout"}, {"signature": "error db"}],
            },
        },
        prior_stats={"prior_fail": 4, "prior_success_rate": 0.2},
    )
    assert float(payload["reward"]) < -0.35
    assert payload["label"] == "negative"
    components = payload["components"]
    assert float(components["recurrence"]) < 0.0
    assert float(components["verification"]) < 0.0


def test_compute_reward_signal_neutral_when_mixed_signals() -> None:
    payload = compute_reward_signal(
        event={
            "status": "executed_ok",
            "detail_json": {"max_down_streak": 8},
            "pre_state_json": {
                "down_services": [],
                "top_signatures": [
                    {"signature": "error timeout"},
                    {"signature": "error db"},
                    {"signature": "error retry"},
                ],
            },
        },
        prior_stats={"prior_fail": 4, "prior_success_rate": 0.6},
    )
    assert -0.35 < float(payload["reward"]) < 0.35
    assert payload["label"] == "neutral"
