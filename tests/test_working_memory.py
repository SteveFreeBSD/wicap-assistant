from __future__ import annotations

from wicap_assist.working_memory import summarize_working_memory, update_working_memory


def test_update_working_memory_tracks_unresolved_and_pending() -> None:
    observation = {
        "ts": "2026-02-12T01:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-redis": {"state": "down", "status": "Exited"},
                    "wicap-ui": {"state": "up", "status": "Up"},
                }
            }
        },
        "top_signatures": [{"signature": "error: redis timeout", "count": 2}],
    }
    events = [
        {
            "ts": "2026-02-12T01:00:00+00:00",
            "decision": "threshold_recover",
            "action": "restart_service:wicap-redis",
            "status": "executed_fail",
            "detail_json": {"service": "wicap-redis"},
        }
    ]
    state = update_working_memory({}, observation=observation, cycle_control_events=events)
    assert state["unresolved_signatures"]
    assert state["pending_actions"]
    assert state["down_services"] == ["wicap-redis"]
    summary = summarize_working_memory(state)
    assert int(summary["unresolved_count"]) == 1
    assert int(summary["pending_count"]) == 1


def test_update_working_memory_clears_pending_when_system_stable() -> None:
    prior = {
        "unresolved_signatures": ["error: redis timeout"],
        "pending_actions": ["restart_service:wicap-redis"],
        "recent_transitions": [],
        "down_services": ["wicap-redis"],
        "last_observation_ts": "2026-02-12T01:00:00+00:00",
    }
    observation = {
        "ts": "2026-02-12T01:01:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-redis": {"state": "up", "status": "Up"},
                    "wicap-ui": {"state": "up", "status": "Up"},
                }
            }
        },
        "top_signatures": [],
    }
    state = update_working_memory(prior, observation=observation, cycle_control_events=[])
    assert state["unresolved_signatures"] == []
    assert state["pending_actions"] == []
    assert state["down_services"] == []

