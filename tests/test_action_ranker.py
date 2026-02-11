from __future__ import annotations

from pathlib import Path

from wicap_assist.action_ranker import rank_allowlisted_actions
from wicap_assist.db import connect_db, insert_decision_feature


def _observation_with_down_redis() -> dict[str, object]:
    return {
        "ts": "2026-02-12T01:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-ui": {"state": "up", "status": "Up 2m"},
                    "wicap-redis": {"state": "down", "status": "Exited (1)"},
                }
            }
        },
        "top_signatures": [{"signature": "error: redis timeout", "count": 2}],
        "alert": "services_down=wicap-redis",
    }


def test_rank_allowlisted_actions_prefers_historical_restart_on_down_service(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        for idx in range(3):
            insert_decision_feature(
                conn,
                control_session_id=None,
                soak_run_id=None,
                episode_id=None,
                ts=f"2026-02-11T00:00:0{idx}+00:00",
                mode="assist",
                policy_profile="supervised-v1",
                decision="threshold_recover",
                action="restart_service:wicap-redis",
                status="executed_ok",
                feature_json={"seed": idx},
            )
        insert_decision_feature(
            conn,
            control_session_id=None,
            soak_run_id=None,
            episode_id=None,
            ts="2026-02-11T00:00:10+00:00",
            mode="assist",
            policy_profile="supervised-v1",
            decision="threshold_recover",
            action="compose_up",
            status="executed_fail",
            feature_json={"seed": "compose-fail"},
        )
        conn.commit()

        ranked = rank_allowlisted_actions(
            conn,
            observation=_observation_with_down_redis(),
            mode="assist",
            policy_profile="supervised-v1",
            top_n=3,
        )
        assert ranked["top_action"] == "restart_service:wicap-redis"
        assert float(ranked["top_score"]) > 0.0
        assert ranked["rankings"]
    finally:
        conn.close()

