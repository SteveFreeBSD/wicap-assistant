from __future__ import annotations

from pathlib import Path

from wicap_assist.db import connect_db, insert_control_episode
from wicap_assist.memory_semantic import retrieve_episode_memories
from wicap_assist.recommend import build_recommendation


def _insert_episode(
    conn,
    *,
    ts: str,
    action: str,
    status: str,
    signature: str,
) -> int:
    return insert_control_episode(
        conn,
        control_session_id=None,
        soak_run_id=None,
        ts=ts,
        decision="threshold_recover",
        action=action,
        status=status,
        pre_state_json={
            "alert": "services_down=wicap-redis",
            "down_services": ["wicap-redis"],
            "top_signatures": [
                {
                    "signature": signature,
                    "count": 2,
                }
            ],
        },
        post_state_json={"status": status},
        detail_json={"service": "wicap-redis"},
    )


def test_retrieve_episode_memories_ranks_successful_actions_first(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        target = "error: redis timeout on reconnect"
        fail_id = _insert_episode(
            conn,
            ts="2026-02-11T09:00:00+00:00",
            action="compose_up",
            status="executed_fail",
            signature=target,
        )
        ok_id = _insert_episode(
            conn,
            ts="2026-02-11T09:05:00+00:00",
            action="restart_service:wicap-redis",
            status="executed_ok",
            signature=target,
        )
        conn.commit()

        memories = retrieve_episode_memories(conn, target, limit=3)
        assert memories
        assert int(memories[0]["episode_id"]) == int(ok_id)
        assert str(memories[0]["action"]) == "restart_service:wicap-redis"
        assert int(memories[0]["match_score"]) >= int(memories[-1]["match_score"])
        assert int(fail_id) in {int(item["episode_id"]) for item in memories}
    finally:
        conn.close()


def test_recommendation_falls_back_to_memory_when_context_is_missing(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        target = "error: redis timeout on reconnect"
        _insert_episode(
            conn,
            ts="2026-02-11T09:05:00+00:00",
            action="restart_service:wicap-redis",
            status="executed_ok",
            signature=target,
        )
        conn.commit()

        payload = build_recommendation(conn, target)
        assert payload["recommended_action"].startswith("Replay historically successful control action:")
        assert float(payload["confidence"]) > 0.0
        assert int(payload["memory_episode_count"]) >= 1
        assert payload["memory_episodes"]
    finally:
        conn.close()

