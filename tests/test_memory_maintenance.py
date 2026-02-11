from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.db import (
    connect_db,
    insert_control_session,
    insert_decision_feature,
    update_control_session,
)
from wicap_assist.memory_maintenance import run_memory_maintenance, write_memory_maintenance_report


def test_run_memory_maintenance_is_deterministic_without_pruning(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        insert_decision_feature(
            conn,
            control_session_id=None,
            soak_run_id=None,
            episode_id=None,
            ts="2026-02-10T00:00:00+00:00",
            mode="assist",
            policy_profile="supervised-v1",
            decision="threshold_recover",
            action="restart_service:wicap-redis",
            status="executed_ok",
            feature_json={"reward_value": 0.4},
        )
        insert_decision_feature(
            conn,
            control_session_id=None,
            soak_run_id=None,
            episode_id=None,
            ts="2026-02-10T00:01:00+00:00",
            mode="assist",
            policy_profile="supervised-v1",
            decision="threshold_recover",
            action="restart_service:wicap-redis",
            status="executed_fail",
            feature_json={"reward_value": -0.2},
        )
        session_id = insert_control_session(
            conn,
            soak_run_id=None,
            started_ts="2026-02-01T00:00:00+00:00",
            mode="assist",
            status="running",
            current_phase="finalize",
            metadata_json={
                "working_memory": {
                    "unresolved_signatures": ["error: redis timeout"],
                    "pending_actions": ["restart_service:wicap-redis"],
                }
            },
        )
        update_control_session(
            conn,
            control_session_id=session_id,
            ended_ts="2026-02-01T00:10:00+00:00",
            status="completed",
        )
        conn.commit()

        run1 = run_memory_maintenance(
            conn,
            lookback_days=30,
            stale_days=7,
            prune_stale=False,
            now_ts="2026-02-12T00:00:00+00:00",
        )
        run2 = run_memory_maintenance(
            conn,
            lookback_days=30,
            stale_days=7,
            prune_stale=False,
            now_ts="2026-02-12T00:00:00+00:00",
        )
        assert run1 == run2
        assert int(run1["stale_session_count"]) == 1
        assert int(run1["pruned_session_count"]) == 0
        assert run1["action_health"]
    finally:
        conn.close()


def test_run_memory_maintenance_prunes_stale_working_memory(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    try:
        session_id = insert_control_session(
            conn,
            soak_run_id=None,
            started_ts="2026-02-01T00:00:00+00:00",
            mode="assist",
            status="running",
            current_phase="finalize",
            metadata_json={
                "working_memory": {
                    "unresolved_signatures": ["error: redis timeout"],
                    "pending_actions": ["restart_service:wicap-redis"],
                    "recent_transitions": ["x"],
                }
            },
        )
        update_control_session(
            conn,
            control_session_id=session_id,
            ended_ts="2026-02-01T00:10:00+00:00",
            status="completed",
        )
        conn.commit()

        first = run_memory_maintenance(
            conn,
            lookback_days=30,
            stale_days=7,
            prune_stale=True,
            now_ts="2026-02-12T00:00:00+00:00",
        )
        assert int(first["pruned_session_count"]) == 1
        row = conn.execute("SELECT metadata_json FROM control_sessions WHERE id = ?", (session_id,)).fetchone()
        assert row is not None
        payload = json.loads(str(row["metadata_json"]))
        working = payload.get("working_memory", {})
        assert working.get("unresolved_signatures") == []
        assert working.get("pending_actions") == []

        second = run_memory_maintenance(
            conn,
            lookback_days=30,
            stale_days=7,
            prune_stale=True,
            now_ts="2026-02-12T00:00:00+00:00",
        )
        assert int(second["pruned_session_count"]) == 0
        assert int(second["stale_session_count"]) == 0
    finally:
        conn.close()


def test_write_memory_maintenance_report_writes_json_file(tmp_path: Path) -> None:
    report = {
        "generated_ts": "2026-02-12T00:00:00+00:00",
        "decision_rows_analyzed": 1,
        "stale_session_count": 0,
        "pruned_session_count": 0,
    }
    path = write_memory_maintenance_report(report, tmp_path / "reports" / "memory.json")
    assert Path(path).exists()
    persisted = json.loads(Path(path).read_text(encoding="utf-8"))
    assert persisted["generated_ts"] == report["generated_ts"]
