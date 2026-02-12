from __future__ import annotations

from pathlib import Path

import wicap_assist.control_center as center
from wicap_assist.db import connect_db, insert_drift_event, insert_forecast_event


def test_build_control_center_snapshot_aggregates_sources(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    try:
        insert_forecast_event(
            conn,
            ts="2026-02-12T03:00:00Z",
            source="test",
            horizon_sec=300,
            risk_score=61.2,
            confidence_low=55.0,
            confidence_high=68.0,
            signature="prediction|a",
            summary="risk rising",
            payload_json={"top_contributors": [{"name": "deauth_rate", "weight": 0.9}]},
        )
        insert_drift_event(
            conn,
            ts="2026-02-12T03:01:00Z",
            source="test",
            status="drift",
            delta=6.1,
            long_mean=20.0,
            short_mean=26.1,
            sample_count=50,
            payload_json={},
        )
        conn.commit()

        monkeypatch.setattr(
            center,
            "collect_live_cycle",
            lambda _conn: {"alert": "", "top_signatures": [], "operator_guidance": []},
        )
        monkeypatch.setattr(
            center,
            "collect_policy_explain",
            lambda *, repo_root=None: {
                "source": "test",
                "control_plane": {"active_policy_profile": "assist-v1", "profile_version": "2026.02"},
                "intel_worker": {"latest_prediction_ts": "2026-02-12T03:00:00Z"},
            },
        )

        payload = center.build_control_center_snapshot(
            conn,
            mode="assist",
            repo_root=Path("/tmp/wicap"),
            forecast_lookback_hours=24,
        )
    finally:
        conn.close()

    assert payload["mode"] == "assist"
    assert payload["policy"]["source"] == "test"
    assert float(payload["forecast"]["latest_risk_score"]) == 61.2
    assert int(payload["drift"]["drift_count"]) == 1
