from __future__ import annotations

import json
from pathlib import Path

import wicap_assist.cli as cli_mod
from wicap_assist.db import connect_db, insert_forecast_event


def test_agent_explain_policy_json(monkeypatch, tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "assistant.db"

    def fake_collect_policy_explain(*, repo_root):  # type: ignore[no-untyped-def]
        return {
            "ok": True,
            "source": "test",
            "control_plane": {
                "active_policy_profile": "assist-v1",
                "profile_version": "2026.02",
                "runtime_plane": True,
                "tool_policy_plane": True,
                "elevated_plane": False,
                "cooldown_until": None,
            },
            "intel_worker": {
                "latest_anomaly_ts": "2026-02-12T00:00:00Z",
                "latest_prediction_ts": "2026-02-12T00:05:00Z",
            },
            "errors": [],
        }

    monkeypatch.setattr(cli_mod, "collect_policy_explain", fake_collect_policy_explain)

    rc = cli_mod.main(["--db", str(db_path), "agent", "explain-policy", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["ok"] is True
    assert payload["control_plane"]["profile_version"] == "2026.02"


def test_agent_forecast_json_uses_forecast_table(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    try:
        insert_forecast_event(
            conn,
            ts="2026-02-12T01:00:00Z",
            source="test",
            horizon_sec=300,
            risk_score=77.7,
            confidence_low=70.0,
            confidence_high=82.0,
            signature="prediction|test",
            summary="risk rising",
            payload_json={"top_contributors": [{"name": "deauth_rate", "weight": 0.7}]},
        )
        conn.commit()
    finally:
        conn.close()

    rc = cli_mod.main(["--db", str(db_path), "agent", "forecast", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert int(payload["count"]) >= 1
    assert float(payload["latest_risk_score"]) == 77.7


def test_agent_control_center_json(monkeypatch, tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "assistant.db"

    def fake_build_control_center_snapshot(conn, *, mode, repo_root, forecast_lookback_hours):  # type: ignore[no-untyped-def]
        _ = conn
        _ = repo_root
        _ = forecast_lookback_hours
        return {
            "generated_ts": "2026-02-12T02:00:00Z",
            "mode": mode,
            "policy": {"source": "test"},
            "forecast": {"count": 0, "latest_risk_score": 0.0, "max_risk_score": 0.0},
            "drift": {"count": 0, "drift_count": 0, "drift_rate": 0.0, "max_abs_delta": 0.0},
            "observation": {"alert": "", "top_signatures": [], "operator_guidance": []},
        }

    monkeypatch.setattr(cli_mod, "build_control_center_snapshot", fake_build_control_center_snapshot)

    rc = cli_mod.main(["--db", str(db_path), "agent", "control-center", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["mode"] == "observe"
    assert payload["policy"]["source"] == "test"


def test_agent_console_default_path(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "assistant.db"
    seen: dict[str, object] = {}

    def fake_run_agent(path, *, control_mode, observe_interval_seconds):  # type: ignore[no-untyped-def]
        seen["path"] = path
        seen["mode"] = control_mode
        seen["interval"] = observe_interval_seconds
        return 0

    monkeypatch.setattr(cli_mod, "_run_agent", fake_run_agent)
    rc = cli_mod.main(["--db", str(db_path), "agent"])
    assert rc == 0
    assert str(seen["path"]).endswith("assistant.db")
    assert seen["mode"] == "observe"
