from __future__ import annotations

from pathlib import Path
import subprocess

from wicap_assist.policy_explain import collect_policy_explain


def test_collect_policy_explain_uses_status_script_output(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    script = repo_root / "scripts" / "check_wicap_status.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    payload = (
        "{"
        '"generated_at":"2026-02-12T00:00:00Z",'
        '"local":{"control_plane":{"runtime_plane":true,"tool_policy_plane":true,'
        '"elevated_plane":false,"active_policy_profile":"assist-v1","profile_version":"2026.02",'
        '"cooldown_until":null},'
        '"last_anomaly_v2":{"ts":"2026-02-12T00:01:00Z","drift_state":{"status":"stable","delta":0.1,"sample_count":50}},'
        '"last_prediction":{"ts":"2026-02-12T00:02:00Z"}}'
        "}"
    )

    def fake_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args
        _ = kwargs
        return subprocess.CompletedProcess(
            args=["python3", str(script), "--local-only", "--json"],
            returncode=0,
            stdout=payload,
            stderr="",
        )

    result = collect_policy_explain(repo_root=repo_root, runner=fake_runner)
    assert result["ok"] is True
    assert result["source"] == "check_wicap_status_json"
    assert result["control_plane"]["active_policy_profile"] == "assist-v1"
    assert result["intel_worker"]["latest_prediction_ts"] == "2026-02-12T00:02:00Z"


def test_collect_policy_explain_falls_back_to_env(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE", "observe-v1")
    monkeypatch.setenv("WICAP_CONTROL_ACTIVE_POLICY_PROFILE_VERSION", "2026.03")
    monkeypatch.setenv("WICAP_CONTROL_RUNTIME_PLANE_ENABLED", "true")
    monkeypatch.setenv("WICAP_CONTROL_TOOL_POLICY_PLANE_ENABLED", "false")

    result = collect_policy_explain(repo_root=repo_root)
    assert result["ok"] is False
    assert result["source"] == "env_fallback"
    assert result["control_plane"]["profile_version"] == "2026.03"
    assert result["control_plane"]["tool_policy_plane"] is False
