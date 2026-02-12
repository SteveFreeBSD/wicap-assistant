from __future__ import annotations

import subprocess
from pathlib import Path


def test_comprehensive_sweep_help() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "comprehensive_sweep.sh"
    result = subprocess.run(
        ["bash", str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert result.returncode == 0
    assert "Comprehensive end-to-end sweep for WiCAP + wicap-assistant." in result.stdout
    assert "--ui-timeout-seconds N" in result.stdout
    assert "--no-start-autopilot-service" in result.stdout
    assert "--run-certifications" in result.stdout
    assert "--strict" in result.stdout


def test_comprehensive_sweep_wires_expected_substeps() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "comprehensive_sweep.sh"
    content = script.read_text(encoding="utf-8")
    assert "scripts/autopilot_bootstrap.sh" in content
    assert "--core-only" in content
    assert "core_reconcile" in content
    assert "scripts/server_rollout_smoke.sh" in content
    assert "scripts/live_testing_gate.sh" in content
    assert "--no-enforce-contract" in content
    assert "autopilot_quiesce" in content
    assert "--gate-history-file" in content
    assert "--history-file" in content
    assert "--allow-scout-down" in content
    assert "--enforce --json" in content
    assert "--operate-interval-seconds" in content
    assert "--no-rollback-on-verify-failure" in content
    assert "--stop-on-escalation" not in content
    assert "strict retry mode adjusted to '" in content
    assert "shadow sample deficit=" in content
    assert "python3 -m wicap_assist.cli --db" in content
    assert "autopilot --control-mode" in content
