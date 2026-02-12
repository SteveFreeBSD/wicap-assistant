from __future__ import annotations

import subprocess
from pathlib import Path


def test_autopilot_bootstrap_help() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "autopilot_bootstrap.sh"
    result = subprocess.run(
        ["bash", str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert result.returncode == 0
    assert "One-command clean-boot bootstrap for WiCAP core + assistant autopilot." in result.stdout
    assert "--autopilot-mode MODE" in result.stdout
    assert "--with-scout" in result.stdout


def test_autopilot_bootstrap_contains_autopilot_profile_startup() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "autopilot_bootstrap.sh"
    content = script.read_text(encoding="utf-8")
    assert "--profile autopilot up -d" in content
    assert "WICAP_ASSIST_AUTOPILOT_MODE" in content
    assert "wicap-assist-autopilot" in content
