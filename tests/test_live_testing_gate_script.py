from __future__ import annotations

import subprocess
from pathlib import Path


def test_live_testing_gate_help() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "live_testing_gate.sh"
    result = subprocess.run(
        ["bash", str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert result.returncode == 0
    assert "--no-enforce-contract" in result.stdout
    assert "--no-enforce-rollout" in result.stdout
