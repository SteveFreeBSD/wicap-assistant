from __future__ import annotations

import subprocess
from pathlib import Path


def test_server_rollout_smoke_help() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "server_rollout_smoke.sh"
    result = subprocess.run(
        ["bash", str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert result.returncode == 0
    assert "SSH-safe cross-repo rollout smoke" in result.stdout
    assert "--with-scout" in result.stdout
    assert "--enforce-contract" in result.stdout


def test_server_rollout_smoke_uses_python3_for_assistant_cli() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "server_rollout_smoke.sh"
    content = script.read_text(encoding="utf-8")
    assert "python -m wicap_assist.cli" not in content
    assert "python3 -m wicap_assist.cli" in content
