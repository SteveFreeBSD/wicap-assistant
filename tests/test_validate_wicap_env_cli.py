from __future__ import annotations

import json
from pathlib import Path

import wicap_assist.cli as cli_mod
from wicap_assist.cli import main


def test_validate_wicap_env_cli_json_success(monkeypatch, tmp_path: Path, capsys) -> None:
    def fake_validate_wicap_env(*, repo_root, env_path=None, probe_live=True, require_live=False):
        _ = (repo_root, env_path, probe_live, require_live)
        return {
            "repo_root": str(tmp_path),
            "env_path": str(tmp_path / ".env"),
            "errors": [],
            "warnings": ["warn"],
            "checks": {"ui_reachable": True},
            "ok": True,
        }

    monkeypatch.setattr(cli_mod, "validate_wicap_env", fake_validate_wicap_env)
    rc = main(["validate-wicap-env", "--repo-root", str(tmp_path), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["ok"] is True


def test_validate_wicap_env_cli_returns_nonzero_on_error(monkeypatch, tmp_path: Path) -> None:
    def fake_validate_wicap_env(*, repo_root, env_path=None, probe_live=True, require_live=False):
        _ = (repo_root, env_path, probe_live, require_live)
        return {
            "repo_root": str(tmp_path),
            "env_path": str(tmp_path / ".env"),
            "errors": ["bad"],
            "warnings": [],
            "checks": {},
            "ok": False,
        }

    monkeypatch.setattr(cli_mod, "validate_wicap_env", fake_validate_wicap_env)
    rc = main(["validate-wicap-env", "--repo-root", str(tmp_path), "--no-live-probe"])
    assert rc == 2
