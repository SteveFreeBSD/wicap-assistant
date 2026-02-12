from __future__ import annotations

from pathlib import Path

import wicap_assist.settings as settings
from wicap_assist.extract.signals import session_gate
from wicap_assist.ingest.antigravity_logs import antigravity_root
from wicap_assist.ingest.codex_jsonl import scan_codex_paths
from wicap_assist.settings import codex_home, repo_url_matches_wicap, wicap_repo_root


def test_codex_home_env_override_is_used_by_scanner(monkeypatch, tmp_path: Path) -> None:
    codex_root = tmp_path / ".codex-custom"
    sessions_dir = codex_root / "sessions" / "2026" / "02" / "11"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    rollout = sessions_dir / "rollout-test.jsonl"
    rollout.write_text("", encoding="utf-8")

    monkeypatch.setenv("CODEX_HOME", str(codex_root))
    assert codex_home() == codex_root

    paths = scan_codex_paths()
    assert rollout in paths


def test_repo_url_hint_override_controls_session_gate(monkeypatch) -> None:
    monkeypatch.setenv("WICAP_REPO_URL_HINTS", "acme/wicap")
    assert repo_url_matches_wicap("https://github.com/acme/wicap.git")
    assert session_gate(None, "https://github.com/acme/wicap.git", False, False) is True
    assert repo_url_matches_wicap("https://github.com/acme/other.git") is False


def test_wicap_repo_root_env_override(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WICAP_REPO_ROOT", str(tmp_path / "wicap-alt"))
    assert wicap_repo_root() == (tmp_path / "wicap-alt")


def test_wicap_repo_root_auto_discovers_sibling_repo(monkeypatch, tmp_path: Path) -> None:
    stack_root = tmp_path / "stack"
    assistant_root = stack_root / "wicap-assistant"
    repo_root = stack_root / "wicap"
    assistant_root.mkdir(parents=True, exist_ok=True)
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / "docker-compose.yml").write_text("services:\n", encoding="utf-8")

    monkeypatch.delenv("WICAP_REPO_ROOT", raising=False)
    monkeypatch.setattr(settings, "_DEFAULT_CONTAINER_WICAP_ROOT", tmp_path / "missing-container")
    monkeypatch.chdir(assistant_root)
    assert wicap_repo_root() == repo_root


def test_antigravity_root_env_override(monkeypatch, tmp_path: Path) -> None:
    custom = tmp_path / "antigravity-root"
    monkeypatch.setenv("WICAP_ASSIST_ANTIGRAVITY_ROOT", str(custom))
    assert antigravity_root() == custom
