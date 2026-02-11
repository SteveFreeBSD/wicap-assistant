"""Runtime settings and path resolution helpers."""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULT_WICAP_REPO_SUFFIX = Path("apps") / "wicap"
_DEFAULT_CODEX_HOME_SUFFIX = Path(".codex")


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    return Path(value).expanduser()


def default_wicap_repo_root() -> Path:
    home = Path.home()
    return (home / _DEFAULT_WICAP_REPO_SUFFIX).expanduser()


def wicap_repo_root() -> Path:
    return _env_path("WICAP_REPO_ROOT") or default_wicap_repo_root()


def default_codex_home() -> Path:
    return (Path.home() / _DEFAULT_CODEX_HOME_SUFFIX).expanduser()


def codex_home() -> Path:
    # Keep compatibility with common XDG-style env vars if present.
    return _env_path("CODEX_HOME") or _env_path("CODEX_ROOT") or default_codex_home()


def wicap_repo_url_hints() -> tuple[str, ...]:
    raw = os.environ.get("WICAP_REPO_URL_HINTS", "").strip()
    if not raw:
        return ("SteveFreeBSD/wicap", "/wicap", "wicap")
    hints = [item.strip() for item in raw.split(",") if item.strip()]
    return tuple(hints) if hints else ("wicap",)


def repo_url_matches_wicap(repo_url: str | None) -> bool:
    if not repo_url:
        return False
    lower_url = str(repo_url).strip().lower()
    if not lower_url:
        return False
    return any(hint.lower() in lower_url for hint in wicap_repo_url_hints())
