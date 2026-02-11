"""Configuration helpers (env-first) for portable deployments."""

from __future__ import annotations

from pathlib import Path

from wicap_assist.settings import default_wicap_repo_root, wicap_repo_root as _wicap_repo_root

DEFAULT_WICAP_REPO_ROOT = str(default_wicap_repo_root())


def wicap_repo_root() -> Path:
    """Return WICAP repository root path.

    Set `WICAP_REPO_ROOT` to override for non-standard layouts or container mounts.
    """
    return _wicap_repo_root()


def wicap_changelog_path() -> Path:
    return wicap_repo_root() / "CHANGELOG.md"
