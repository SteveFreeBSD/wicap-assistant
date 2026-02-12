"""Runtime settings and path resolution helpers."""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULT_WICAP_REPO_SUFFIX = Path("apps") / "wicap"
_DEFAULT_CODEX_HOME_SUFFIX = Path(".codex")
_DEFAULT_CONTAINER_WICAP_ROOT = Path("/wicap")
_DEFAULT_WICAP_DIRNAME = "wicap"


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    return Path(value).expanduser()


def _looks_like_wicap_repo(path: Path) -> bool:
    if not path.is_dir():
        return False
    markers = (
        path / "docker-compose.yml",
        path / "start_wicap.py",
        path / "wicap-ui",
    )
    return any(marker.exists() for marker in markers)


def _candidate_wicap_repo_roots() -> list[Path]:
    candidates: list[Path] = []
    # Container runtime mount target used by compose sidecar.
    candidates.append(_DEFAULT_CONTAINER_WICAP_ROOT)
    # Common host layouts: run from wicap-assistant directory or a child folder.
    cwd = Path.cwd().resolve()
    candidates.append(cwd / _DEFAULT_WICAP_DIRNAME)
    candidates.append(cwd.parent / _DEFAULT_WICAP_DIRNAME)
    # Legacy home layout remains as final fallback.
    candidates.append((Path.home() / _DEFAULT_WICAP_REPO_SUFFIX).expanduser())

    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        expanded = candidate.expanduser()
        if expanded in seen:
            continue
        seen.add(expanded)
        deduped.append(expanded)
    return deduped


def default_wicap_repo_root() -> Path:
    for candidate in _candidate_wicap_repo_roots():
        if _looks_like_wicap_repo(candidate):
            return candidate
    # Keep deterministic fallback even before the repo is cloned.
    return (Path.home() / _DEFAULT_WICAP_REPO_SUFFIX).expanduser()


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
