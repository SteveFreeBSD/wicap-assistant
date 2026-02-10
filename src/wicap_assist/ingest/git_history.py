"""Git history helpers for bundle correlation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
from typing import Callable


@dataclass(slots=True)
class GitCommit:
    """A single git commit summary."""

    hash: str
    author: str
    date: str
    subject: str
    files: list[str]
    overlap_score: int = 0


def compute_window_from_mtimes(file_paths: list[str]) -> tuple[datetime | None, datetime | None]:
    """Compute soak-centric window from mtimes: min-6h to max+1h."""
    mtimes: list[float] = []
    for file_path in file_paths:
        path = Path(file_path)
        try:
            mtimes.append(path.stat().st_mtime)
        except FileNotFoundError:
            continue

    if not mtimes:
        return None, None

    min_dt = datetime.fromtimestamp(min(mtimes), tz=timezone.utc)
    max_dt = datetime.fromtimestamp(max(mtimes), tz=timezone.utc)
    return min_dt - timedelta(hours=6), max_dt + timedelta(hours=1)


def parse_git_log_output(output: str) -> list[GitCommit]:
    """Parse git log output encoded with field/record separators."""
    commits: list[GitCommit] = []
    current: GitCommit | None = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Header lines contain unit separators for hash/author/date/subject.
        if "\x1f" in line:
            header = line.replace("\x1e", "")
            parts = header.split("\x1f")
            if len(parts) < 4:
                continue

            current = GitCommit(
                hash=parts[0],
                author=parts[1],
                date=parts[2],
                subject=parts[3],
                files=[],
            )
            commits.append(current)
            continue

        if current is not None:
            current.files.append(line)

    return commits


def load_git_commits(
    repo_root: Path,
    window_start: datetime | None,
    window_end: datetime | None,
    *,
    max_commits: int = 30,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[GitCommit]:
    """Load commits in a window from local git history."""
    if window_start is None or window_end is None:
        return []

    pretty = "%H%x1f%an%x1f%ad%x1f%s%x1e"
    cmd = [
        "git",
        "-C",
        str(repo_root),
        "log",
        f"--since={window_start.isoformat()}",
        f"--until={window_end.isoformat()}",
        "--date=iso-strict",
        f"--max-count={max_commits}",
        f"--pretty=format:{pretty}",
        "--name-only",
    ]

    result = runner(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []

    return parse_git_log_output(result.stdout)
