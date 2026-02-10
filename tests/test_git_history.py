from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path

from wicap_assist.ingest.git_history import (
    compute_window_from_mtimes,
    load_git_commits,
    parse_git_log_output,
)


def test_git_window_and_parse_with_mock_runner(tmp_path: Path) -> None:
    file_a = tmp_path / "a.log"
    file_b = tmp_path / "b.log"
    file_a.write_text("a\n", encoding="utf-8")
    file_b.write_text("b\n", encoding="utf-8")

    t1 = 1_700_000_000
    t2 = 1_700_000_600
    os.utime(file_a, (t1, t1))
    os.utime(file_b, (t2, t2))

    window_start, window_end = compute_window_from_mtimes([str(file_a), str(file_b)])
    assert window_start is not None
    assert window_end is not None
    assert int(window_start.timestamp()) == t1 - 6 * 3600
    assert int(window_end.timestamp()) == t2 + 3600

    output = (
        "abc123\x1fAlice\x1f2026-02-10T10:00:00+00:00\x1fFix pyodbc timeout\x1e\n"
        "src/wicap/core/processing/persistence.py\n"
        "wicap-ui/app/static/css/style.css\n\n"
        "def456\x1fBob\x1f2026-02-10T09:00:00+00:00\x1fRefactor\x1e\n"
        "README.md\n"
    )

    captured: dict[str, object] = {}

    class DummyResult:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout
            self.returncode = 0

    def fake_runner(cmd, capture_output, text, check):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd
        return DummyResult(output)

    commits = load_git_commits(
        repo_root=tmp_path,
        window_start=window_start,
        window_end=window_end,
        runner=fake_runner,
    )

    assert len(commits) == 2
    assert commits[0].hash == "abc123"
    assert commits[0].author == "Alice"
    assert commits[0].files == [
        "src/wicap/core/processing/persistence.py",
        "wicap-ui/app/static/css/style.css",
    ]

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert any(str(window_start.isoformat()) in str(part) for part in cmd)
    assert any(str(window_end.isoformat()) in str(part) for part in cmd)


def test_parse_git_log_output_handles_empty() -> None:
    assert parse_git_log_output("") == []
