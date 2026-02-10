from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from wicap_assist import cli
from wicap_assist.db import connect_db


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def _base_session_records(*, with_git: bool) -> list[dict]:
    payload = {
        "id": "session-git-persist",
        "cwd": "/home/steve/apps/wicap",
    }
    if with_git:
        payload["git"] = {
            "repository_url": "https://github.com/SteveFreeBSD/wicap.git",
            "branch": "main",
            "commit_hash": "deadbeef",
        }
    return [
        {
            "type": "session_meta",
            "timestamp": "2026-02-10T10:00:00Z",
            "payload": payload,
        },
        {
            "type": "response_item",
            "timestamp": "2026-02-10T10:00:01Z",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "wicap check"}],
            },
        },
    ]


def test_sessions_table_migration_adds_git_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            session_id TEXT NOT NULL,
            cwd TEXT,
            ts_first TEXT,
            ts_last TEXT,
            is_wicap INTEGER NOT NULL,
            raw_path TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

    migrated = connect_db(db_path)
    cols = {
        str(row["name"])
        for row in migrated.execute("PRAGMA table_info(sessions)").fetchall()
    }
    assert "repo_url" in cols
    assert "branch" in cols
    assert "commit_hash" in cols
    migrated.close()


def test_codex_reingest_backfills_git_metadata(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    rollout = tmp_path / "rollout-2026-02-10T10-00-00-test.jsonl"

    _write_jsonl(rollout, _base_session_records(with_git=False))
    monkeypatch.setattr(cli, "scan_codex_paths", lambda: [rollout])

    rc_first = cli._run_ingest(
        db_path,
        scan_codex=True,
        scan_soaks=False,
        scan_harness=False,
        scan_antigravity=False,
        scan_changelog=False,
    )
    assert rc_first == 0

    conn = connect_db(db_path)
    row_first = conn.execute(
        """
        SELECT commit_hash, branch, repo_url
        FROM sessions
        WHERE session_id = 'session-git-persist'
        """
    ).fetchone()
    assert row_first is not None
    assert row_first["commit_hash"] is None
    conn.close()

    _write_jsonl(rollout, _base_session_records(with_git=True))
    rc_second = cli._run_ingest(
        db_path,
        scan_codex=True,
        scan_soaks=False,
        scan_harness=False,
        scan_antigravity=False,
        scan_changelog=False,
    )
    assert rc_second == 0

    conn = connect_db(db_path)
    row_second = conn.execute(
        """
        SELECT commit_hash, branch, repo_url, cwd
        FROM sessions
        WHERE session_id = 'session-git-persist'
        """
    ).fetchone()
    assert row_second is not None
    assert row_second["commit_hash"] == "deadbeef"
    assert row_second["branch"] == "main"
    assert row_second["repo_url"] == "https://github.com/SteveFreeBSD/wicap.git"
    assert row_second["cwd"] == "/home/steve/apps/wicap"
    conn.close()
