from __future__ import annotations

import json
from pathlib import Path

import wicap_assist.cli as cli_module
from wicap_assist.db import connect_db
from wicap_assist.ingest.codex_jsonl import parse_codex_file


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_parse_rollout_extracts_operational_signals(tmp_path: Path) -> None:
    path = tmp_path / "rollout-2026-02-09T21-46-38-abc.jsonl"
    records = [
        {
            "type": "session_meta",
            "timestamp": "2026-02-09T21:46:38Z",
            "payload": {
                "id": "session-123",
                "cwd": "/home/steve/apps/wicap",
                "git": {
                    "repository_url": "https://github.com/SteveFreeBSD/wicap.git",
                    "branch": "main",
                    "commit_hash": "deadbeef",
                },
            },
        },
        {
            "type": "response_item",
            "timestamp": "2026-02-09T21:46:40Z",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": "\n".join(
                            [
                                "cd /home/steve/apps/wicap",
                                "python scripts/check.py --token=abc123",
                                "Error: failed to open /home/steve/apps/wicap/config.yaml permission denied",
                                "fixed wicap startup after systemctl restart wicap.service",
                            ]
                        ),
                    }
                ],
            },
        },
    ]
    _write_jsonl(path, records)

    sessions = parse_codex_file(path)
    assert len(sessions) == 1

    parsed = sessions[0]
    assert parsed.is_wicap is True
    assert parsed.session_id == "session-123"

    categories = {signal.category for signal in parsed.signals}
    assert "commands" in categories
    assert "file_paths" in categories
    assert "errors" in categories
    assert "outcomes" in categories

    assert any("<redacted>" in signal.snippet for signal in parsed.signals)
    assert all(len(signal.snippet) <= 200 for signal in parsed.signals)


def test_parse_rollout_non_wicap_session(tmp_path: Path) -> None:
    path = tmp_path / "rollout-2026-02-09T21-46-38-other.jsonl"
    records = [
        {
            "type": "session_meta",
            "timestamp": "2026-02-09T21:46:38Z",
            "payload": {
                "id": "session-999",
                "cwd": "/tmp/not-wicap",
                "git": {"repository_url": "https://example.com/other.git"},
            },
        },
        {
            "type": "response_item",
            "timestamp": "2026-02-09T21:46:40Z",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "python scripts/check.py"}],
            },
        },
    ]
    _write_jsonl(path, records)

    sessions = parse_codex_file(path)
    assert len(sessions) == 1
    assert sessions[0].is_wicap is False


def test_codex_ingest_is_idempotent_for_unchanged_sources(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "rollout-2026-02-09T21-46-38-idem.jsonl"
    records = [
        {
            "type": "session_meta",
            "timestamp": "2026-02-09T21:46:38Z",
            "payload": {
                "id": "session-idem",
                "cwd": "/home/steve/apps/wicap",
                "git": {
                    "repository_url": "https://github.com/SteveFreeBSD/wicap.git",
                    "branch": "main",
                    "commit_hash": "cafefeed",
                },
            },
        },
        {
            "type": "response_item",
            "timestamp": "2026-02-09T21:46:40Z",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": "\n".join(
                            [
                                "$ cd /home/steve/apps/wicap",
                                "python scripts/check_wicap_status.py --sql-only",
                                "Error: failed to open /home/steve/apps/wicap/config.yaml permission denied",
                                "fixed wicap startup after systemctl restart wicap.service",
                            ]
                        ),
                    }
                ],
            },
        },
    ]
    _write_jsonl(path, records)

    monkeypatch.setattr(cli_module, "scan_codex_paths", lambda: [path])
    db_path = tmp_path / "assistant.db"

    rc_first = cli_module._run_ingest(
        db_path,
        scan_codex=True,
        scan_soaks=False,
        scan_harness=False,
        scan_antigravity=False,
        scan_changelog=False,
    )
    assert rc_first == 0

    conn = connect_db(db_path)
    first_counts = {
        "sessions": int(conn.execute("SELECT count(*) AS cnt FROM sessions").fetchone()["cnt"]),
        "signals": int(conn.execute("SELECT count(*) AS cnt FROM signals").fetchone()["cnt"]),
        "sources": int(conn.execute("SELECT count(*) AS cnt FROM sources").fetchone()["cnt"]),
    }
    conn.close()

    rc_second = cli_module._run_ingest(
        db_path,
        scan_codex=True,
        scan_soaks=False,
        scan_harness=False,
        scan_antigravity=False,
        scan_changelog=False,
    )
    assert rc_second == 0

    conn = connect_db(db_path)
    second_counts = {
        "sessions": int(conn.execute("SELECT count(*) AS cnt FROM sessions").fetchone()["cnt"]),
        "signals": int(conn.execute("SELECT count(*) AS cnt FROM signals").fetchone()["cnt"]),
        "sources": int(conn.execute("SELECT count(*) AS cnt FROM sources").fetchone()["cnt"]),
    }
    conn.close()

    assert first_counts["sessions"] == 1
    assert first_counts["signals"] >= 1
    assert first_counts == second_counts
