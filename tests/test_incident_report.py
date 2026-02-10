from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.incident import load_bundle_json, write_incident_report
from wicap_assist.db import connect_db


def test_incident_report_creates_file_and_updates_index(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")

    source_path = "/home/steve/apps/wicap/logs_soak_fake/run.log"
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", source_path, 1.0, 100),
    )
    source_id = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            "2026-02-10 09:00:00",
            "error",
            "fp1",
            "Error: pyodbc setinputsizes failed",
            source_path,
            "{}",
        ),
    )
    cur.execute(
        """
        INSERT INTO harness_scripts(script_path, role, commands_json, tools_json, env_vars_json, last_modified)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            "/home/steve/apps/wicap/stop_wicap.py",
            "cleanup",
            json.dumps(["python scripts/check.py", "docker compose down"], sort_keys=True),
            json.dumps(["python", "docker"], sort_keys=True),
            json.dumps(["WICAP_ENV"], sort_keys=True),
            "2026-02-10T08:00:00+00:00",
        ),
    )
    conn.commit()

    bundle_json = {
        "target": "logs_soak_fake",
        "log_summary": {
            "error": [{"count": 3, "snippet": "Error: pyodbc setinputsizes failed", "file": source_path}],
            "docker_fail": [{"count": 1, "snippet": "docker restart failed", "file": source_path}],
            "pytest_fail": [{"count": 2, "snippet": "AssertionError in soak", "file": source_path}],
        },
        "related_sessions": [
            {
                "session_id": "session-1",
                "ts_last": "2026-02-10T10:00:00+00:00",
                "cwd": "/home/steve/apps/wicap",
                "git": {
                    "repo_url": "https://github.com/SteveFreeBSD/wicap.git",
                    "branch": "main",
                    "commit_hash": "deadbeef",
                },
                "source": "/home/steve/.codex/sessions/2026/02/10/rollout-1.jsonl",
                "matches": {
                    "commands": [{"snippet": "python scripts/check.py", "fingerprint": "c1"}],
                    "errors": [{"snippet": "Error: pyodbc timeout", "fingerprint": "e1"}],
                    "file_paths": [{"snippet": "src/wicap/core/processing/persistence.py", "fingerprint": "f1"}],
                    "outcomes": [{"snippet": "fixed pyodbc retry path", "fingerprint": "o1"}],
                },
            }
        ],
        "git_commits": [
            {
                "hash": "abc123",
                "date": "2026-02-10T08:30:00+00:00",
                "subject": "Fix pyodbc handling",
                "files": ["src/wicap/core/processing/persistence.py"],
                "overlap_score": 1,
            }
        ],
    }

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle_json), encoding="utf-8")
    loaded_bundle = load_bundle_json(bundle_path)

    incidents_dir = tmp_path / "wicap" / "docs" / "incidents"
    report_path = write_incident_report(
        conn,
        target="logs_soak_fake",
        bundle=loaded_bundle,
        incidents_dir=incidents_dir,
        overwrite=False,
    )

    assert report_path.exists()
    assert report_path.name.startswith("2026-02-10-")

    report_text = report_path.read_text(encoding="utf-8")
    assert "# WICAP Incident Report" in report_text
    assert "## Summary" in report_text
    assert "## Related Fix Sessions" in report_text
    assert "## Nearby Commits" in report_text
    assert "## Git Context" in report_text
    assert "most_common_commit_hash:" in report_text
    assert "## Harness References" in report_text
    assert "/home/steve/apps/wicap/stop_wicap.py" in report_text
    assert "session-1" in report_text

    index_path = incidents_dir / "INDEX.md"
    assert index_path.exists()
    index_text = index_path.read_text(encoding="utf-8")
    assert report_path.name in index_text
    assert "logs_soak_fake" in index_text

    conn.close()
