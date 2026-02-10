from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.db import connect_db
from wicap_assist.git_context import build_git_context
from wicap_assist.incident import write_incident_report
from wicap_assist.recommend import build_recommendation, recommendation_to_json


def _seed_git_context_data(conn, tmp_path: Path) -> None:
    cur = conn.cursor()

    source_path = tmp_path / "logs_soak_git_ctx" / "run.log"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(source_path), 1.0, 100),
    )
    soak_source_id = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, 'error', ?, ?, ?, '{}')
        """,
        (
            soak_source_id,
            "2026-02-10 10:00:00",
            "ctx-fp-1",
            "Error: pyodbc setinputsizes failed in persistence path",
            str(source_path),
        ),
    )

    for idx, commit_hash in enumerate(("abc123", "abc123", "def456"), start=1):
        cur.execute(
            "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
            (
                "session",
                f"/home/steve/.codex/sessions/2026/02/10/rollout-ctx-{idx}.jsonl",
                2.0 + idx,
                120,
            ),
        )
        source_id = int(cur.lastrowid)
        session_id = f"session-git-{idx}"
        cur.execute(
            """
            INSERT INTO sessions(
                source_id, session_id, cwd, ts_first, ts_last,
                repo_url, branch, commit_hash, is_wicap, raw_path
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                session_id,
                "/home/steve/apps/wicap",
                "2026-02-10T09:50:00+00:00",
                f"2026-02-10T10:0{idx}:00+00:00",
                "https://github.com/SteveFreeBSD/wicap.git",
                "main" if idx < 3 else "feature-x",
                commit_hash,
                1,
                f"/home/steve/.codex/sessions/2026/02/10/rollout-ctx-{idx}.jsonl",
            ),
        )
        session_pk = int(cur.lastrowid)

        cur.execute(
            """
            INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
            VALUES(?, ?, 'commands', ?, ?, '{}')
            """,
            (
                session_pk,
                f"2026-02-10T10:0{idx}:10+00:00",
                f"ctx-cmd-{idx}",
                "python scripts/check_wicap_status.py --sql-only",
            ),
        )
        cur.execute(
            """
            INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
            VALUES(?, ?, 'outcomes', ?, ?, '{}')
            """,
            (
                session_pk,
                f"2026-02-10T10:0{idx}:30+00:00",
                f"ctx-out-{idx}",
                "fixed pyodbc setinputsizes by updating persistence merge",
            ),
        )

    conn.commit()


def test_build_git_context_aggregation_rules() -> None:
    context = build_git_context(
        [
            {
                "source": "codex",
                "repo_url": "https://github.com/SteveFreeBSD/wicap.git",
                "branch": "main",
                "commit_hash": "abc123",
            },
            {
                "source": "codex",
                "repo_url": "https://github.com/SteveFreeBSD/wicap.git",
                "branch": "main",
                "commit_hash": "abc123",
            },
            {
                "source": "antigravity",
                "repo_url": "https://github.com/SteveFreeBSD/wicap.git",
                "branch": "feature-x",
                "commit_hash": "def456",
            },
        ]
    )

    assert context["repo_url"] == "https://github.com/SteveFreeBSD/wicap.git"
    assert context["most_common_commit_hash"] == "abc123"
    assert context["commit_spread"] == 2
    assert context["unique_commits"][0] == {"commit_hash": "abc123", "count": 2}
    assert context["unique_branches"][0] == {"branch": "main", "count": 2}
    assert context["evidence_sources"] == {
        "codex_sessions": 2,
        "antigravity_conversations": 1,
    }

    mismatch = build_git_context(
        [
            {"source": "codex", "repo_url": "https://github.com/SteveFreeBSD/wicap.git"},
            {"source": "codex", "repo_url": "https://example.com/other.git"},
        ]
    )
    assert mismatch["repo_url"] is None


def test_recommend_output_includes_git_context_with_stable_schema(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    _seed_git_context_data(conn, tmp_path)

    payload = build_recommendation(conn, "logs_soak_git_ctx")
    encoded = recommendation_to_json(payload)
    parsed = json.loads(encoded)

    assert "git_context" in parsed
    assert set(parsed["git_context"].keys()) == {
        "repo_url",
        "most_common_commit_hash",
        "unique_commits",
        "unique_branches",
        "commit_spread",
        "evidence_sources",
    }
    assert parsed["git_context"]["most_common_commit_hash"] == "abc123"

    conn.close()


def test_incident_output_contains_git_context_section(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    _seed_git_context_data(conn, tmp_path)

    source_path = str(tmp_path / "logs_soak_git_ctx" / "run.log")
    bundle = {
        "target": "logs_soak_git_ctx",
        "log_summary": {
            "error": [{"count": 1, "snippet": "Error: pyodbc setinputsizes failed in persistence path", "file": source_path}],
            "docker_fail": [],
            "pytest_fail": [],
        },
        "related_sessions": [
            {
                "session_id": "session-git-1",
                "ts_last": "2026-02-10T10:01:00+00:00",
                "cwd": "/home/steve/apps/wicap",
                "git": {
                    "repo_url": "https://github.com/SteveFreeBSD/wicap.git",
                    "branch": "main",
                    "commit_hash": "abc123",
                },
                "source": "/home/steve/.codex/sessions/2026/02/10/rollout-ctx-1.jsonl",
                "matches": {
                    "commands": [{"snippet": "python scripts/check_wicap_status.py --sql-only", "fingerprint": "f1"}],
                    "errors": [],
                    "file_paths": [],
                    "outcomes": [{"snippet": "fixed pyodbc setinputsizes by updating persistence merge", "fingerprint": "f2"}],
                },
            }
        ],
        "git_commits": [],
    }

    incidents_dir = tmp_path / "wicap" / "docs" / "incidents"
    path = write_incident_report(
        conn,
        target="logs_soak_git_ctx",
        bundle=bundle,
        incidents_dir=incidents_dir,
        overwrite=False,
    )
    text = path.read_text(encoding="utf-8")
    assert "## Git Context" in text
    assert "most_common_commit_hash: abc123" in text
    assert "repo_url: https://github.com/SteveFreeBSD/wicap.git" in text
    assert text.index("## Summary") < text.index("## Git Context") < text.index("## Failure Signatures")

    conn.close()


def test_recommend_logs_soak_target_uses_window_fallback_git_context(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_1769746905" / "docker_fail_iter_1.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), 1.0, 100),
    )
    soak_source_id = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, 'error', ?, ?, ?, '{}')
        """,
        (
            soak_source_id,
            "2026-01-30 10:00:00",
            "fallback-fp-1",
            "Error: wicap processor failed to flush",
            str(log_path),
        ),
    )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/01/31/rollout-fallback.jsonl", 2.0, 120),
    )
    source_id = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            "session-fallback",
            "/home/steve/apps/wicap",
            "2026-01-31T09:00:00+00:00",
            "2026-01-31T09:30:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "feedbead",
            1,
            "/home/steve/.codex/sessions/2026/01/31/rollout-fallback.jsonl",
        ),
    )
    conn.commit()

    payload = build_recommendation(conn, "logs_soak_1769746905")
    git_context = payload["git_context"]
    assert git_context["commit_spread"] >= 1
    assert git_context["most_common_commit_hash"] == "feedbead"
    assert git_context["evidence_sources"]["codex_sessions"] >= 1

    conn.close()
