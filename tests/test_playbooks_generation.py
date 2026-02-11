from __future__ import annotations

import json
from pathlib import Path
import re

from wicap_assist.db import connect_db
from wicap_assist.playbooks import generate_playbooks


def test_generate_playbooks_from_clustered_log_events(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_1" / "docker_fail_iter_1.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), log_path.stat().st_mtime, log_path.stat().st_size),
    )
    source_id = int(cur.lastrowid)

    events = [
        "Error: pyodbc setinputsizes failed for 00:0D:97:00:98:FA code 500",
        "Error: pyodbc setinputsizes failed for 00:0D:97:00:98:FB code 501",
        "Error: pyodbc setinputsizes failed for 00:0D:97:00:98:FC code 777",
    ]
    for idx, snippet in enumerate(events, start=1):
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (source_id, f"2026-02-10 10:00:0{idx}", f"fp-{idx}", snippet, str(log_path)),
        )

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-test.jsonl", 2.0, 200),
    )
    session_source_id = int(cur.lastrowid)

    cur.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_source_id,
            "session-playbook",
            "/home/steve/apps/wicap",
            "2026-02-10T10:00:00+00:00",
            "2026-02-10T10:05:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "deadbeef",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-test.jsonl",
        ),
    )
    session_pk = int(cur.lastrowid)

    command_snippets = [
        "python scripts/check_wicap_status.py --sql-only [c58565f698] [1709a0a81b]",
        "- docker logs wicap-ui --tail 200 [abcdef123456]",
        "docker ps [deadbeef]",
        "systemctl status wicap-ui.service [0123456789ab]",
        "python start_wicap.py [aabbccddeeff]",
        "journalctl -u wicap-ui -n 200 [ffeeddccbbaa]",
        "docker ps [deadbeef]",
        "ls -la [0123abcd]",
        "cd /home/steve/apps/wicap [1234abcd]",
        "python scripts/check_wicap_status.py --sql-only [c58565f698] [1709a0a81b]",
    ]
    for idx, snippet in enumerate(command_snippets, start=1):
        cur.execute(
            """
            INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
            VALUES(?, ?, 'commands', ?, ?, '{}')
            """,
            (session_pk, f"2026-02-10T10:00:{idx:02d}+00:00", f"cmd-{idx}", snippet),
        )
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (session_pk, "2026-02-10T10:01:00+00:00", "out-1", "fixed pyodbc setinputsizes retry in src/wicap/core/processing/persistence.py"),
    )
    cur.execute(
        """
        INSERT INTO harness_scripts(script_path, role, commands_json, tools_json, env_vars_json, last_modified)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            "/home/steve/apps/wicap/soak_runner_demo.py",
            "runner",
            json.dumps(["python scripts/check_wicap_status.py --sql-only"], sort_keys=True),
            json.dumps(["python", "docker"], sort_keys=True),
            json.dumps(["SOAK_INTERVAL"], sort_keys=True),
            "2026-02-10T10:00:00+00:00",
        ),
    )

    conn.commit()

    def fake_commits(repo_root, window_start, window_end, max_commits=30):  # type: ignore[no-untyped-def]
        return []

    playbooks_dir = tmp_path / "docs" / "playbooks"
    generated = generate_playbooks(
        conn,
        top_n=1,
        playbooks_dir=playbooks_dir,
        repo_root=tmp_path,
        load_commits_fn=fake_commits,
    )

    assert len(generated) == 1
    playbook_path = generated[0]
    assert playbook_path.exists()

    content = playbook_path.read_text(encoding="utf-8")
    assert "## Trigger" in content
    assert "## Fix steps" in content
    assert "python scripts/check_wicap_status.py --sql-only" in content
    assert re.search(r"\[[0-9a-f]{8,40}\]", content, re.IGNORECASE) is None
    assert "## Harness Integration" in content
    assert "/home/steve/apps/wicap/soak_runner_demo.py" in content

    quick_checks_block = content.split("## Quick checks", 1)[1].split("## Fix steps", 1)[0]
    quick_checks = [line for line in quick_checks_block.splitlines() if line.startswith("- `")]
    assert len(quick_checks) <= 5
    assert len(quick_checks) == len(set(quick_checks))

    fix_steps_block = content.split("## Fix steps", 1)[1].split("## Verify", 1)[0]
    fix_steps = [line for line in fix_steps_block.splitlines() if re.match(r"^\d+\.\s", line)]
    assert len(fix_steps) <= 8

    index_path = playbooks_dir / "INDEX.md"
    assert index_path.exists()
    index_content = index_path.read_text(encoding="utf-8")
    assert playbook_path.name in index_content

    conn.close()


def test_generate_playbook_for_network_anomaly_includes_route_ladder(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    log_path = tmp_path / "captures" / "wicap_anomaly_events.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("sample\n", encoding="utf-8")
    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("network_event_log", str(log_path), log_path.stat().st_mtime, log_path.stat().st_size),
    )
    source_id = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
        VALUES(?, ?, 'network_anomaly', ?, ?, ?, '{}')
        """,
        (
            source_id,
            "2026-02-11T16:00:00Z",
            "net-1",
            "deauth_spike|global|aa:bb:cc:dd:ee:ff",
            str(log_path),
        ),
    )
    conn.commit()

    playbooks_dir = tmp_path / "docs" / "playbooks"
    generated = generate_playbooks(
        conn,
        top_n=1,
        playbooks_dir=playbooks_dir,
        repo_root=tmp_path,
        load_commits_fn=lambda *args, **kwargs: [],
    )
    assert len(generated) == 1
    content = generated[0].read_text(encoding="utf-8")
    assert "docker compose restart wicap-scout" in content
    assert "python scripts/check_wicap_status.py --local-only" in content
    conn.close()
