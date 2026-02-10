from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from wicap_assist.db import connect_db
from wicap_assist.guardian import (
    GuardianState,
    load_playbook_entries,
    scan_guardian_once,
)
from wicap_assist.playbooks import normalize_signature


def test_guardian_scans_only_new_lines_and_dedupes_alerts(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/home/steve/.codex/sessions/2026/02/10/rollout-test.jsonl", 1.0, 10),
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
            "session-guardian",
            "/home/steve/apps/wicap",
            "2026-02-10T11:00:00+00:00",
            "2026-02-10T11:05:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "deadbeef",
            1,
            "/home/steve/.codex/sessions/2026/02/10/rollout-test.jsonl",
        ),
    )
    session_pk = int(cur.lastrowid)
    cur.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'errors', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-10T11:02:00+00:00",
            "sig-1",
            "Error: pyodbc setinputsizes failed while writing profile",
        ),
    )
    conn.commit()

    line = "Error: pyodbc setinputsizes failed while writing profile"
    signature = normalize_signature(line)

    playbooks_dir = tmp_path / "docs" / "playbooks"
    playbooks_dir.mkdir(parents=True)
    (playbooks_dir / "error-pyodbc.md").write_text(
        "\n".join(
            [
                "# Playbook: Error - pyodbc",
                "",
                "## Trigger",
                "- Category: error",
                f"- Signature: {signature}",
                "",
                "## Fix steps",
                "1. Run `python scripts/check_wicap_status.py --sql-only`.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    playbooks = load_playbook_entries(playbooks_dir)

    log_path = tmp_path / "guardian.log"
    log_path.write_text(line + "\n", encoding="utf-8")

    state = GuardianState()
    base = datetime(2026, 2, 10, 12, 0, tzinfo=timezone.utc)

    first = scan_guardian_once(
        conn,
        state=state,
        path_specs=[str(log_path)],
        playbooks=playbooks,
        now=base,
        start_at_end_for_new=True,
    )
    assert first == []

    log_path.write_text(line + "\n" + line + "\n", encoding="utf-8")
    second = scan_guardian_once(
        conn,
        state=state,
        path_specs=[str(log_path)],
        playbooks=playbooks,
        now=base + timedelta(minutes=1),
        start_at_end_for_new=True,
    )
    assert len(second) == 1
    assert second[0].category == "error"
    assert second[0].signature == signature
    assert second[0].playbook == "error-pyodbc.md"
    assert second[0].recent_session_id == "session-guardian"

    third = scan_guardian_once(
        conn,
        state=state,
        path_specs=[str(log_path)],
        playbooks=playbooks,
        now=base + timedelta(minutes=2),
        start_at_end_for_new=True,
    )
    assert third == []

    log_path.write_text(line + "\n" + line + "\n" + line + "\n", encoding="utf-8")
    fourth = scan_guardian_once(
        conn,
        state=state,
        path_specs=[str(log_path)],
        playbooks=playbooks,
        now=base + timedelta(minutes=3),
        start_at_end_for_new=True,
    )
    assert fourth == []

    log_path.write_text(line + "\n" + line + "\n" + line + "\n" + line + "\n", encoding="utf-8")
    fifth = scan_guardian_once(
        conn,
        state=state,
        path_specs=[str(log_path)],
        playbooks=playbooks,
        now=base + timedelta(minutes=12),
        start_at_end_for_new=True,
    )
    assert len(fifth) == 1
    assert fifth[0].first_step == "Run `python scripts/check_wicap_status.py --sql-only`."

    conn.close()


def test_guardian_includes_verification_track_record(tmp_path: Path) -> None:
    """Guardian alerts should include verification outcomes and relapse warnings."""
    from wicap_assist.db import insert_verification_outcome
    from wicap_assist.guardian import format_guardian_alert_text

    conn = connect_db(tmp_path / "assistant.db")
    
    # Create a dummy playbook
    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()
    (playbooks_dir / "error-test.md").write_text(
        "- Category: error\n- Signature: error: test error signature\n## Fix steps\n1. Do something.",
        encoding="utf-8"
    )
    playbooks = load_playbook_entries(playbooks_dir)

    # Insert verification outcomes: 1 pass then 1 fail => Relapse
    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="test error signature",
        outcome="pass",
        evidence_snippet="works",
        ts="2026-02-10T10:00:00Z",
    )
    insert_verification_outcome(
        conn,
        conversation_pk=None,
        signature="test error signature",
        outcome="fail",
        evidence_snippet="broken again",
        ts="2026-02-10T12:00:00Z",
    )
    conn.commit()

    # Create log file with matching error
    log_path = tmp_path / "app.log"
    log_path.write_text("ERROR: test error signature\n", encoding="utf-8")

    state = GuardianState()
    alerts = scan_guardian_once(
        conn,
        state=state,
        path_specs=[str(log_path)],
        playbooks=playbooks,
        start_at_end_for_new=False,  # Read from beginning
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.signature == "error: test error signature"
    assert alert.past_fix_passes == 1
    assert alert.past_fix_fails == 1
    assert alert.relapse_risk is True

    text = format_guardian_alert_text(alert)
    assert "Past Fix Track Record: pass=1 fail=1 ⚠ RELAPSE RISK" in text

    conn.close()

