from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from wicap_assist.daily_report import format_daily_report_text, generate_daily_report
from wicap_assist.db import connect_db
from wicap_assist.playbooks import normalize_signature


def test_daily_report_detects_upward_trend_and_correlates_docs(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    cur = conn.cursor()

    log_path = tmp_path / "logs_soak_1" / "docker_fail_iter_1.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("sample\n", encoding="utf-8")

    now = datetime(2026, 2, 10, 12, 0, 0, tzinfo=timezone.utc)

    cur.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("soak_log", str(log_path), now.timestamp(), log_path.stat().st_size),
    )
    source_id = int(cur.lastrowid)

    base_snippets = [
        "Error: pyodbc setinputsizes failed for 00:0D:97:00:98:FA code 500",
        "Error: pyodbc setinputsizes failed for 00:0D:97:00:98:FB code 501",
    ]
    for idx, snippet in enumerate(base_snippets, start=1):
        ts = (now - timedelta(days=4) + timedelta(minutes=idx)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (source_id, ts, f"base-{idx}", snippet, str(log_path)),
        )

    for idx in range(7):
        ts = (now - timedelta(days=1) + timedelta(minutes=idx)).strftime("%Y-%m-%d %H:%M:%S")
        snippet = f"Error: pyodbc setinputsizes failed for 00:0D:97:00:98:{idx:02X} code {600 + idx}"
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'error', ?, ?, ?, '{}')
            """,
            (source_id, ts, f"recent-{idx}", snippet, str(log_path)),
        )

    for idx in range(4):
        ts = (now - timedelta(days=1) + timedelta(minutes=30 + idx)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            """
            INSERT INTO log_events(source_id, ts_text, category, fingerprint, snippet, file_path, extra_json)
            VALUES(?, ?, 'docker_fail', ?, ?, ?, '{}')
            """,
            (source_id, ts, f"other-{idx}", "docker fail once", str(log_path)),
        )

    conn.commit()

    signature = normalize_signature("Error: pyodbc setinputsizes failed for 00:0D:97:00:98:AA code 777")

    playbooks_dir = tmp_path / "docs" / "playbooks"
    playbooks_dir.mkdir(parents=True)
    playbook_path = playbooks_dir / "error-pyodbc-setinputsizes.md"
    playbook_path.write_text(
        "\n".join(
            [
                "# Playbook: Error - pyodbc setinputsizes",
                "",
                "## Trigger",
                "- Category: error",
                f"- Signature: {signature}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    incidents_dir = tmp_path / "docs" / "incidents"
    incidents_dir.mkdir(parents=True)
    (incidents_dir / "2026-02-01-old.md").write_text(
        "### error\nExample snippet: pyodbc setinputsizes failed",
        encoding="utf-8",
    )
    newest_incident = incidents_dir / "2026-02-09-new.md"
    newest_incident.write_text(
        "### error\nExample snippet: pyodbc setinputsizes failed again",
        encoding="utf-8",
    )

    report = generate_daily_report(
        conn,
        days=3,
        top=10,
        now=now,
        playbooks_dir=playbooks_dir,
        incidents_dir=incidents_dir,
    )

    assert report["items"]
    first = report["items"][0]
    assert first["category"] == "error"
    assert first["signature"] == signature
    assert first["recent_count"] == 7
    assert first["baseline_count"] == 2
    assert first["trend_score"] == 5
    assert first["playbook"] == playbook_path.name
    assert first["incident"] == newest_incident.name

    text = format_daily_report_text(report)
    assert "=== WICAP Daily Regression Report ===" in text
    assert "Suggested Playbook:" in text
    assert playbook_path.name in text

    conn.close()

