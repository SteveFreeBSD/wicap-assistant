from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.cli import main


def test_memory_maintenance_cli_writes_report_json(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "assistant.db"
    report_path = tmp_path / "reports" / "memory.json"
    rc = main(
        [
            "--db",
            str(db_path),
            "memory-maintenance",
            "--output",
            str(report_path),
            "--json",
        ]
    )
    assert rc == 0
    assert report_path.exists()
    payload = json.loads(capsys.readouterr().out.strip())
    assert "decision_rows_analyzed" in payload
    assert "stale_session_count" in payload


def test_rollout_gates_cli_json_output(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "assistant.db"
    history = tmp_path / "rollout_history.jsonl"
    rc = main(
        [
            "--db",
            str(db_path),
            "rollout-gates",
            "--history-file",
            str(history),
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert "overall_pass" in payload
    assert "gates" in payload
    assert "promotion" in payload
    assert history.exists()


def test_rollout_gates_cli_enforce_requires_promotion_readiness(tmp_path: Path) -> None:
    db_path = tmp_path / "assistant.db"
    history = tmp_path / "rollout_history.jsonl"
    rc = main(
        [
            "--db",
            str(db_path),
            "rollout-gates",
            "--history-file",
            str(history),
            "--required-consecutive-passes",
            "2",
            "--enforce",
            "--json",
        ]
    )
    assert rc == 2
