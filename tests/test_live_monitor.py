from __future__ import annotations

import json
from pathlib import Path

from wicap_assist.cli import main
from wicap_assist.db import connect_db, insert_control_session
from wicap_assist.guardian import GuardianAlert
from wicap_assist.live import run_live_monitor
from wicap_assist.probes.docker_probe import probe_docker
from wicap_assist.util.evidence import normalize_signature
from wicap_assist.util.redact import to_snippet


class _DummyResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_docker_probe_parses_service_status_and_logs() -> None:
    def fake_runner(cmd, capture_output, text, check):  # type: ignore[no-untyped-def]
        if cmd[:3] == ["docker", "ps", "--format"]:
            return _DummyResult(
                0,
                stdout=(
                    "wicap-ui\tUp 2 minutes\tabc123\n"
                    "wicap-processor\tRestarting (1) 5 seconds ago\tdef456\n"
                ),
            )

        if cmd[:2] == ["docker", "logs"]:
            service = cmd[-1]
            if service == "wicap-ui":
                return _DummyResult(0, stdout="INFO ready\nError: connection refused\n")
            return _DummyResult(1, stderr=f"No such container: {service}\n")

        raise AssertionError(f"Unexpected command: {cmd}")

    payload = probe_docker(runner=fake_runner)

    services = payload["services"]
    assert services["wicap-ui"]["state"] == "up"
    assert services["wicap-processor"]["state"] == "restarting"
    assert services["wicap-scout"]["state"] == "down"
    assert any("Error: connection refused" in line for line in payload["logs"]["wicap-ui"])


def test_live_once_writes_db_row_and_extracts_signatures(tmp_path: Path, monkeypatch, capsys) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)

    error_line = "Error: failed to connect to SQL backend"
    expected_sig = normalize_signature(to_snippet(error_line, max_len=200))

    def fake_probe_docker():  # type: ignore[no-untyped-def]
        return {
            "docker_ps_ok": True,
            "services": {
                "wicap-ui": {"state": "up", "status": "Up 10 minutes", "container": "a"},
                "wicap-processor": {"state": "up", "status": "Up 10 minutes", "container": "b"},
                "wicap-scout": {"state": "up", "status": "Up 10 minutes", "container": "c"},
                "wicap-redis": {"state": "up", "status": "Up 10 minutes", "container": "d"},
            },
            "logs": {
                "wicap-ui": [error_line, error_line],
                "wicap-processor": ["INFO healthy"],
                "wicap-scout": [],
                "wicap-redis": [],
            },
        }

    def fake_probe_network():  # type: ignore[no-untyped-def]
        return {"ss_ok": True, "listening_ports": [8080], "expected_ports": {"8080": True, "6379": False}}

    def fake_probe_http_health():  # type: ignore[no-untyped-def]
        return {"url": "http://127.0.0.1:8080/health", "ok": True, "status_code": 200, "error": None}

    def fake_recommendation(_conn, target):  # type: ignore[no-untyped-def]
        return {
            "input": target,
            "recommended_action": "Apply previously successful fix",
            "confidence": 0.33,
            "based_on_sessions": [],
            "related_playbooks": [],
            "harness_tests": [],
            "git_context": {},
            "confidence_breakdown": {},
            "verification_priority": ["docker logs --tail 100 wicap-ui"],
            "verification_step_safety": [
                {"step": "docker logs --tail 100 wicap-ui", "safety": "safe"},
                {"step": "systemctl restart wicap", "safety": "caution"},
            ],
            "risk_notes": "",
            "verification_steps": ["docker logs --tail 100 wicap-ui"],
        }

    monkeypatch.setattr("wicap_assist.live.probe_docker", fake_probe_docker)
    monkeypatch.setattr("wicap_assist.live.probe_network", fake_probe_network)
    monkeypatch.setattr("wicap_assist.live.probe_http_health", fake_probe_http_health)
    monkeypatch.setattr("wicap_assist.live.build_recommendation", fake_recommendation)

    playbooks_dir = tmp_path / "docs" / "playbooks"
    playbooks_dir.mkdir(parents=True)
    (playbooks_dir / "error-sql.md").write_text(
        "\n".join(
            [
                "# Playbook: SQL error",
                "",
                "## Trigger",
                "- Category: error",
                f"- Signature: {expected_sig}",
                "",
                "## Fix steps",
                "1. Run `docker logs --tail 100 wicap-ui`.",
            ]
        ),
        encoding="utf-8",
    )

    rc = run_live_monitor(conn, interval=0.1, once=True, playbooks_dir=playbooks_dir)
    assert rc == 0
    output = capsys.readouterr().out
    assert "operator_guidance:" in output

    row = conn.execute("SELECT * FROM live_observations ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None

    top = json.loads(row["top_signatures_json"])
    assert top
    assert top[0]["signature"] == expected_sig
    assert int(top[0]["count"]) == 2
    assert top[0]["playbook"] == "error-sql.md"

    recommended = json.loads(row["recommended_json"])
    assert recommended
    assert recommended[0]["safe_verify_steps"] == ["docker logs --tail 100 wicap-ui"]

    conn.close()


def test_cli_live_once_exits_cleanly(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run_live_monitor(conn, **kwargs):  # type: ignore[no-untyped-def]
        interval = kwargs.get("interval")
        once = kwargs.get("once")
        captured["interval"] = interval
        captured["once"] = once
        captured["control_mode"] = kwargs.get("control_mode")
        return 0

    monkeypatch.setattr("wicap_assist.cli.run_live_monitor", fake_run_live_monitor)

    rc = main(["--db", str(tmp_path / "assistant.db"), "live", "--interval", "3", "--once"])
    assert rc == 0
    assert captured["once"] is True
    assert float(captured["interval"]) == 3.0
    assert captured["control_mode"] == "observe"


def test_cli_live_accepts_autonomous_mode(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run_live_monitor(conn, **kwargs):  # type: ignore[no-untyped-def]
        captured["control_mode"] = kwargs.get("control_mode")
        captured["control_check_threshold"] = kwargs.get("control_check_threshold")
        return 0

    monkeypatch.setattr("wicap_assist.cli.run_live_monitor", fake_run_live_monitor)

    rc = main(
        [
            "--db",
            str(tmp_path / "assistant.db"),
            "live",
            "--once",
            "--control-mode",
            "autonomous",
        ]
    )
    assert rc == 0
    assert captured["control_mode"] == "autonomous"
    assert captured["control_check_threshold"] is None


def test_live_once_includes_guardian_alerts_in_persisted_payload(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)

    def fake_probe_docker():  # type: ignore[no-untyped-def]
        return {
            "docker_ps_ok": True,
            "services": {
                "wicap-ui": {"state": "up", "status": "Up 10 minutes", "container": "a"},
            },
            "logs": {"wicap-ui": []},
        }

    def fake_probe_network():  # type: ignore[no-untyped-def]
        return {"ss_ok": True, "listening_ports": [8080], "expected_ports": {"8080": True}}

    def fake_probe_http_health():  # type: ignore[no-untyped-def]
        return {"url": "http://127.0.0.1:8080/health", "ok": True, "status_code": 200, "error": None}

    def fake_recommendation(_conn, target):  # type: ignore[no-untyped-def]
        return {
            "input": target,
            "recommended_action": "insufficient historical evidence",
            "confidence": 0.0,
            "based_on_sessions": [],
            "related_playbooks": [],
            "harness_tests": [],
            "git_context": {},
            "confidence_breakdown": {},
            "verification_priority": [],
            "verification_step_safety": [],
            "risk_notes": "",
            "verification_steps": [],
        }

    monkeypatch.setattr("wicap_assist.live.probe_docker", fake_probe_docker)
    monkeypatch.setattr("wicap_assist.live.probe_network", fake_probe_network)
    monkeypatch.setattr("wicap_assist.live.probe_http_health", fake_probe_http_health)
    monkeypatch.setattr("wicap_assist.live.build_recommendation", fake_recommendation)
    monkeypatch.setattr(
        "wicap_assist.live.scan_guardian_once",
        lambda *args, **kwargs: [
            GuardianAlert(
                signature="error: pyodbc timeout",
                category="error",
                playbook="error-pyodbc.md",
                recent_session_id="session-1",
                recent_session_ts="2026-02-11T00:00:00Z",
                first_step="python scripts/check_wicap_status.py --sql-only",
                harness_script=None,
                harness_role=None,
                file_path="/home/steve/apps/wicap/wicap.log",
                line="Error: timeout",
            )
        ],
    )

    rc = run_live_monitor(conn, interval=0.1, once=True)
    assert rc == 0

    row = conn.execute("SELECT recommended_json FROM live_observations ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None
    payload = json.loads(str(row["recommended_json"]))
    assert isinstance(payload, list)
    assert any(isinstance(item, dict) and "guardian_alerts" in item for item in payload)

    conn.close()


def test_live_assist_mode_records_control_events(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)

    repo_root = tmp_path / "wicap"
    status_script = repo_root / "check_wicap_status.py"
    status_script.parent.mkdir(parents=True)
    status_script.write_text("print('ok')\n", encoding="utf-8")

    def fake_probe_docker():  # type: ignore[no-untyped-def]
        return {
            "docker_ps_ok": True,
            "services": {
                "wicap-ui": {"state": "down", "status": "Exited (1)", "container": "a"},
                "wicap-processor": {"state": "down", "status": "Exited (1)", "container": "b"},
                "wicap-scout": {"state": "down", "status": "Exited (1)", "container": "c"},
                "wicap-redis": {"state": "down", "status": "Exited (1)", "container": "d"},
            },
            "logs": {"wicap-ui": ["Error: down"]},
        }

    def fake_probe_network():  # type: ignore[no-untyped-def]
        return {"ss_ok": True, "listening_ports": [6379], "expected_ports": {"8080": False, "6379": True}}

    def fake_probe_http_health():  # type: ignore[no-untyped-def]
        return {"url": "http://127.0.0.1:8080/health", "ok": False, "status_code": None, "error": "down"}

    def fake_recommendation(_conn, target):  # type: ignore[no-untyped-def]
        return {
            "input": target,
            "recommended_action": "insufficient historical evidence",
            "confidence": 0.0,
            "based_on_sessions": [],
            "related_playbooks": [],
            "harness_tests": [],
            "git_context": {},
            "confidence_breakdown": {},
            "verification_priority": [],
            "verification_step_safety": [],
            "risk_notes": "",
            "verification_steps": [],
        }

    class _DummyResult:
        def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok")

    monkeypatch.setattr("wicap_assist.live.probe_docker", fake_probe_docker)
    monkeypatch.setattr("wicap_assist.live.probe_network", fake_probe_network)
    monkeypatch.setattr("wicap_assist.live.probe_http_health", fake_probe_http_health)
    monkeypatch.setattr("wicap_assist.live.build_recommendation", fake_recommendation)

    rc = run_live_monitor(
        conn,
        interval=0.1,
        once=True,
        control_mode="assist",
        control_check_threshold=1,
        control_recover_threshold=2,
        control_action_cooldown_cycles=0,
        repo_root=repo_root,
        control_runner=fake_runner,
    )
    assert rc == 0
    assert calls

    event_count = conn.execute("SELECT count(*) FROM control_events").fetchone()[0]
    episode_count = conn.execute("SELECT count(*) FROM episodes").fetchone()[0]
    outcome_count = conn.execute("SELECT count(*) FROM episode_outcomes").fetchone()[0]
    feature_count = conn.execute("SELECT count(*) FROM decision_features").fetchone()[0]
    session_count = conn.execute("SELECT count(*) FROM control_sessions").fetchone()[0]
    session_status = conn.execute(
        "SELECT status FROM control_sessions ORDER BY id DESC LIMIT 1"
    ).fetchone()["status"]
    detail_row = conn.execute("SELECT detail_json FROM control_events ORDER BY id DESC LIMIT 1").fetchone()
    assert int(event_count) >= 1
    assert int(episode_count) >= int(event_count)
    assert int(outcome_count) >= int(event_count)
    assert int(feature_count) >= int(event_count)
    assert int(session_count) == 1
    assert str(session_status) == "completed"
    assert detail_row is not None
    detail_payload = json.loads(str(detail_row["detail_json"]))
    assert "episode_id" in detail_payload

    conn.close()


def test_live_monitor_resumes_recent_running_session(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True)

    session_id = insert_control_session(
        conn,
        soak_run_id=None,
        started_ts="2026-02-11T00:00:00+00:00",
        last_heartbeat_ts="2026-02-11T00:00:30+00:00",
        mode="observe",
        status="running",
        current_phase="live_cycle",
        handoff_state="active",
        metadata_json={"repo_root": str(repo_root)},
    )
    conn.commit()

    def fake_probe_docker():  # type: ignore[no-untyped-def]
        return {
            "docker_ps_ok": True,
            "services": {
                "wicap-ui": {"state": "up", "status": "Up 10 minutes", "container": "a"},
            },
            "logs": {"wicap-ui": []},
        }

    def fake_probe_network():  # type: ignore[no-untyped-def]
        return {"ss_ok": True, "listening_ports": [8080], "expected_ports": {"8080": True}}

    def fake_probe_http_health():  # type: ignore[no-untyped-def]
        return {"url": "http://127.0.0.1:8080/health", "ok": True, "status_code": 200, "error": None}

    def fake_recommendation(_conn, target):  # type: ignore[no-untyped-def]
        return {
            "input": target,
            "recommended_action": "insufficient historical evidence",
            "confidence": 0.0,
            "based_on_sessions": [],
            "related_playbooks": [],
            "harness_tests": [],
            "git_context": {},
            "confidence_breakdown": {},
            "verification_priority": [],
            "verification_step_safety": [],
            "risk_notes": "",
            "verification_steps": [],
        }

    monkeypatch.setattr("wicap_assist.live.probe_docker", fake_probe_docker)
    monkeypatch.setattr("wicap_assist.live.probe_network", fake_probe_network)
    monkeypatch.setattr("wicap_assist.live.probe_http_health", fake_probe_http_health)
    monkeypatch.setattr("wicap_assist.live.build_recommendation", fake_recommendation)

    rc = run_live_monitor(
        conn,
        interval=0.1,
        once=True,
        control_mode="observe",
        repo_root=repo_root,
        resume_window_seconds=10_000_000,
    )
    assert rc == 0

    count = conn.execute("SELECT count(*) FROM control_sessions").fetchone()[0]
    assert int(count) == 1
    row = conn.execute(
        "SELECT status, handoff_state, ended_ts FROM control_sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    assert row is not None
    assert str(row["status"]) == "completed"
    assert str(row["handoff_state"]) == "completed"
    assert row["ended_ts"] is not None

    resumed = conn.execute(
        "SELECT count(*) FROM control_session_events WHERE control_session_id = ? AND status = 'resumed'",
        (session_id,),
    ).fetchone()[0]
    assert int(resumed) >= 1

    conn.close()


def test_live_monitor_closes_stale_session_then_starts_new(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "assistant.db"
    conn = connect_db(db_path)
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True)

    stale_id = insert_control_session(
        conn,
        soak_run_id=None,
        started_ts="2000-01-01T00:00:00+00:00",
        last_heartbeat_ts="2000-01-01T00:00:00+00:00",
        mode="observe",
        status="running",
        current_phase="live_cycle",
        handoff_state="active",
        metadata_json={"repo_root": str(repo_root)},
    )
    conn.commit()

    def fake_probe_docker():  # type: ignore[no-untyped-def]
        return {
            "docker_ps_ok": True,
            "services": {
                "wicap-ui": {"state": "up", "status": "Up 10 minutes", "container": "a"},
            },
            "logs": {"wicap-ui": []},
        }

    def fake_probe_network():  # type: ignore[no-untyped-def]
        return {"ss_ok": True, "listening_ports": [8080], "expected_ports": {"8080": True}}

    def fake_probe_http_health():  # type: ignore[no-untyped-def]
        return {"url": "http://127.0.0.1:8080/health", "ok": True, "status_code": 200, "error": None}

    def fake_recommendation(_conn, target):  # type: ignore[no-untyped-def]
        return {
            "input": target,
            "recommended_action": "insufficient historical evidence",
            "confidence": 0.0,
            "based_on_sessions": [],
            "related_playbooks": [],
            "harness_tests": [],
            "git_context": {},
            "confidence_breakdown": {},
            "verification_priority": [],
            "verification_step_safety": [],
            "risk_notes": "",
            "verification_steps": [],
        }

    monkeypatch.setattr("wicap_assist.live.probe_docker", fake_probe_docker)
    monkeypatch.setattr("wicap_assist.live.probe_network", fake_probe_network)
    monkeypatch.setattr("wicap_assist.live.probe_http_health", fake_probe_http_health)
    monkeypatch.setattr("wicap_assist.live.build_recommendation", fake_recommendation)

    rc = run_live_monitor(
        conn,
        interval=0.1,
        once=True,
        control_mode="observe",
        repo_root=repo_root,
        resume_window_seconds=30,
    )
    assert rc == 0

    stale = conn.execute(
        "SELECT status, handoff_state, ended_ts FROM control_sessions WHERE id = ?",
        (stale_id,),
    ).fetchone()
    assert stale is not None
    assert str(stale["status"]) == "interrupted"
    assert str(stale["handoff_state"]) in {"stale_closed", "interrupted"}
    assert stale["ended_ts"] is not None

    count = conn.execute("SELECT count(*) FROM control_sessions").fetchone()[0]
    assert int(count) == 2
    newest = conn.execute(
        "SELECT id, status FROM control_sessions ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert newest is not None
    assert int(newest["id"]) != int(stale_id)
    assert str(newest["status"]) == "completed"

    conn.close()
