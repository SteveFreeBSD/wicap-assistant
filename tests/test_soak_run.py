from __future__ import annotations

from pathlib import Path

from wicap_assist.db import connect_db, insert_control_session
from wicap_assist.soak_run import run_supervised_soak


class _DummyResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_soak_run_success_writes_log_records_row_and_calls_hooks(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    status_script = repo_root / "check_wicap_status.py"
    status_script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    (repo_root / "logs_soak_1700000000").mkdir(parents=True)

    conn = connect_db(tmp_path / "assistant.db")

    ingest_calls: list[Path] = []
    incident_calls: list[str] = []

    def fake_runner(cmd, cwd, stdout, stderr, text, check, timeout):  # type: ignore[no-untyped-def]
        assert str(preferred_runner) in cmd
        assert cwd == str(repo_root)
        assert timeout == (10 + 5) * 60
        (repo_root / "logs_soak_1700000010").mkdir(parents=True)
        stdout.write("runner ok\n")
        stdout.flush()
        return _DummyResult(0)

    def fake_ingest(conn_arg, root_arg):  # type: ignore[no-untyped-def]
        assert conn_arg is conn
        assert root_arg == repo_root
        ingest_calls.append(root_arg)
        return 1, 3

    def fake_incident(conn_arg, target):  # type: ignore[no-untyped-def]
        assert conn_arg is conn
        incident_calls.append(target)
        path = tmp_path / "incident.md"
        path.write_text("# incident\n", encoding="utf-8")
        return path

    summary = run_supervised_soak(
        conn,
        duration_minutes=10,
        playwright_interval_minutes=2,
        baseline_path=tmp_path / "baseline.json",
        baseline_update=True,
        dry_run=False,
        managed_observe=False,
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        runner=fake_runner,
        ingest_hook=fake_ingest,
        incident_hook=fake_incident,
    )

    assert summary["exit_code"] == 0
    assert summary["run_id"] is not None
    assert summary["control_session_id"] is not None
    assert summary["incident_path"] == str(tmp_path / "incident.md")
    assert summary["newest_soak_dir"] is not None
    assert "logs_soak_1700000010" in str(summary["newest_soak_dir"])
    assert ingest_calls == [repo_root]
    assert incident_calls == ["logs_soak_1700000010"]
    assert "learned_runbook" in summary
    assert "learning_readiness" in summary
    assert "manager_actions" in summary
    assert summary["manager_actions"]
    assert "operator_guidance" in summary
    assert summary["operator_guidance"]
    assert summary["cleanup_status"] in {"skipped_observe_mode", "executed_ok", "executed_fail"}
    assert int(summary["snapshot_count"]) == 0
    assert summary["snapshot_dir"] is None
    assert "phase_plan" in summary
    assert "phase_trace" in summary
    assert any(item["phase"] == "ingest_soaks" for item in summary["phase_trace"])
    assert any(item["phase"] == "preflight_init" for item in summary["phase_trace"])

    log_path = Path(summary["runner_log"])
    assert log_path.exists()
    text = log_path.read_text(encoding="utf-8")
    assert "[soak-run] started_ts=" in text
    assert "runner ok" in text

    row = conn.execute(
        "SELECT * FROM soak_runs WHERE id = ?",
        (summary["run_id"],),
    ).fetchone()
    assert row is not None
    assert int(row["exit_code"]) == 0
    assert str(row["runner_path"]) == str(preferred_runner)
    assert "logs_soak_1700000010" in str(row["newest_soak_dir"])
    assert str(row["incident_path"]) == str(tmp_path / "incident.md")
    cs = conn.execute(
        "SELECT * FROM control_sessions WHERE id = ?",
        (summary["control_session_id"],),
    ).fetchone()
    assert cs is not None
    assert int(cs["soak_run_id"]) == int(summary["run_id"])
    assert str(cs["status"]) == "completed"
    assert str(cs["current_phase"]) == "finalize"
    cse = conn.execute(
        "SELECT count(*) FROM control_session_events WHERE control_session_id = ?",
        (summary["control_session_id"],),
    ).fetchone()
    assert cse is not None
    assert int(cse[0]) >= 2

    conn.close()


def test_soak_run_failure_uses_fallback_runner_and_still_records_row(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    fallback_runner = repo_root / "scripts" / "run_live_soak.py"
    fallback_runner.parent.mkdir(parents=True)
    fallback_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    conn = connect_db(tmp_path / "assistant.db")

    ingest_calls: list[Path] = []
    incident_calls: list[str] = []

    def fake_runner(cmd, cwd, stdout, stderr, text, check, timeout):  # type: ignore[no-untyped-def]
        assert str(fallback_runner) in cmd
        assert cwd == str(repo_root)
        (repo_root / "logs_soak_1700000020").mkdir(parents=True)
        stdout.write("runner failed\n")
        stdout.flush()
        return _DummyResult(3)

    def fake_ingest(conn_arg, root_arg):  # type: ignore[no-untyped-def]
        ingest_calls.append(root_arg)
        return 1, 2

    def fake_incident(conn_arg, target):  # type: ignore[no-untyped-def]
        incident_calls.append(target)
        path = tmp_path / "incident-failed.md"
        path.write_text("# incident\n", encoding="utf-8")
        return path

    summary = run_supervised_soak(
        conn,
        duration_minutes=12,
        playwright_interval_minutes=3,
        baseline_path=None,
        baseline_update=False,
        dry_run=False,
        managed_observe=False,
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        runner=fake_runner,
        ingest_hook=fake_ingest,
        incident_hook=fake_incident,
    )

    assert summary["exit_code"] == 3
    assert summary["control_session_id"] is not None
    assert summary["cleanup_status"] in {"skipped_observe_mode", "executed_ok", "executed_fail"}
    assert ingest_calls == [repo_root]
    assert incident_calls == ["logs_soak_1700000020"]
    assert "learned_runbook" in summary
    assert "learning_readiness" in summary
    assert "manager_actions" in summary
    assert "operator_guidance" in summary
    assert int(summary["snapshot_count"]) == 0
    assert summary["snapshot_dir"] is None
    assert any(item["phase"] == "soak_execute" and item["status"] == "failed" for item in summary["phase_trace"])

    row = conn.execute(
        "SELECT * FROM soak_runs WHERE id = ?",
        (summary["run_id"],),
    ).fetchone()
    assert row is not None
    assert int(row["exit_code"]) == 3
    cs = conn.execute(
        "SELECT status FROM control_sessions WHERE id = ?",
        (summary["control_session_id"],),
    ).fetchone()
    assert cs is not None
    assert str(cs["status"]) == "failed"

    conn.close()


def test_soak_run_dry_run_does_not_execute_or_insert_rows(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    conn = connect_db(tmp_path / "assistant.db")

    called = {"runner": False}

    def fake_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        called["runner"] = True
        return _DummyResult(0)

    summary = run_supervised_soak(
        conn,
        duration_minutes=10,
        playwright_interval_minutes=2,
        baseline_path=None,
        baseline_update=False,
        dry_run=True,
        managed_observe=True,
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        runner=fake_runner,
    )

    assert summary["dry_run"] is True
    assert summary["run_id"] is None
    assert summary["control_session_id"] is None
    assert summary["cleanup_status"] is None
    assert summary["exit_code"] is None
    assert called["runner"] is False
    assert not Path(summary["runner_log"]).exists()
    assert "learned_runbook" in summary
    assert "learning_readiness" in summary
    assert "manager_actions" in summary
    assert any("Dry-run only" in item for item in summary["manager_actions"])
    assert "operator_guidance" in summary
    assert summary["operator_guidance"]
    assert int(summary["snapshot_count"]) == 0
    assert summary["snapshot_paths"] == []
    assert summary["phase_plan"] == [
        "preflight_init",
        "soak_execute",
        "observe",
        "ingest_soaks",
        "incident_report",
        "finalize",
    ]

    count = int(conn.execute("SELECT count(*) FROM soak_runs").fetchone()[0])
    assert count == 0

    conn.close()


def test_soak_run_dry_run_autonomous_uses_policy_profile_defaults(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    conn = connect_db(tmp_path / "assistant.db")

    summary = run_supervised_soak(
        conn,
        duration_minutes=10,
        playwright_interval_minutes=2,
        baseline_path=None,
        baseline_update=False,
        dry_run=True,
        managed_observe=True,
        control_mode="autonomous",
        repo_root=repo_root,
        run_root=tmp_path / "runs",
    )

    assert summary["dry_run"] is True
    assert summary["control_mode"] == "autonomous"
    assert summary["control_policy_profile"] == "autonomous-v1"
    assert int(summary["control_check_threshold"]) == 2
    assert int(summary["control_recover_threshold"]) == 3
    assert int(summary["control_max_recover_attempts"]) == 3
    assert bool(summary["control_rollback_enabled"]) is True
    assert summary["control_kill_switch_env_var"] == "WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH"
    assert summary["control_kill_switch_file"]

    conn.close()


def test_soak_run_uses_learned_profile_when_args_omitted(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    conn = connect_db(tmp_path / "assistant.db")

    src = conn.execute(
        "INSERT INTO sources(kind, path, mtime, size) VALUES(?, ?, ?, ?)",
        ("session", "/tmp/history.jsonl", 1.0, 100),
    )
    source_id = int(src.lastrowid)
    sess = conn.execute(
        """
        INSERT INTO sessions(
            source_id, session_id, cwd, ts_first, ts_last,
            repo_url, branch, commit_hash, is_wicap, raw_path
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            "session-learned",
            "/home/steve/apps/wicap",
            "2026-02-11T00:00:00+00:00",
            "2026-02-11T00:00:00+00:00",
            "https://github.com/SteveFreeBSD/wicap.git",
            "main",
            "abc123",
            1,
            "/tmp/history.jsonl",
        ),
    )
    session_pk = int(sess.lastrowid)
    conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'commands', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-11T00:00:00+00:00",
            "fp-cmd",
            "python /home/steve/apps/wicap/tests/soak_test.py --duration-minutes 17 --playwright-interval-minutes 4",
        ),
    )
    conn.execute(
        """
        INSERT INTO signals(session_pk, ts, category, fingerprint, snippet, extra_json)
        VALUES(?, ?, 'outcomes', ?, ?, '{}')
        """,
        (
            session_pk,
            "2026-02-11T00:00:05+00:00",
            "fp-out",
            "fixed soak startup and verified output",
        ),
    )
    conn.commit()

    called = {"runner": False}

    def fake_runner(cmd, cwd, stdout, stderr, text, check, timeout):  # type: ignore[no-untyped-def]
        called["runner"] = True
        assert "--duration-minutes" in cmd
        idx = cmd.index("--duration-minutes")
        assert cmd[idx + 1] == "17"
        idx2 = cmd.index("--playwright-interval-minutes")
        assert cmd[idx2 + 1] == "4"
        (repo_root / "logs_soak_1700000030").mkdir(parents=True)
        return _DummyResult(0)

    def fake_ingest(_conn_arg, _root_arg):  # type: ignore[no-untyped-def]
        return 1, 1

    def fake_incident(_conn_arg, _target):  # type: ignore[no-untyped-def]
        return tmp_path / "incident-learned.md"

    summary = run_supervised_soak(
        conn,
        duration_minutes=None,
        playwright_interval_minutes=None,
        baseline_path=None,
        baseline_update=None,
        dry_run=False,
        managed_observe=False,
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        runner=fake_runner,
        ingest_hook=fake_ingest,
        incident_hook=fake_incident,
    )

    assert called["runner"] is True
    assert summary["control_session_id"] is not None
    assert int(summary["effective_duration_minutes"]) == 17
    assert int(summary["effective_playwright_interval_minutes"]) == 4
    assert summary["learned_profile"] is not None
    assert int(summary["learned_profile"]["duration_minutes"]) == 17
    assert int(summary["learned_profile"]["playwright_interval_minutes"]) == 4
    assert "learned_runbook" in summary
    assert summary["learning_readiness"]["status"] in {"ready", "partial"}
    assert "manager_actions" in summary
    assert "operator_guidance" in summary
    assert int(summary["snapshot_count"]) == 0
    assert summary["snapshot_dir"] is None
    assert any(item["phase"] == "finalize" for item in summary["phase_trace"])
    cs = conn.execute(
        "SELECT status FROM control_sessions WHERE id = ?",
        (summary["control_session_id"],),
    ).fetchone()
    assert cs is not None
    assert str(cs["status"]) == "completed"

    conn.close()


def test_soak_run_managed_observe_collects_live_metrics(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    (repo_root / "logs_soak_1700000000").mkdir(parents=True)
    conn = connect_db(tmp_path / "assistant.db")

    class _DummyProc:
        def __init__(self) -> None:
            self._poll_count = 0
            self.returncode = None

        def poll(self):  # type: ignore[no-untyped-def]
            self._poll_count += 1
            if self._poll_count >= 3:
                self.returncode = 0
                return 0
            return None

        def wait(self, timeout=None):  # type: ignore[no-untyped-def]
            self.returncode = 0
            return 0

        def terminate(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

        def kill(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

    observe_calls = {"count": 0}
    control_calls: list[list[str]] = []
    progress_events: list[dict[str, object]] = []

    def fake_process_factory(command, *, repo_root, handle):  # type: ignore[no-untyped-def]
        assert "--duration-minutes" in command
        (repo_root / "logs_soak_1700000090").mkdir(parents=True)
        handle.write("managed run\n")
        handle.flush()
        return _DummyProc()

    def fake_observe(_conn_arg):  # type: ignore[no-untyped-def]
        observe_calls["count"] += 1
        return {
            "ts": "2026-02-11T01:20:00+00:00",
            "service_status": {
                "docker": {
                    "services": {
                        "wicap-ui": {"state": "up", "status": "Up 2m"},
                        "wicap-processor": {"state": "up", "status": "Up 2m"},
                        "wicap-scout": {"state": "down", "status": "not running"},
                        "wicap-redis": {"state": "up", "status": "Up 2m"},
                    }
                }
            },
            "top_signatures": [
                {"signature": "error: sql timeout", "count": 2},
                {"signature": "error: redis refused", "count": 1},
            ],
            "alert": "services_down=wicap-scout",
        }

    def fake_ingest(_conn_arg, _root_arg):  # type: ignore[no-untyped-def]
        return 1, 2

    def fake_incident(_conn_arg, _target):  # type: ignore[no-untyped-def]
        path = tmp_path / "incident-managed.md"
        path.write_text("# incident\n", encoding="utf-8")
        return path

    def fake_control_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        control_calls.append(list(cmd))
        return _DummyResult(0)

    summary = run_supervised_soak(
        conn,
        duration_minutes=5,
        playwright_interval_minutes=1,
        baseline_path=None,
        baseline_update=False,
        dry_run=False,
        managed_observe=True,
        observe_interval_seconds=0.1,
        control_mode="assist",
        control_check_threshold=1,
        control_recover_threshold=2,
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        process_factory=fake_process_factory,
        control_runner=fake_control_runner,
        ingest_hook=fake_ingest,
        incident_hook=fake_incident,
        observe_hook=fake_observe,
        progress_hook=lambda event: progress_events.append(event),
    )

    assert summary["exit_code"] == 0
    assert summary["control_session_id"] is not None
    assert int(summary["observation_cycles"]) >= 2
    assert int(summary["alert_cycles"]) >= 1
    assert int(summary["down_service_cycles"]) >= 1
    assert summary["top_signatures"]
    assert summary["cleanup_status"] == "executed_ok"
    assert summary["cleanup_commands"]
    assert summary["preflight_actions"]
    assert any(item.get("action") == "compose_up" for item in summary["preflight_actions"])
    assert any(item.get("action") == "status_check" for item in summary["preflight_actions"])
    assert observe_calls["count"] >= 2
    assert int(summary["control_actions_executed"]) >= 1
    assert "control_escalations" in summary
    assert int(summary["snapshot_count"]) >= 1
    snapshot_dir = summary.get("snapshot_dir")
    assert snapshot_dir is not None
    assert Path(snapshot_dir).exists()
    assert summary.get("snapshot_paths")
    assert control_calls
    assert any(cmd[:4] == ["docker", "compose", "up", "-d"] for cmd in control_calls)
    assert "learning_readiness" in summary
    assert "manager_actions" in summary
    assert "operator_guidance" in summary
    assert any(item["phase"] == "observe" and item["status"] == "completed" for item in summary["phase_trace"])
    assert any(str(event.get("event")) == "runner_start" for event in progress_events)
    assert any(str(event.get("event")) == "observe_cycle" for event in progress_events)
    assert any(str(event.get("event")) == "control_event" for event in progress_events)
    assert any(str(event.get("event")) == "run_complete" for event in progress_events)
    control_rows = conn.execute("SELECT count(*) FROM control_events WHERE soak_run_id = ?", (summary["run_id"],)).fetchone()
    assert control_rows is not None
    assert int(control_rows[0]) >= 1
    preflight_rows = conn.execute(
        "SELECT count(*) FROM control_events WHERE soak_run_id = ? AND decision = 'preflight_startup'",
        (summary["run_id"],),
    ).fetchone()
    assert preflight_rows is not None
    assert int(preflight_rows[0]) >= 2
    session_status = conn.execute(
        "SELECT status FROM control_sessions WHERE id = ?",
        (summary["control_session_id"],),
    ).fetchone()
    assert session_status is not None
    assert str(session_status["status"]) == "completed"

    conn.close()


def test_soak_run_assist_prefers_live_runner_when_available(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    fallback_runner = repo_root / "scripts" / "run_live_soak.py"
    preferred_runner.parent.mkdir(parents=True)
    fallback_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    fallback_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (repo_root / "scripts" / "check_wicap_status.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (repo_root / "logs_soak_1700000000").mkdir(parents=True)

    conn = connect_db(tmp_path / "assistant.db")

    class _DummyProc:
        def __init__(self) -> None:
            self._poll_count = 0
            self.returncode = None

        def poll(self):  # type: ignore[no-untyped-def]
            self._poll_count += 1
            if self._poll_count >= 2:
                self.returncode = 0
                return 0
            return None

        def wait(self, timeout=None):  # type: ignore[no-untyped-def]
            self.returncode = 0
            return 0

        def terminate(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

        def kill(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

    commands_seen: list[list[str]] = []

    def fake_process_factory(command, *, repo_root, handle):  # type: ignore[no-untyped-def]
        commands_seen.append(list(command))
        (repo_root / "logs_soak_1700000300").mkdir(parents=True)
        handle.write("managed run prefer live\n")
        handle.flush()
        return _DummyProc()

    def fake_observe(_conn_arg):  # type: ignore[no-untyped-def]
        return {
            "ts": "2026-02-11T01:20:00+00:00",
            "service_status": {
                "docker": {
                    "services": {
                        "wicap-ui": {"state": "up", "status": "Up 2m"},
                        "wicap-processor": {"state": "up", "status": "Up 2m"},
                        "wicap-scout": {"state": "up", "status": "Up 2m"},
                        "wicap-redis": {"state": "up", "status": "Up 2m"},
                    }
                }
            },
            "top_signatures": [],
            "alert": "",
        }

    def fake_control_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        commands_seen.append(list(cmd))
        return _DummyResult(0, stdout="ok")

    summary = run_supervised_soak(
        conn,
        duration_minutes=1,
        playwright_interval_minutes=1,
        baseline_path=None,
        baseline_update=False,
        dry_run=False,
        managed_observe=True,
        observe_interval_seconds=0.1,
        control_mode="assist",
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        process_factory=fake_process_factory,
        control_runner=fake_control_runner,
        observe_hook=fake_observe,
        ingest_hook=lambda *_args, **_kwargs: (0, 0),  # type: ignore[no-untyped-def]
        incident_hook=lambda *_args, **_kwargs: tmp_path / "incident.md",  # type: ignore[no-untyped-def]
    )

    assert summary["runner_path"] == str(fallback_runner)
    assert commands_seen
    assert any(len(cmd) > 1 and cmd[1] == str(fallback_runner) for cmd in commands_seen)
    assert summary["preflight_actions"]
    assert any(item.get("action") == "compose_up" for item in summary["preflight_actions"])

    conn.close()


def test_soak_run_managed_observe_escalation_hard_stop(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    (repo_root / "logs_soak_1700000000").mkdir(parents=True)
    conn = connect_db(tmp_path / "assistant.db")

    class _LongProc:
        def __init__(self) -> None:
            self.returncode = None

        def poll(self):  # type: ignore[no-untyped-def]
            return self.returncode

        def wait(self, timeout=None):  # type: ignore[no-untyped-def]
            self.returncode = 0
            return 0

        def terminate(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

        def kill(self):  # type: ignore[no-untyped-def]
            self.returncode = 1

    progress_events: list[dict[str, object]] = []
    control_calls: list[list[str]] = []

    def fake_process_factory(command, *, repo_root, handle):  # type: ignore[no-untyped-def]
        assert "--duration-minutes" in command
        (repo_root / "logs_soak_1700000100").mkdir(parents=True)
        handle.write("managed run for escalation\n")
        handle.flush()
        return _LongProc()

    def fake_observe(_conn_arg):  # type: ignore[no-untyped-def]
        return {
            "ts": "2026-02-11T01:20:00+00:00",
            "service_status": {
                "docker": {
                    "services": {
                        "wicap-redis": {"state": "down", "status": "Exited (1)"},
                    }
                }
            },
            "top_signatures": [
                {"signature": "error: redis refused", "count": 2},
            ],
            "alert": "services_down=wicap-redis",
        }

    def fake_ingest(_conn_arg, _root_arg):  # type: ignore[no-untyped-def]
        return 1, 2

    def fake_incident(_conn_arg, _target):  # type: ignore[no-untyped-def]
        path = tmp_path / "incident-managed-escalated.md"
        path.write_text("# incident\n", encoding="utf-8")
        return path

    def fail_control_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        control_calls.append(list(cmd))
        if cmd[:4] == ["docker", "compose", "up", "-d"]:
            return _DummyResult(1, stderr="compose failed")
        return _DummyResult(0, stdout="status ok")

    summary = run_supervised_soak(
        conn,
        duration_minutes=5,
        playwright_interval_minutes=1,
        baseline_path=None,
        baseline_update=False,
        dry_run=False,
        managed_observe=True,
        observe_interval_seconds=0.1,
        control_mode="assist",
        control_check_threshold=1,
        control_recover_threshold=1,
        control_max_recover_attempts=1,
        control_action_cooldown_cycles=0,
        stop_on_escalation=True,
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        process_factory=fake_process_factory,
        control_runner=fail_control_runner,
        ingest_hook=fake_ingest,
        incident_hook=fake_incident,
        observe_hook=fake_observe,
        progress_hook=lambda event: progress_events.append(event),
    )

    assert int(summary["exit_code"]) == 86
    assert summary["control_session_id"] is not None
    assert bool(summary["escalation_hard_stop"]) is True
    assert summary.get("escalation_reason")
    assert int(summary["control_escalations"]) >= 1
    assert summary["cleanup_status"] in {"executed_fail", "executed_ok"}
    assert int(summary["snapshot_count"]) >= 1
    assert summary.get("snapshot_paths")
    assert any(str(event.get("event")) == "escalation_stop" for event in progress_events)
    assert any(cmd[:4] == ["docker", "compose", "up", "-d"] for cmd in control_calls)

    row = conn.execute(
        "SELECT args_json FROM soak_runs WHERE id = ?",
        (summary["run_id"],),
    ).fetchone()
    assert row is not None
    assert '"escalation_hard_stop": true' in str(row["args_json"]).lower()
    cs = conn.execute(
        "SELECT status FROM control_sessions WHERE id = ?",
        (summary["control_session_id"],),
    ).fetchone()
    assert cs is not None
    assert str(cs["status"]) == "escalated"

    conn.close()


def test_soak_run_closes_stale_running_control_sessions(tmp_path: Path) -> None:
    repo_root = tmp_path / "wicap"
    preferred_runner = repo_root / "tests" / "soak_test.py"
    preferred_runner.parent.mkdir(parents=True)
    preferred_runner.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (repo_root / "logs_soak_1700000000").mkdir(parents=True)

    conn = connect_db(tmp_path / "assistant.db")
    stale_id = insert_control_session(
        conn,
        soak_run_id=None,
        started_ts="2026-02-11T00:00:00+00:00",
        mode="assist",
        status="running",
        current_phase="observe",
        metadata_json={"reason": "stale"},
    )
    conn.commit()

    class _DummyProc:
        def __init__(self) -> None:
            self._poll_count = 0
            self.returncode = None

        def poll(self):  # type: ignore[no-untyped-def]
            self._poll_count += 1
            if self._poll_count >= 2:
                self.returncode = 0
                return 0
            return None

        def wait(self, timeout=None):  # type: ignore[no-untyped-def]
            self.returncode = 0
            return 0

        def terminate(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

        def kill(self):  # type: ignore[no-untyped-def]
            self.returncode = 0

    def fake_process_factory(command, *, repo_root, handle):  # type: ignore[no-untyped-def]
        (repo_root / "logs_soak_1700000200").mkdir(parents=True)
        handle.write("run ok\n")
        return _DummyProc()

    def fake_observe(_conn_arg):  # type: ignore[no-untyped-def]
        return {
            "ts": "2026-02-11T01:20:00+00:00",
            "service_status": {
                "docker": {
                    "services": {
                        "wicap-ui": {"state": "up", "status": "Up 2m"},
                    }
                }
            },
            "top_signatures": [],
            "alert": "",
        }

    summary = run_supervised_soak(
        conn,
        duration_minutes=1,
        playwright_interval_minutes=1,
        baseline_path=None,
        baseline_update=False,
        dry_run=False,
        managed_observe=True,
        observe_interval_seconds=0.1,
        control_mode="assist",
        repo_root=repo_root,
        run_root=tmp_path / "runs",
        process_factory=fake_process_factory,
        observe_hook=fake_observe,
        ingest_hook=lambda *_args, **_kwargs: (0, 0),  # type: ignore[no-untyped-def]
        incident_hook=lambda *_args, **_kwargs: tmp_path / "incident.md",  # type: ignore[no-untyped-def]
        control_runner=lambda *args, **kwargs: _DummyResult(0),  # type: ignore[no-untyped-def]
    )

    stale = conn.execute("SELECT status, ended_ts FROM control_sessions WHERE id = ?", (stale_id,)).fetchone()
    assert stale is not None
    assert str(stale["status"]) == "interrupted"
    assert stale["ended_ts"] is not None
    assert summary["control_session_id"] != stale_id

    conn.close()
