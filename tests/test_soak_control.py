from __future__ import annotations

from pathlib import Path

from wicap_assist.soak_control import ControlPolicy


class _DummyResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _observation(*, down: bool) -> dict[str, object]:
    state = "down" if down else "up"
    status = "not running" if down else "Up 2m"
    return {
        "ts": "2026-02-11T00:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-ui": {"state": state, "status": status},
                    "wicap-processor": {"state": state, "status": status},
                }
            }
        },
    }


def _network_anomaly_observation() -> dict[str, object]:
    return {
        "ts": "2026-02-11T00:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-ui": {"state": "up", "status": "Up 2m"},
                    "wicap-processor": {"state": "up", "status": "Up 2m"},
                }
            }
        },
        "top_signatures": [
            {
                "category": "network_anomaly",
                "signature": "deauth_spike|global|aa:bb:cc:dd:ee:ff",
                "count": 3,
            }
        ],
    }


def test_control_policy_observe_mode_emits_skipped_actions(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(list(args[0]))
        return _DummyResult(0)

    policy = ControlPolicy(
        mode="observe",
        repo_root=repo,
        runner=fake_runner,
        check_threshold=1,
        recover_threshold=2,
    )

    events1 = policy.process_observation(_observation(down=True))
    events2 = policy.process_observation(_observation(down=True))

    assert calls == []
    statuses = [str(event.get("status")) for event in [*events1, *events2]]
    assert "skipped_observe_mode" in statuses


def test_control_policy_assist_mode_executes_allowlisted_actions(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok\n")

    policy = ControlPolicy(
        mode="assist",
        repo_root=repo,
        runner=fake_runner,
        check_threshold=1,
        recover_threshold=2,
    )

    policy.process_observation(_observation(down=True))
    policy.process_observation(_observation(down=True))

    assert calls
    assert any(
        ("check_wicap_status.py" in " ".join(cmd) or "scripts.check_wicap_status" in " ".join(cmd))
        for cmd in calls
    )
    assert any(cmd[:2] == ["docker", "restart"] for cmd in calls)


def test_control_policy_escalates_after_max_recover_attempts(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    def fail_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        if cmd[:4] == ["docker", "compose", "up", "-d"]:
            return _DummyResult(1, stderr="compose failed")
        return _DummyResult(0, stdout="status ok")

    policy = ControlPolicy(
        mode="assist",
        repo_root=repo,
        runner=fail_runner,
        check_threshold=1,
        recover_threshold=1,
        max_recover_attempts=1,
        action_cooldown_cycles=0,
    )

    all_events: list[dict[str, object]] = []
    for _ in range(3):
        all_events.extend(policy.process_observation(_observation(down=True)))

    assert any(str(event.get("status")) == "escalated" for event in all_events)


def test_control_policy_uses_service_specific_ladder_thresholds(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0)

    policy = ControlPolicy(
        mode="assist",
        repo_root=repo,
        runner=fake_runner,
        check_threshold=1,
        recover_threshold=2,
        max_recover_attempts=2,
        action_cooldown_cycles=0,
    )

    # Redis uses an aggressive ladder; by cycle 2 recovery should have been attempted.
    observation = {
        "ts": "2026-02-11T00:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-redis": {"state": "down", "status": "Exited"},
                }
            }
        },
    }
    cycle1 = policy.process_observation(observation)
    cycle2 = policy.process_observation(observation)
    events = [*cycle1, *cycle2]

    recover_event = next(
        (
            event
            for event in events
            if str(event.get("action", "")).startswith("restart_service:")
        ),
        None,
    )
    assert recover_event is not None
    detail = recover_event.get("detail_json")
    assert isinstance(detail, dict)
    assert int(detail.get("recover_threshold", 0)) == 1
    assert int(detail.get("max_recover_attempts", 0)) == 1
    assert any(cmd[:2] == ["docker", "restart"] for cmd in calls)


def test_control_policy_autonomous_kill_switch_escalates(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setenv("WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH", "1")

    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok\n")

    policy = ControlPolicy(
        mode="autonomous",
        repo_root=repo,
        runner=fake_runner,
        check_threshold=None,
        recover_threshold=None,
    )

    events = policy.process_observation(_observation(down=True))
    assert calls == []
    assert any(str(event.get("decision")) == "kill_switch" for event in events)
    assert any(str(event.get("status")) == "escalated" for event in events)


def test_control_policy_autonomous_runs_rollback_sequence_after_failed_recovery(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")
    kill_file = repo / ".wicap_assist_autonomous.kill"
    if kill_file.exists():
        kill_file.unlink()

    calls: list[list[str]] = []

    def fail_recover_then_rollback(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        if cmd[:2] == ["docker", "restart"]:
            return _DummyResult(1, stderr="restart failed")
        return _DummyResult(0, stdout="ok")

    policy = ControlPolicy(
        mode="autonomous",
        repo_root=repo,
        runner=fail_recover_then_rollback,
        check_threshold=1,
        recover_threshold=1,
        max_recover_attempts=2,
        action_cooldown_cycles=0,
    )

    observation = {
        "ts": "2026-02-11T00:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-redis": {"state": "down", "status": "Exited"},
                }
            }
        },
    }

    cycle1 = policy.process_observation(observation)
    cycle2 = policy.process_observation(observation)
    events = [*cycle1, *cycle2]

    assert any(str(event.get("action")) == "rollback_sequence" for event in events)
    assert any(cmd[:4] == ["docker", "compose", "down", "--remove-orphans"] for cmd in calls)
    assert any(cmd[:4] == ["docker", "compose", "up", "-d"] for cmd in calls)


def test_control_policy_emits_anomaly_route_and_runs_verify_check_in_assist_mode(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def ok_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok\n")

    policy = ControlPolicy(
        mode="assist",
        repo_root=repo,
        runner=ok_runner,
        check_threshold=2,
        recover_threshold=3,
        action_cooldown_cycles=0,
    )

    events = policy.process_observation(_network_anomaly_observation())
    assert any(str(event.get("decision")) == "anomaly_route" for event in events)
    assert any(str(event.get("decision")) == "anomaly_verify" for event in events)
    assert any("check_wicap_status.py" in " ".join(cmd) or "scripts.check_wicap_status" in " ".join(cmd) for cmd in calls)


def test_control_policy_emits_health_probe_on_stable_cycle(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def ok_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok\n")

    policy = ControlPolicy(
        mode="assist",
        repo_root=repo,
        runner=ok_runner,
        check_threshold=2,
        recover_threshold=3,
        health_probe_interval_cycles=1,
    )

    observation = _observation(down=False)
    events = policy.process_observation(observation)
    probe = next((event for event in events if str(event.get("decision")) == "health_probe"), None)
    assert probe is not None
    assert str(probe.get("action")) == "status_check"
    assert any("check_wicap_status.py" in " ".join(cmd) or "scripts.check_wicap_status" in " ".join(cmd) for cmd in calls)


def test_control_policy_emits_health_probe_without_status_script(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    repo.mkdir(parents=True)

    calls: list[list[str]] = []

    def ok_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok\n")

    policy = ControlPolicy(
        mode="assist",
        repo_root=repo,
        runner=ok_runner,
        check_threshold=2,
        recover_threshold=3,
        health_probe_interval_cycles=1,
    )

    observation = _observation(down=False)
    events = policy.process_observation(observation)
    probe = next((event for event in events if str(event.get("decision")) == "health_probe"), None)
    assert probe is not None
    assert str(probe.get("action")) == "status_check"
    assert str(probe.get("status")) == "executed_ok"
    assert calls == []


def test_control_policy_ignores_scout_down_for_health_state(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def ok_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok\n")

    policy = ControlPolicy(
        mode="autonomous",
        repo_root=repo,
        runner=ok_runner,
        check_threshold=2,
        recover_threshold=3,
        health_probe_interval_cycles=1,
    )

    observation = {
        "ts": "2026-02-11T00:00:00+00:00",
        "service_status": {
            "docker": {
                "services": {
                    "wicap-ui": {"state": "up", "status": "Up 2m"},
                    "wicap-processor": {"state": "up", "status": "Up 2m"},
                    "wicap-scout": {"state": "down", "status": "not running"},
                }
            }
        },
    }

    events = policy.process_observation(observation)
    health = next((event for event in events if str(event.get("decision")) == "service_health"), None)
    assert health is not None
    assert str(health.get("status")) == "stable"
    assert any(str(event.get("decision")) == "health_probe" for event in events)
