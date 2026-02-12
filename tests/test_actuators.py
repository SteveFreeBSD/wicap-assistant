from __future__ import annotations

from pathlib import Path

from wicap_assist.actuators import run_allowlisted_action
from wicap_assist.control_planes import ControlPlanePolicy


class _DummyResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_status_check_missing_script_returns_missing_script(tmp_path: Path) -> None:
    result = run_allowlisted_action(
        action="status_check",
        mode="assist",
        repo_root=tmp_path,
        runner=lambda *args, **kwargs: _DummyResult(0),  # type: ignore[no-untyped-def]
    )
    assert result.status == "missing_script"
    assert result.commands == []


def test_compose_up_observe_mode_is_skipped(tmp_path: Path) -> None:
    result = run_allowlisted_action(
        action="compose_up",
        mode="observe",
        repo_root=tmp_path,
        runner=lambda *args, **kwargs: _DummyResult(0),  # type: ignore[no-untyped-def]
    )
    assert result.status == "skipped_observe_mode"
    assert result.commands == [["docker", "compose", "up", "-d"]]


def test_shutdown_executes_stop_script_then_compose_down(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    stop_script = repo / "scripts" / "stop_wicap.py"
    stop_script.parent.mkdir(parents=True)
    stop_script.write_text("print('stop')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok")

    result = run_allowlisted_action(
        action="shutdown",
        mode="assist",
        repo_root=repo,
        runner=fake_runner,
    )

    assert result.status == "executed_ok"
    assert any("stop_wicap.py" in " ".join(cmd) for cmd in calls)
    assert any(cmd[:4] == ["docker", "compose", "down", "--remove-orphans"] for cmd in calls)


def test_restart_service_executes_allowlisted_container_restart(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok")

    result = run_allowlisted_action(
        action="restart_service:wicap-ui",
        mode="assist",
        repo_root=repo,
        runner=fake_runner,
    )

    assert result.status == "executed_ok"
    assert result.commands == [["docker", "restart", "wicap-ui"]]
    assert calls == [["docker", "restart", "wicap-ui"]]


def test_restart_service_accepts_compose_service_alias(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok")

    result = run_allowlisted_action(
        action="restart_service:ui",
        mode="assist",
        repo_root=repo,
        runner=fake_runner,
    )

    assert result.status == "executed_ok"
    assert calls == [["docker", "restart", "wicap-ui"]]


def test_restart_service_rejects_unknown_service(tmp_path: Path) -> None:
    result = run_allowlisted_action(
        action="restart_service:mysql",
        mode="assist",
        repo_root=tmp_path,
        runner=lambda *args, **kwargs: _DummyResult(0),  # type: ignore[no-untyped-def]
    )
    assert result.status == "rejected"
    assert "unknown restart service" in result.detail


def test_autonomous_mode_executes_allowlisted_action(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout="ok")

    result = run_allowlisted_action(
        action="compose_up",
        mode="autonomous",
        repo_root=repo,
        runner=fake_runner,
    )

    assert result.status == "executed_ok"
    assert calls == [["docker", "compose", "up", "-d"]]


def test_status_check_uses_normalized_action_and_json_flag(tmp_path: Path) -> None:
    repo = tmp_path / "wicap"
    script = repo / "scripts" / "check_wicap_status.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('ok')\n", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_runner(cmd, cwd, capture_output, text, check, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(cmd))
        return _DummyResult(0, stdout='{"ok": true}')

    result = run_allowlisted_action(
        action=" Status_Check ",
        mode="assist",
        repo_root=repo,
        runner=fake_runner,
    )

    assert result.status == "executed_ok"
    assert calls
    assert calls[0][-2:] == ["--local-only", "--json"]


def test_compose_up_is_rejected_when_elevated_plane_disabled(tmp_path: Path) -> None:
    result = run_allowlisted_action(
        action="compose_up",
        mode="assist",
        repo_root=tmp_path,
        runner=lambda *args, **kwargs: _DummyResult(0),  # type: ignore[no-untyped-def]
        plane_policy=ControlPlanePolicy(
            runtime_enabled=True,
            tool_policy_enabled=True,
            elevated_enabled=False,
        ),
    )
    assert result.status == "rejected"
    assert "elevated_plane" in result.detail


def test_actuator_returns_policy_trace_for_rejected_action(tmp_path: Path) -> None:
    result = run_allowlisted_action(
        action="compose_up",
        mode="assist",
        repo_root=tmp_path,
        runner=lambda *args, **kwargs: _DummyResult(0),  # type: ignore[no-untyped-def]
        plane_policy=ControlPlanePolicy(
            runtime_enabled=True,
            tool_policy_enabled=True,
            elevated_enabled=True,
            action_budget_max=0,
            elevated_action_budget_max=0,
            deny_actions=("compose_up",),
        ),
    )
    assert result.status == "rejected"
    assert isinstance(result.policy_trace, dict)
    assert result.policy_trace.get("denied_by") == "tool_policy_plane"
