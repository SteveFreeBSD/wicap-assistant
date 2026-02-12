from __future__ import annotations

from wicap_assist.control_planes import ControlPlanePolicy


def test_control_plane_denies_when_runtime_plane_disabled() -> None:
    policy = ControlPlanePolicy(runtime_enabled=False, tool_policy_enabled=True, elevated_enabled=True)
    decision = policy.evaluate(action_name="status_check")
    assert decision.allowed is False
    assert decision.denied_by == "runtime_plane"


def test_control_plane_denies_when_tool_policy_plane_disabled() -> None:
    policy = ControlPlanePolicy(runtime_enabled=True, tool_policy_enabled=False, elevated_enabled=True)
    decision = policy.evaluate(action_name="status_check")
    assert decision.allowed is False
    assert decision.denied_by == "tool_policy_plane"


def test_control_plane_denies_elevated_action_when_elevated_plane_disabled() -> None:
    policy = ControlPlanePolicy(runtime_enabled=True, tool_policy_enabled=True, elevated_enabled=False)
    decision = policy.evaluate(action_name="compose_up")
    assert decision.allowed is False
    assert decision.denied_by == "elevated_plane"


def test_control_plane_allows_non_elevated_action_when_elevated_plane_disabled() -> None:
    policy = ControlPlanePolicy(runtime_enabled=True, tool_policy_enabled=True, elevated_enabled=False)
    decision = policy.evaluate(action_name="status_check")
    assert decision.allowed is True
    assert decision.denied_by is None


def test_control_plane_denies_when_action_budget_exhausted() -> None:
    policy = ControlPlanePolicy(
        runtime_enabled=True,
        tool_policy_enabled=True,
        elevated_enabled=True,
        action_budget_max=1,
    )
    first = policy.evaluate(action_name="status_check", mode="assist", record_usage=True)
    second = policy.evaluate(action_name="status_check", mode="assist", record_usage=True)
    assert first.allowed is True
    assert second.allowed is False
    assert second.denied_by == "tool_policy_plane"
    assert "budget exhausted" in second.reason


def test_control_plane_denies_autonomous_when_kill_switch_active(monkeypatch) -> None:
    monkeypatch.setenv("WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH", "1")
    policy = ControlPlanePolicy(runtime_enabled=True, tool_policy_enabled=True, elevated_enabled=True)
    decision = policy.evaluate(action_name="status_check", mode="autonomous")
    assert decision.allowed is False
    assert decision.denied_by == "runtime_plane"
    assert "kill-switch" in decision.reason
