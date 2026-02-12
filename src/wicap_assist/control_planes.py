"""OpenClaw-style control plane policy evaluation for live actions."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from typing import Any

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}

_ENV_RUNTIME_ENABLED = "WICAP_ASSIST_RUNTIME_PLANE_ENABLED"
_ENV_TOOL_POLICY_ENABLED = "WICAP_ASSIST_TOOL_POLICY_PLANE_ENABLED"
_ENV_ELEVATED_ENABLED = "WICAP_ASSIST_ELEVATED_PLANE_ENABLED"
_ENV_ACTION_BUDGET_MAX = "WICAP_ASSIST_ACTION_BUDGET_MAX"
_ENV_ELEVATED_ACTION_BUDGET_MAX = "WICAP_ASSIST_ELEVATED_ACTION_BUDGET_MAX"
_ENV_DENY_ACTIONS = "WICAP_ASSIST_DENY_ACTIONS"
_ENV_AUTONOMOUS_KILL_SWITCH = "WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH"


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    value = str(raw).strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    return bool(default)


def _env_int(name: str, *, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return int(default)


def _env_list(name: str) -> tuple[str, ...]:
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return ()
    return tuple(
        item.strip().lower()
        for item in raw.split(",")
        if item.strip()
    )


@dataclass(slots=True)
class ControlPlaneDecision:
    allowed: bool
    denied_by: str | None = None
    reason: str = ""
    policy_trace: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ControlPlanePolicy:
    """Evaluate action eligibility across runtime/tool/elevated planes."""

    runtime_enabled: bool = True
    tool_policy_enabled: bool = True
    elevated_enabled: bool = True
    allowlisted_actions: tuple[str, ...] = ("status_check", "compose_up", "shutdown", "restart_service")
    elevated_required_actions: tuple[str, ...] = ("compose_up", "shutdown", "restart_service")
    deny_actions: tuple[str, ...] = ()
    action_budget_max: int | None = None
    elevated_action_budget_max: int | None = None
    action_budget_used: int = 0
    elevated_action_budget_used: int = 0

    @classmethod
    def from_env(cls) -> ControlPlanePolicy:
        action_budget_max = _env_int(_ENV_ACTION_BUDGET_MAX, default=0)
        elevated_budget_max = _env_int(_ENV_ELEVATED_ACTION_BUDGET_MAX, default=0)
        return cls(
            runtime_enabled=_env_bool(_ENV_RUNTIME_ENABLED, default=True),
            tool_policy_enabled=_env_bool(_ENV_TOOL_POLICY_ENABLED, default=True),
            elevated_enabled=_env_bool(_ENV_ELEVATED_ENABLED, default=True),
            deny_actions=_env_list(_ENV_DENY_ACTIONS),
            action_budget_max=(action_budget_max if action_budget_max > 0 else None),
            elevated_action_budget_max=(elevated_budget_max if elevated_budget_max > 0 else None),
        )

    def reset_budgets(self) -> None:
        self.action_budget_used = 0
        self.elevated_action_budget_used = 0

    def _trace_for(
        self,
        *,
        action_name: str,
        mode: str,
        denied_by: str | None,
        deny_reasons: list[str],
    ) -> dict[str, Any]:
        normalized_mode = str(mode).strip().lower()
        payload = {
            "action_name": action_name,
            "mode": normalized_mode,
            "plane_decisions": {
                "runtime_plane": bool(self.runtime_enabled),
                "tool_policy_plane": bool(self.tool_policy_enabled),
                "elevated_plane": bool(self.elevated_enabled),
            },
            "deny_reasons": list(deny_reasons),
            "denied_by": denied_by,
            "budget_state": {
                "action_budget_used": int(self.action_budget_used),
                "action_budget_max": int(self.action_budget_max) if self.action_budget_max is not None else None,
                "elevated_action_budget_used": int(self.elevated_action_budget_used),
                "elevated_action_budget_max": (
                    int(self.elevated_action_budget_max) if self.elevated_action_budget_max is not None else None
                ),
            },
        }
        seed = (
            f"{payload['action_name']}|{payload['mode']}|"
            f"{payload['plane_decisions']}|{payload['deny_reasons']}|{payload['budget_state']}"
        )
        payload["trace_id"] = hashlib.sha1(seed.encode("utf-8", errors="replace")).hexdigest()[:16]
        return payload

    def evaluate(
        self,
        *,
        action_name: str,
        mode: str = "observe",
        record_usage: bool = False,
    ) -> ControlPlaneDecision:
        """Apply deny-precedence checks for one normalized action name."""
        normalized = str(action_name).strip().lower()
        deny_reasons: list[str] = []
        denied_by: str | None = None
        elevated_required = normalized in set(self.elevated_required_actions)
        kill_switch_active = (
            str(os.environ.get(_ENV_AUTONOMOUS_KILL_SWITCH, "")).strip().lower() in _TRUE_VALUES
        )
        normalized_mode = str(mode).strip().lower() or "observe"

        if normalized_mode == "autonomous" and kill_switch_active:
            denied_by = "runtime_plane"
            deny_reasons.append("autonomous kill-switch is active")
        elif not self.runtime_enabled:
            denied_by = "runtime_plane"
            deny_reasons.append("runtime plane disabled")

        if denied_by is None and not self.tool_policy_enabled:
            denied_by = "tool_policy_plane"
            deny_reasons.append("tool policy plane disabled")

        if denied_by is None and normalized in set(self.deny_actions):
            denied_by = "tool_policy_plane"
            deny_reasons.append(f"action denied by explicit policy denylist: {normalized}")

        if denied_by is None and normalized not in set(self.allowlisted_actions):
            denied_by = "tool_policy_plane"
            deny_reasons.append(f"action is not allowlisted: {normalized}")

        if denied_by is None and elevated_required and not self.elevated_enabled:
            denied_by = "elevated_plane"
            deny_reasons.append(f"elevated plane disabled for action: {normalized}")

        if denied_by is None and self.action_budget_max is not None:
            if int(self.action_budget_used) >= int(self.action_budget_max):
                denied_by = "tool_policy_plane"
                deny_reasons.append(
                    f"action budget exhausted ({self.action_budget_used}/{self.action_budget_max})"
                )

        if denied_by is None and elevated_required and self.elevated_action_budget_max is not None:
            if int(self.elevated_action_budget_used) >= int(self.elevated_action_budget_max):
                denied_by = "elevated_plane"
                deny_reasons.append(
                    "elevated action budget exhausted "
                    f"({self.elevated_action_budget_used}/{self.elevated_action_budget_max})"
                )

        allowed = denied_by is None
        if allowed and record_usage:
            self.action_budget_used = int(self.action_budget_used) + 1
            if elevated_required:
                self.elevated_action_budget_used = int(self.elevated_action_budget_used) + 1

        trace = self._trace_for(
            action_name=normalized,
            mode=normalized_mode,
            denied_by=denied_by,
            deny_reasons=deny_reasons,
        )
        if allowed:
            return ControlPlaneDecision(allowed=True, policy_trace=trace)
        return ControlPlaneDecision(
            allowed=False,
            denied_by=denied_by,
            reason=deny_reasons[0] if deny_reasons else "policy denied",
            policy_trace=trace,
        )
