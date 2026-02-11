"""OpenClaw-style control plane policy evaluation for live actions."""

from __future__ import annotations

from dataclasses import dataclass
import os

_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}

_ENV_RUNTIME_ENABLED = "WICAP_ASSIST_RUNTIME_PLANE_ENABLED"
_ENV_TOOL_POLICY_ENABLED = "WICAP_ASSIST_TOOL_POLICY_PLANE_ENABLED"
_ENV_ELEVATED_ENABLED = "WICAP_ASSIST_ELEVATED_PLANE_ENABLED"


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


@dataclass(slots=True)
class ControlPlaneDecision:
    allowed: bool
    denied_by: str | None = None
    reason: str = ""


@dataclass(slots=True)
class ControlPlanePolicy:
    """Evaluate action eligibility across runtime/tool/elevated planes."""

    runtime_enabled: bool = True
    tool_policy_enabled: bool = True
    elevated_enabled: bool = True
    allowlisted_actions: tuple[str, ...] = ("status_check", "compose_up", "shutdown", "restart_service")
    elevated_required_actions: tuple[str, ...] = ("compose_up", "shutdown", "restart_service")

    @classmethod
    def from_env(cls) -> ControlPlanePolicy:
        return cls(
            runtime_enabled=_env_bool(_ENV_RUNTIME_ENABLED, default=True),
            tool_policy_enabled=_env_bool(_ENV_TOOL_POLICY_ENABLED, default=True),
            elevated_enabled=_env_bool(_ENV_ELEVATED_ENABLED, default=True),
        )

    def evaluate(self, *, action_name: str) -> ControlPlaneDecision:
        """Apply deny-precedence checks for one normalized action name."""
        normalized = str(action_name).strip().lower()

        if not self.runtime_enabled:
            return ControlPlaneDecision(
                allowed=False,
                denied_by="runtime_plane",
                reason="runtime plane disabled",
            )

        if not self.tool_policy_enabled:
            return ControlPlaneDecision(
                allowed=False,
                denied_by="tool_policy_plane",
                reason="tool policy plane disabled",
            )

        if normalized not in set(self.allowlisted_actions):
            return ControlPlaneDecision(
                allowed=False,
                denied_by="tool_policy_plane",
                reason=f"action is not allowlisted: {normalized}",
            )

        if normalized in set(self.elevated_required_actions) and not self.elevated_enabled:
            return ControlPlaneDecision(
                allowed=False,
                denied_by="elevated_plane",
                reason=f"elevated plane disabled for action: {normalized}",
            )

        return ControlPlaneDecision(allowed=True)

