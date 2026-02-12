"""Role-scoped agent runtime helpers for planner/executor/verifier/memory flows."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

ROLE_ALLOWED_ACTIONS: dict[str, tuple[str, ...]] = {
    "planner": ("status_check", "compose_up", "compose_up_core", "shutdown", "restart_service"),
    "executor": ("status_check", "compose_up", "compose_up_core", "shutdown", "restart_service"),
    "verifier": ("status_check",),
    "memory": (),
}


@dataclass(slots=True)
class AgentRoleDecision:
    role: str
    action: str
    allowed: bool
    reason: str


def _normalized_action(action: str) -> str:
    text = str(action or "").strip().lower()
    if text.startswith("restart_service:"):
        return "restart_service"
    return text


def validate_role_action(*, role: str, action: str) -> AgentRoleDecision:
    """Validate whether a role can request a concrete action."""
    normalized_role = str(role or "").strip().lower()
    normalized_action = _normalized_action(action)
    allow = set(ROLE_ALLOWED_ACTIONS.get(normalized_role, ()))
    if normalized_action in allow:
        return AgentRoleDecision(role=normalized_role, action=normalized_action, allowed=True, reason="")
    return AgentRoleDecision(
        role=normalized_role,
        action=normalized_action,
        allowed=False,
        reason=f"role '{normalized_role}' cannot execute action '{normalized_action}'",
    )


def build_handoff_token(
    *,
    planner_intent: str,
    action: str,
    verifier_step: str,
    ts: str,
) -> str:
    """Create deterministic handoff token linking planner->executor->verifier."""
    seed = f"{planner_intent}|{action}|{verifier_step}|{ts}"
    return hashlib.sha1(seed.encode("utf-8", errors="replace")).hexdigest()[:20]


def orchestrate_role_handoff(
    *,
    planner_intent: str,
    action: str,
    verifier_step: str,
    ts: str,
) -> dict[str, Any]:
    """Build handoff object used by control event metadata."""
    return {
        "planner_intent": str(planner_intent).strip(),
        "executor_action": str(action).strip(),
        "verifier_step": str(verifier_step).strip(),
        "handoff_token": build_handoff_token(
            planner_intent=str(planner_intent),
            action=str(action),
            verifier_step=str(verifier_step),
            ts=str(ts),
        ),
    }
