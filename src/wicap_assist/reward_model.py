"""Deterministic reward modeling for control-loop outcomes."""

from __future__ import annotations

from typing import Any, Mapping


_FAIL_STATUSES = {"executed_fail", "missing_script", "rejected"}


def _as_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _as_int(value: object, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _as_float(value: object, *, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _count_top_signatures(pre_state: Mapping[str, Any]) -> int:
    top = pre_state.get("top_signatures")
    if not isinstance(top, list):
        return 0
    count = 0
    for item in top:
        if not isinstance(item, dict):
            continue
        signature = str(item.get("signature", "")).strip()
        if signature:
            count += 1
    return count


def _durability_component(
    *,
    status: str,
    down_service_count: int,
    unresolved_signature_count: int,
) -> float:
    if status == "executed_ok":
        if down_service_count == 0 and unresolved_signature_count == 0:
            return 0.24
        if down_service_count == 0:
            return 0.12
        return -0.08
    if status == "escalated":
        return -0.18
    if status in _FAIL_STATUSES:
        return -0.12
    return 0.0


def _ttr_component(*, status: str, max_down_streak: int) -> float:
    # Approximate TTR from down streak length when explicit timing is not available.
    if status != "executed_ok":
        return -0.04 if status in _FAIL_STATUSES else 0.0
    if max_down_streak <= 1:
        return 0.20
    if max_down_streak <= 3:
        return 0.10
    if max_down_streak <= 6:
        return 0.02
    return -0.08


def _recurrence_component(
    *,
    status: str,
    prior_fail: int,
    unresolved_signature_count: int,
) -> float:
    raw_penalty = min(0.34, (0.05 * float(max(0, prior_fail))) + (0.03 * float(max(0, unresolved_signature_count))))
    if status == "executed_ok":
        return -raw_penalty
    if status in _FAIL_STATUSES or status == "escalated":
        return -min(0.46, raw_penalty + 0.10)
    return -min(0.20, raw_penalty / 2.0)


def _verification_component(*, status: str, detail: Mapping[str, Any]) -> float:
    explicit_pass = bool(detail.get("verification_passed"))
    explicit_fail = bool(detail.get("verification_failed"))
    if explicit_pass and not explicit_fail:
        return 0.18
    if explicit_fail and not explicit_pass:
        return -0.18
    if status == "executed_ok":
        return 0.10
    if status in _FAIL_STATUSES:
        return -0.14
    if status == "escalated":
        return -0.22
    return 0.0


def _label_for_reward(value: float) -> str:
    if value >= 0.35:
        return "positive"
    if value <= -0.35:
        return "negative"
    return "neutral"


def compute_reward_signal(
    *,
    event: Mapping[str, Any],
    prior_stats: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute deterministic reward components and an outcome label."""
    detail = _as_dict(event.get("detail_json"))
    pre_state = _as_dict(event.get("pre_state_json"))
    status = str(event.get("status", "")).strip().lower()
    prior = dict(prior_stats or {})

    down_service_count = _as_int(
        detail.get("down_service_count", pre_state.get("down_service_count", 0)),
        default=0,
    )
    if down_service_count <= 0:
        down_services = pre_state.get("down_services")
        if isinstance(down_services, list):
            down_service_count = sum(1 for item in down_services if str(item).strip())

    unresolved_signature_count = _count_top_signatures(pre_state)
    max_down_streak = _as_int(detail.get("max_down_streak", pre_state.get("max_down_streak", 0)), default=0)
    prior_fail = _as_int(prior.get("prior_fail", 0), default=0)

    outcome_component = 0.0
    if status == "executed_ok":
        outcome_component = 0.34
    elif status in _FAIL_STATUSES:
        outcome_component = -0.40
    elif status == "escalated":
        outcome_component = -0.56

    durability_component = _durability_component(
        status=status,
        down_service_count=down_service_count,
        unresolved_signature_count=unresolved_signature_count,
    )
    ttr_component = _ttr_component(status=status, max_down_streak=max_down_streak)
    recurrence_component = _recurrence_component(
        status=status,
        prior_fail=prior_fail,
        unresolved_signature_count=unresolved_signature_count,
    )
    verification_component = _verification_component(status=status, detail=detail)

    reward = (
        float(outcome_component)
        + float(durability_component)
        + float(ttr_component)
        + float(recurrence_component)
        + float(verification_component)
    )
    reward = max(-1.0, min(1.0, reward))
    reward = round(float(reward), 4)
    label = _label_for_reward(reward)

    components = {
        "outcome": round(float(outcome_component), 4),
        "durability": round(float(durability_component), 4),
        "ttr": round(float(ttr_component), 4),
        "recurrence": round(float(recurrence_component), 4),
        "verification": round(float(verification_component), 4),
    }

    return {
        "reward": reward,
        "label": label,
        "components": components,
        "signals": {
            "status": status,
            "down_service_count": int(max(0, down_service_count)),
            "unresolved_signature_count": int(max(0, unresolved_signature_count)),
            "max_down_streak": int(max(0, max_down_streak)),
            "prior_fail": int(max(0, prior_fail)),
            "prior_success_rate": round(_as_float(prior.get("prior_success_rate", 0.0)), 4),
        },
    }
