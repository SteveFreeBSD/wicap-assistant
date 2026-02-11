"""Session-scoped working memory for live control loops."""

from __future__ import annotations

import json
from typing import Any, Mapping

from wicap_assist.util.evidence import normalize_signature


def parse_working_memory(raw_metadata_json: object) -> dict[str, Any]:
    """Extract working memory payload from control session metadata JSON."""
    if not isinstance(raw_metadata_json, str) or not raw_metadata_json.strip():
        return {
            "unresolved_signatures": [],
            "pending_actions": [],
            "recent_transitions": [],
            "down_services": [],
            "last_observation_ts": None,
        }
    try:
        payload = json.loads(raw_metadata_json)
    except json.JSONDecodeError:
        return {
            "unresolved_signatures": [],
            "pending_actions": [],
            "recent_transitions": [],
            "down_services": [],
            "last_observation_ts": None,
        }
    if not isinstance(payload, dict):
        return {
            "unresolved_signatures": [],
            "pending_actions": [],
            "recent_transitions": [],
            "down_services": [],
            "last_observation_ts": None,
        }
    working = payload.get("working_memory")
    if isinstance(working, dict):
        return {
            "unresolved_signatures": list(working.get("unresolved_signatures", []))
            if isinstance(working.get("unresolved_signatures"), list)
            else [],
            "pending_actions": list(working.get("pending_actions", []))
            if isinstance(working.get("pending_actions"), list)
            else [],
            "recent_transitions": list(working.get("recent_transitions", []))
            if isinstance(working.get("recent_transitions"), list)
            else [],
            "down_services": list(working.get("down_services", []))
            if isinstance(working.get("down_services"), list)
            else [],
            "last_observation_ts": working.get("last_observation_ts"),
        }
    return {
        "unresolved_signatures": [],
        "pending_actions": [],
        "recent_transitions": [],
        "down_services": [],
        "last_observation_ts": None,
    }


def _extract_down_services(observation: Mapping[str, Any]) -> list[str]:
    status = observation.get("service_status")
    if not isinstance(status, dict):
        return []
    docker = status.get("docker")
    if not isinstance(docker, dict):
        return []
    services = docker.get("services")
    if not isinstance(services, dict):
        return []
    out: list[str] = []
    for service_name, info in services.items():
        if not isinstance(info, dict):
            continue
        if str(info.get("state", "unknown")) != "up":
            value = str(service_name).strip()
            if value:
                out.append(value)
    return sorted(set(out))


def _extract_unresolved_signatures(observation: Mapping[str, Any]) -> list[str]:
    top = observation.get("top_signatures")
    if not isinstance(top, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in top:
        if not isinstance(item, dict):
            continue
        signature = normalize_signature(str(item.get("signature", "")).strip(), max_len=160)
        if not signature or signature in seen:
            continue
        seen.add(signature)
        out.append(signature)
    return out[:8]


def _build_pending_actions(events: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for event in events:
        decision = str(event.get("decision", "")).strip()
        action = str(event.get("action", "")).strip() if event.get("action") is not None else ""
        status = str(event.get("status", "")).strip()
        if status in {"stable", "executed_ok"}:
            continue
        token = action or decision
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out[:8]


def _compact_transition(event: Mapping[str, Any], *, ts_fallback: str | None = None) -> dict[str, Any]:
    detail = event.get("detail_json")
    service = None
    if isinstance(detail, dict):
        raw_service = detail.get("service")
        if isinstance(raw_service, str) and raw_service.strip():
            service = raw_service.strip()
    return {
        "ts": str(event.get("ts") or ts_fallback or ""),
        "decision": str(event.get("decision", "")).strip(),
        "action": str(event.get("action", "")).strip() if event.get("action") is not None else None,
        "status": str(event.get("status", "")).strip(),
        "service": service,
    }


def update_working_memory(
    existing: Mapping[str, Any] | None,
    *,
    observation: Mapping[str, Any],
    cycle_control_events: list[dict[str, Any]],
    max_transitions: int = 24,
) -> dict[str, Any]:
    """Merge one observation cycle into working memory state."""
    previous = dict(existing or {})
    prior_transitions = previous.get("recent_transitions", [])
    transitions: list[dict[str, Any]] = []
    if isinstance(prior_transitions, list):
        for item in prior_transitions:
            if isinstance(item, dict):
                transitions.append(dict(item))

    ts = str(observation.get("ts", "")).strip() or None
    for event in cycle_control_events:
        if not isinstance(event, dict):
            continue
        transitions.append(_compact_transition(event, ts_fallback=ts))
    if len(transitions) > max(1, int(max_transitions)):
        transitions = transitions[-max(1, int(max_transitions)) :]

    down_services = _extract_down_services(observation)
    unresolved = _extract_unresolved_signatures(observation)
    pending_actions = _build_pending_actions(cycle_control_events)

    if not down_services and not unresolved:
        pending_actions = []

    return {
        "unresolved_signatures": unresolved,
        "pending_actions": pending_actions,
        "recent_transitions": transitions,
        "down_services": down_services,
        "last_observation_ts": ts,
    }


def summarize_working_memory(memory: Mapping[str, Any] | None) -> dict[str, int]:
    """Return compact count summary for logs/events."""
    payload = dict(memory or {})
    unresolved = payload.get("unresolved_signatures")
    pending = payload.get("pending_actions")
    transitions = payload.get("recent_transitions")
    down_services = payload.get("down_services")
    return {
        "unresolved_count": len(unresolved) if isinstance(unresolved, list) else 0,
        "pending_count": len(pending) if isinstance(pending, list) else 0,
        "transition_count": len(transitions) if isinstance(transitions, list) else 0,
        "down_service_count": len(down_services) if isinstance(down_services, list) else 0,
    }

