"""Deterministic soak control policy with allowlisted recovery actions."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
from typing import Any, Callable

from wicap_assist.actuators import run_allowlisted_action
from wicap_assist.agent_runtime import orchestrate_role_handoff
from wicap_assist.anomaly_routing import route_for_anomaly
from wicap_assist.failover_profiles import classify_failover_failure
from wicap_assist.util.time import utc_now_iso

ControlRunner = Callable[..., subprocess.CompletedProcess[str]]
_AUTONOMOUS_KILL_SWITCH_FILE = ".wicap_assist_autonomous.kill"
_KILL_SWITCH_TRUE_VALUES = {"1", "true", "yes", "on"}


def _default_policy_profile(
    *,
    mode: str,
    check_threshold: int | None,
    recover_threshold: int | None,
    max_recover_attempts: int | None,
    action_cooldown_cycles: int | None,
    repo_root: Path,
    kill_switch_env_var: str | None,
    kill_switch_file: Path | None,
    rollback_enabled: bool | None,
    rollback_actions: tuple[str, ...] | None,
    rollback_max_attempts: int | None,
) -> dict[str, object]:
    normalized_mode = str(mode).strip()
    if normalized_mode == "autonomous":
        default_check = 2
        default_recover = 3
        default_max_recover = 3
        default_cooldown = 1
        default_rollbacks = ("shutdown", "compose_up_core")
        return {
            "name": "autonomous-v1",
            "check_threshold": max(1, int(check_threshold if check_threshold is not None else default_check)),
            "recover_threshold": max(
                1,
                int(recover_threshold if recover_threshold is not None else default_recover),
            ),
            "max_recover_attempts": max(
                1,
                int(max_recover_attempts if max_recover_attempts is not None else default_max_recover),
            ),
            "action_cooldown_cycles": max(
                0,
                int(action_cooldown_cycles if action_cooldown_cycles is not None else default_cooldown),
            ),
            "kill_switch_env_var": str(kill_switch_env_var or "WICAP_ASSIST_AUTONOMOUS_KILL_SWITCH").strip(),
            "kill_switch_file": (
                kill_switch_file.resolve()
                if kill_switch_file is not None
                else (repo_root / _AUTONOMOUS_KILL_SWITCH_FILE).resolve()
            ),
            "rollback_enabled": bool(True if rollback_enabled is None else rollback_enabled),
            "rollback_actions": tuple(
                item.strip()
                for item in (rollback_actions if rollback_actions is not None else default_rollbacks)
                if item.strip()
            )
            or default_rollbacks,
            "rollback_max_attempts": max(
                1,
                int(rollback_max_attempts if rollback_max_attempts is not None else 1),
            ),
        }

    default_check = 3
    default_recover = 5
    default_max_recover = 2
    default_cooldown = 1
    return {
        "name": "supervised-v1",
        "check_threshold": max(1, int(check_threshold if check_threshold is not None else default_check)),
        "recover_threshold": max(
            1,
            int(recover_threshold if recover_threshold is not None else default_recover),
        ),
        "max_recover_attempts": max(
            1,
            int(max_recover_attempts if max_recover_attempts is not None else default_max_recover),
        ),
        "action_cooldown_cycles": max(
            0,
            int(action_cooldown_cycles if action_cooldown_cycles is not None else default_cooldown),
        ),
        "kill_switch_env_var": None,
        "kill_switch_file": None,
        "rollback_enabled": bool(False if rollback_enabled is None else rollback_enabled),
        "rollback_actions": tuple(
            item.strip()
            for item in (rollback_actions or ())
            if item.strip()
        ),
        "rollback_max_attempts": max(
            1,
            int(rollback_max_attempts if rollback_max_attempts is not None else 1),
        ),
    }


def _default_service_ladders(
    *,
    check_threshold: int,
    recover_threshold: int,
    max_recover_attempts: int,
) -> dict[str, dict[str, int]]:
    base_check = max(1, int(check_threshold))
    base_recover = max(1, int(recover_threshold))
    base_max = max(1, int(max_recover_attempts))
    return {
        # ui startup is often noisy; wait longer before compose recovery.
        "wicap-ui": {
            "check_threshold": max(base_check, 2),
            "recover_threshold": max(base_recover + 2, 3),
            "max_recover_attempts": base_max,
        },
        "wicap-processor": {
            "check_threshold": base_check,
            "recover_threshold": base_recover,
            "max_recover_attempts": base_max,
        },
        "wicap-scout": {
            "check_threshold": base_check,
            "recover_threshold": max(1, base_recover - 1),
            "max_recover_attempts": base_max,
        },
        "wicap-redis": {
            "check_threshold": base_check,
            "recover_threshold": max(1, base_recover - 1),
            "max_recover_attempts": max(1, base_max - 1),
        },
    }


@dataclass(slots=True)
class ControlPolicy:
    """Stateful deterministic control policy for supervised soak runs."""

    mode: str
    repo_root: Path
    runner: ControlRunner
    check_threshold: int | None
    recover_threshold: int | None
    max_recover_attempts: int | None = None
    action_cooldown_cycles: int | None = None
    timeout_seconds: int = 120
    service_ladders: dict[str, dict[str, int]] | None = None
    kill_switch_env_var: str | None = None
    kill_switch_file: Path | None = None
    rollback_enabled: bool | None = None
    rollback_actions: tuple[str, ...] | None = None
    rollback_max_attempts: int | None = None
    profile_name: str = field(default="", init=False)
    _service_state: dict[str, dict[str, int]] = field(default_factory=dict, init=False)
    _anomaly_state: dict[str, int] = field(default_factory=dict, init=False)
    _cycle: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.mode = str(self.mode).strip().lower()
        if self.mode == "monitor":
            self.mode = "observe"
        if self.mode not in {"observe", "assist", "autonomous"}:
            raise ValueError("control mode must be observe, assist, or autonomous")
        self.repo_root = self.repo_root.resolve()
        profile = _default_policy_profile(
            mode=self.mode,
            check_threshold=self.check_threshold,
            recover_threshold=self.recover_threshold,
            max_recover_attempts=self.max_recover_attempts,
            action_cooldown_cycles=self.action_cooldown_cycles,
            repo_root=self.repo_root,
            kill_switch_env_var=self.kill_switch_env_var,
            kill_switch_file=self.kill_switch_file,
            rollback_enabled=self.rollback_enabled,
            rollback_actions=self.rollback_actions,
            rollback_max_attempts=self.rollback_max_attempts,
        )
        self.profile_name = str(profile["name"])
        self.check_threshold = int(profile["check_threshold"])
        self.recover_threshold = int(profile["recover_threshold"])
        self.max_recover_attempts = int(profile["max_recover_attempts"])
        self.action_cooldown_cycles = int(profile["action_cooldown_cycles"])
        self.kill_switch_env_var = (
            str(profile["kill_switch_env_var"])
            if profile.get("kill_switch_env_var") is not None
            else None
        )
        self.kill_switch_file = (
            Path(str(profile["kill_switch_file"])).resolve()
            if profile.get("kill_switch_file") is not None
            else None
        )
        self.rollback_enabled = bool(profile["rollback_enabled"])
        self.rollback_actions = tuple(str(item) for item in profile["rollback_actions"])
        self.rollback_max_attempts = int(profile["rollback_max_attempts"])

        normalized: dict[str, dict[str, int]] = {}
        source = self.service_ladders or _default_service_ladders(
            check_threshold=self.check_threshold,
            recover_threshold=self.recover_threshold,
            max_recover_attempts=self.max_recover_attempts,
        )
        for service, values in source.items():
            if not isinstance(values, dict):
                continue
            normalized[str(service)] = {
                "check_threshold": max(1, int(values.get("check_threshold", self.check_threshold))),
                "recover_threshold": max(1, int(values.get("recover_threshold", self.recover_threshold))),
                "max_recover_attempts": max(
                    1,
                    int(values.get("max_recover_attempts", self.max_recover_attempts)),
                ),
            }
        self.service_ladders = normalized

    def _state_for(self, service: str) -> dict[str, int]:
        return self._service_state.setdefault(
            service,
            {
                "down_streak": 0,
                "check_attempts": 0,
                "recover_attempts": 0,
                "rollback_attempts": 0,
                "cooldown_until": 0,
                "escalated": 0,
            },
        )

    def _run_allowlisted(self, action: str) -> tuple[str, list[str], str, dict[str, Any], str]:
        result = run_allowlisted_action(
            action=str(action),
            mode=self.mode,
            repo_root=self.repo_root,
            runner=self.runner,
            timeout_seconds=max(1, int(self.timeout_seconds)),
        )
        flat_command = result.commands[0] if result.commands else []
        trace = result.policy_trace if isinstance(result.policy_trace, dict) else {}
        failure_class = (
            classify_failover_failure(status=result.status, detail=result.detail)
            if str(result.status) not in {"executed_ok", "stable", "skipped_observe_mode"}
            else "none"
        )
        return result.status, flat_command, result.detail, trace, failure_class

    def _ladder_for(self, service: str) -> dict[str, int]:
        ladder = (self.service_ladders or {}).get(service)
        if ladder is None:
            return {
                "check_threshold": int(self.check_threshold),
                "recover_threshold": int(self.recover_threshold),
                "max_recover_attempts": int(self.max_recover_attempts),
            }
        return {
            "check_threshold": max(1, int(ladder.get("check_threshold", self.check_threshold))),
            "recover_threshold": max(1, int(ladder.get("recover_threshold", self.recover_threshold))),
            "max_recover_attempts": max(1, int(ladder.get("max_recover_attempts", self.max_recover_attempts))),
        }

    def _kill_switch_state(self) -> tuple[bool, dict[str, object]]:
        if self.mode != "autonomous":
            return False, {"enabled": False}
        env_var = str(self.kill_switch_env_var or "").strip()
        env_value = os.environ.get(env_var, "") if env_var else ""
        env_active = str(env_value).strip().lower() in _KILL_SWITCH_TRUE_VALUES if env_var else False
        file_path = self.kill_switch_file.resolve() if self.kill_switch_file is not None else None
        file_active = bool(file_path and file_path.exists())
        active = bool(env_active or file_active)
        detail: dict[str, object] = {
            "enabled": True,
            "active": active,
            "mode": self.mode,
            "env_var": env_var or None,
            "env_active": bool(env_active),
            "file_path": str(file_path) if file_path is not None else None,
            "file_active": bool(file_active),
        }
        return active, detail

    def _run_rollback_sequence(
        self,
        *,
        ts: str,
        service_name: str,
        trigger_action: str,
        trigger_status: str,
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not bool(self.rollback_enabled):
            return events

        state = self._state_for(service_name)
        rollback_attempts = int(state["rollback_attempts"])
        max_rollbacks = int(self.rollback_max_attempts or 1)
        if rollback_attempts >= max_rollbacks:
            state["escalated"] = 1
            events.append(
                {
                    "ts": ts,
                    "decision": "rollback_rule",
                    "action": "rollback_sequence",
                    "status": "escalated",
                    "detail_json": {
                        "service": service_name,
                        "reason": "rollback_attempts_exhausted",
                        "rollback_attempts": rollback_attempts,
                        "rollback_max_attempts": max_rollbacks,
                        "trigger_action": trigger_action,
                        "trigger_status": trigger_status,
                    },
                }
            )
            return events

        state["rollback_attempts"] = rollback_attempts + 1
        sequence = list(self.rollback_actions or ())
        action_results: list[dict[str, object]] = []
        failed = False
        for action in sequence:
            status, command, detail, policy_trace, failure_class = self._run_allowlisted(action)
            action_results.append(
                {
                    "action": action,
                    "status": status,
                    "command": command,
                    "detail": detail,
                    "policy_trace": policy_trace,
                    "failure_class": failure_class,
                }
            )
            if status == "executed_ok":
                state["cooldown_until"] = int(self._cycle + self.action_cooldown_cycles)
                continue
            failed = True
            break

        summary_status = "executed_fail" if failed else "executed_ok"
        events.append(
            {
                "ts": ts,
                "decision": "rollback_rule",
                "action": "rollback_sequence",
                "status": summary_status,
                "detail_json": {
                    "service": service_name,
                    "trigger_action": trigger_action,
                    "trigger_status": trigger_status,
                    "rollback_attempts": int(state["rollback_attempts"]),
                    "rollback_max_attempts": max_rollbacks,
                    "actions": action_results,
                },
            }
        )

        if failed:
            state["escalated"] = 1
            events.append(
                {
                    "ts": ts,
                    "decision": "rollback_rule",
                    "action": None,
                    "status": "escalated",
                    "detail_json": {
                        "service": service_name,
                        "reason": "rollback_failed",
                        "trigger_action": trigger_action,
                        "trigger_status": trigger_status,
                        "rollback_attempts": int(state["rollback_attempts"]),
                        "rollback_max_attempts": max_rollbacks,
                    },
                }
            )

        return events

    def process_observation(self, observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Return deterministic control events for one observation cycle."""
        self._cycle += 1
        ts = str(observation.get("ts") or utc_now_iso())
        down_services: list[str] = []

        service_status = observation.get("service_status", {})
        docker = service_status.get("docker", {}) if isinstance(service_status, dict) else {}
        services = docker.get("services", {}) if isinstance(docker, dict) else {}
        if isinstance(services, dict):
            for service_name, info in services.items():
                if not isinstance(info, dict):
                    continue
                if str(info.get("state", "unknown")) != "up":
                    down_services.append(str(service_name))

        down_set = set(down_services)
        for service_name in sorted(self._service_state):
            if service_name in down_set:
                continue
            state = self._state_for(service_name)
            state["down_streak"] = 0
            state["check_attempts"] = 0
            state["recover_attempts"] = 0
            state["rollback_attempts"] = 0
            state["cooldown_until"] = 0
            state["escalated"] = 0

        for service_name in sorted(down_set):
            state = self._state_for(service_name)
            state["down_streak"] = int(state["down_streak"]) + 1

        max_streak = max((int(self._state_for(name)["down_streak"]) for name in down_set), default=0)
        events: list[dict[str, Any]] = []
        anomaly_routes: list[dict[str, Any]] = []
        top_signatures = observation.get("top_signatures")
        if isinstance(top_signatures, list):
            for item in top_signatures:
                if not isinstance(item, dict):
                    continue
                category = str(item.get("category", "")).strip()
                if category not in {"network_anomaly", "network_flow"}:
                    continue
                signature = str(item.get("signature", "")).strip()
                if not signature:
                    continue
                attack_type_value = item.get("attack_type")
                attack_type = str(attack_type_value).strip().lower() if isinstance(attack_type_value, str) else None
                if not attack_type and "|" in signature:
                    attack_type = signature.split("|", 1)[0].strip().lower()
                anomaly_routes.append(
                    {
                        "category": category,
                        "signature": signature,
                        "route": route_for_anomaly(
                            signature=signature,
                            category=category,
                            attack_type=attack_type,
                        ),
                    }
                )

        events.append(
            {
                "ts": ts,
                "decision": "service_health",
                "action": None,
                "status": "down_detected" if down_services else "stable",
                "detail_json": {
                    "down_services": sorted(down_services),
                    "max_down_streak": int(max_streak),
                    "cycle": int(self._cycle),
                    "mode": self.mode,
                    "profile": self.profile_name,
                    "anomaly_routes": [item.get("route", {}) for item in anomaly_routes],
                },
            }
        )

        for item in anomaly_routes:
            route = item.get("route")
            if not isinstance(route, dict):
                continue
            class_id = str(route.get("class_id", "")).strip()
            signature = str(item.get("signature", "")).strip()
            category = str(item.get("category", "")).strip()
            if not class_id or not signature:
                continue
            route_key = f"{class_id}|{signature}"
            events.append(
                {
                    "ts": ts,
                    "decision": "anomaly_route",
                    "action": None,
                    "status": "planned",
                    "detail_json": {
                        "cycle": int(self._cycle),
                        "category": category,
                        "signature": signature,
                        "anomaly_class": class_id,
                        "action_ladder": [str(value) for value in route.get("action_ladder", []) if str(value).strip()],
                        "verification_ladder": [
                            str(value) for value in route.get("verification_ladder", []) if str(value).strip()
                        ],
                        "feedback": route.get("feedback", {}),
                    },
                }
            )
            if self.mode not in {"assist", "autonomous"}:
                continue
            action_ladder = route.get("action_ladder", [])
            if not isinstance(action_ladder, list) or not action_ladder:
                continue
            primary_action = str(action_ladder[0]).strip().lower()
            if primary_action != "status_check":
                continue
            cooldown_until = int(self._anomaly_state.get(route_key, 0))
            if int(self._cycle) < cooldown_until:
                continue
            status, command, detail, policy_trace, failure_class = self._run_allowlisted("status_check")
            self._anomaly_state[route_key] = int(self._cycle + max(1, self.action_cooldown_cycles))
            events.append(
                {
                    "ts": ts,
                    "decision": "anomaly_verify",
                    "action": "status_check",
                    "status": status,
                    "detail_json": {
                        "cycle": int(self._cycle),
                        "category": category,
                        "signature": signature,
                        "anomaly_class": class_id,
                        "command": command,
                        "detail": detail,
                        "policy_trace": policy_trace,
                        "failure_class": failure_class,
                        "handoff": orchestrate_role_handoff(
                            planner_intent=f"anomaly_route:{class_id}",
                            action="status_check",
                            verifier_step="status_check",
                            ts=ts,
                        ),
                    },
                }
            )

        if not down_services:
            return events

        kill_switch_active, kill_switch_detail = self._kill_switch_state()
        if kill_switch_active:
            for service_name in sorted(down_set):
                state = self._state_for(service_name)
                state["escalated"] = 1
            events.append(
                {
                    "ts": ts,
                    "decision": "kill_switch",
                    "action": None,
                    "status": "escalated",
                    "detail_json": {
                        **kill_switch_detail,
                        "reason": "kill_switch_engaged",
                        "cycle": int(self._cycle),
                        "down_services": sorted(down_services),
                    },
                }
            )
            return events

        for service_name in sorted(down_set):
            state = self._state_for(service_name)
            down_streak = int(state["down_streak"])
            check_attempts = int(state["check_attempts"])
            recover_attempts = int(state["recover_attempts"])
            rollback_attempts = int(state["rollback_attempts"])
            cooldown_until = int(state["cooldown_until"])
            escalated = int(state["escalated"]) == 1
            ladder = self._ladder_for(service_name)
            check_threshold = int(ladder["check_threshold"])
            recover_threshold = int(ladder["recover_threshold"])
            max_recover_attempts = int(ladder["max_recover_attempts"])
            max_rollbacks = int(self.rollback_max_attempts or 1)

            if escalated:
                continue

            if self._cycle < cooldown_until:
                events.append(
                    {
                        "ts": ts,
                        "decision": "cooldown_wait",
                        "action": None,
                        "status": "cooldown",
                        "detail_json": {
                            "service": service_name,
                            "cycle": int(self._cycle),
                            "cooldown_until": cooldown_until,
                            "check_threshold": check_threshold,
                            "recover_threshold": recover_threshold,
                            "max_recover_attempts": max_recover_attempts,
                            "rollback_attempts": rollback_attempts,
                            "rollback_max_attempts": max_rollbacks,
                        },
                    }
                )
                continue

            if down_streak >= check_threshold and check_attempts == 0:
                status, command, detail, policy_trace, failure_class = self._run_allowlisted("status_check")
                state["check_attempts"] = check_attempts + 1
                if status.startswith("executed_"):
                    state["cooldown_until"] = int(self._cycle + self.action_cooldown_cycles)
                events.append(
                    {
                        "ts": ts,
                        "decision": "threshold_check",
                        "action": "status_check",
                        "status": status,
                        "detail_json": {
                            "service": service_name,
                            "cycle": int(self._cycle),
                            "down_streak": down_streak,
                            "check_attempts": int(state["check_attempts"]),
                            "check_threshold": check_threshold,
                            "recover_threshold": recover_threshold,
                            "max_recover_attempts": max_recover_attempts,
                            "rollback_attempts": rollback_attempts,
                            "rollback_max_attempts": max_rollbacks,
                            "command": command,
                            "detail": detail,
                            "policy_trace": policy_trace,
                            "failure_class": failure_class,
                            "handoff": orchestrate_role_handoff(
                                planner_intent="threshold_check",
                                action="status_check",
                                verifier_step="status_check",
                                ts=ts,
                            ),
                        },
                    }
                )
                continue

            if down_streak >= recover_threshold and recover_attempts < max_recover_attempts:
                recover_action = (
                    f"restart_service:{service_name}"
                    if recover_attempts == 0
                    else "compose_up_core"
                )
                status, command, detail, policy_trace, failure_class = self._run_allowlisted(recover_action)
                state["recover_attempts"] = recover_attempts + 1
                if status.startswith("executed_"):
                    state["cooldown_until"] = int(self._cycle + self.action_cooldown_cycles)
                events.append(
                    {
                        "ts": ts,
                        "decision": "threshold_recover",
                        "action": recover_action,
                        "status": status,
                        "detail_json": {
                            "service": service_name,
                            "cycle": int(self._cycle),
                            "down_streak": down_streak,
                            "recover_attempts": int(state["recover_attempts"]),
                            "check_threshold": check_threshold,
                            "recover_threshold": recover_threshold,
                            "max_recover_attempts": max_recover_attempts,
                            "rollback_attempts": rollback_attempts,
                            "rollback_max_attempts": max_rollbacks,
                            "command": command,
                            "detail": detail,
                            "policy_trace": policy_trace,
                            "failure_class": failure_class,
                            "handoff": orchestrate_role_handoff(
                                planner_intent="threshold_recover",
                                action=recover_action,
                                verifier_step="status_check",
                                ts=ts,
                            ),
                        },
                    }
                )
                if status in {"executed_fail", "missing_script", "rejected"}:
                    rollback_events = self._run_rollback_sequence(
                        ts=ts,
                        service_name=service_name,
                        trigger_action=recover_action,
                        trigger_status=status,
                    )
                    events.extend(rollback_events)
                continue

            if down_streak >= recover_threshold and recover_attempts >= max_recover_attempts:
                state["escalated"] = 1
                events.append(
                    {
                        "ts": ts,
                        "decision": "escalate",
                        "action": None,
                        "status": "escalated",
                        "detail_json": {
                            "service": service_name,
                            "cycle": int(self._cycle),
                            "down_streak": down_streak,
                            "recover_attempts": recover_attempts,
                            "check_threshold": check_threshold,
                            "recover_threshold": recover_threshold,
                            "max_recover_attempts": max_recover_attempts,
                            "rollback_attempts": rollback_attempts,
                            "rollback_max_attempts": max_rollbacks,
                            "reason": "max_recover_attempts_reached",
                        },
                    }
                )

        return events
