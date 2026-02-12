from __future__ import annotations

from pathlib import Path

from wicap_assist.actuators import ActuatorResult
from wicap_assist.agent_console import parse_agent_prompt, run_agent_console
from wicap_assist.db import connect_db, insert_control_session


def test_parse_agent_prompt_soak_assist_dry_run() -> None:
    intent = parse_agent_prompt("start soak for 12 minutes assist dry-run interval 3 minutes")
    assert intent.kind == "soak"
    assert int(intent.duration_minutes or 0) == 12
    assert int(intent.playwright_interval_minutes or 0) == 3
    assert intent.control_mode == "assist"
    assert intent.dry_run is True


def test_parse_agent_prompt_soak_autonomous() -> None:
    intent = parse_agent_prompt("run soak for 30 minutes autonomous")
    assert intent.kind == "soak"
    assert int(intent.duration_minutes or 0) == 30
    assert intent.control_mode == "autonomous"


def test_parse_agent_prompt_supports_mode_action_and_stats() -> None:
    assert parse_agent_prompt("stats").kind == "stats"

    mode_intent = parse_agent_prompt("mode assist")
    assert mode_intent.kind == "set_mode"
    assert mode_intent.control_mode == "assist"

    action_intent = parse_agent_prompt("action restart_service:wicap-ui")
    assert action_intent.kind == "action"
    assert action_intent.action == "restart_service:wicap-ui"

    restart_intent = parse_agent_prompt("restart wicap-processor")
    assert restart_intent.kind == "action"
    assert restart_intent.action == "restart_service:wicap-processor"


def test_run_agent_console_routes_core_intents(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    outputs: list[str] = []
    prompts = iter(
        [
            "help",
            "status",
            "recommend logs_soak_123",
            "incident logs_soak_123",
            "start soak for 5 minutes assist dry-run",
            "quit",
        ]
    )

    soak_calls: list[tuple[int | None, str, bool]] = []
    recommend_calls: list[str] = []
    incident_calls: list[str] = []

    def input_fn(_prompt: str) -> str:
        return next(prompts)

    def output_fn(line: str) -> None:
        outputs.append(str(line))

    def fake_live_once(_conn) -> str:  # type: ignore[no-untyped-def]
        return "LIVE_OK"

    def fake_soak_run(_conn, *, intent):  # type: ignore[no-untyped-def]
        soak_calls.append((intent.duration_minutes, intent.control_mode, intent.dry_run))
        return {
            "run_id": None,
            "exit_code": None,
            "control_mode": intent.control_mode,
            "newest_soak_dir": "/home/steve/apps/wicap/logs_soak_123",
            "incident_path": None,
            "observation_cycles": 0,
            "alert_cycles": 0,
            "down_service_cycles": 0,
            "control_actions_executed": 0,
            "operator_guidance": ["Dry-run only guidance."],
        }

    def fake_recommend(_conn, target: str):  # type: ignore[no-untyped-def]
        recommend_calls.append(target)
        return {
            "recommended_action": "Apply known fix",
            "confidence": 0.5,
            "verification_priority": ["python scripts/check_wicap_status.py --local-only"],
        }

    def fake_incident(_conn, target: str) -> str:  # type: ignore[no-untyped-def]
        incident_calls.append(target)
        return "/tmp/incident.md"

    rc = run_agent_console(
        conn,
        input_fn=input_fn,
        output_fn=output_fn,
        default_control_mode="observe",
        default_observe_interval_seconds=1.0,
        live_once_fn=fake_live_once,
        soak_run_fn=fake_soak_run,
        recommend_fn=fake_recommend,
        incident_fn=fake_incident,
    )

    assert rc == 0
    assert recommend_calls == ["logs_soak_123"]
    assert incident_calls == ["logs_soak_123"]
    assert soak_calls == [(5, "assist", True)]
    assert any("LIVE_OK" in line for line in outputs)
    assert any("recommend: action=Apply known fix" in line for line in outputs)
    assert any("incident: path=/tmp/incident.md" in line for line in outputs)
    assert any("guide: Dry-run only guidance." in line for line in outputs)
    assert any("agent: exit" in line for line in outputs)

    conn.close()


def test_run_agent_console_recommend_uses_working_memory_target(tmp_path: Path) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    outputs: list[str] = []
    prompts = iter(["recommend", "quit"])
    recommend_calls: list[str] = []

    insert_control_session(
        conn,
        soak_run_id=None,
        started_ts="2026-02-12T00:00:00+00:00",
        last_heartbeat_ts="2026-02-12T00:00:01+00:00",
        mode="assist",
        status="running",
        current_phase="live_cycle",
        handoff_state="active",
        metadata_json={
            "working_memory": {
                "unresolved_signatures": ["error: redis timeout on reconnect"],
                "pending_actions": ["restart_service:wicap-redis"],
                "recent_transitions": [],
                "down_services": ["wicap-redis"],
                "last_observation_ts": "2026-02-12T00:00:01+00:00",
            }
        },
    )
    conn.commit()

    def input_fn(_prompt: str) -> str:
        return next(prompts)

    def output_fn(line: str) -> None:
        outputs.append(str(line))

    def fake_recommend(_conn, target: str):  # type: ignore[no-untyped-def]
        recommend_calls.append(target)
        return {
            "recommended_action": "Apply known fix",
            "confidence": 0.8,
            "verification_priority": ["python scripts/check_wicap_status.py --local-only"],
        }

    rc = run_agent_console(
        conn,
        input_fn=input_fn,
        output_fn=output_fn,
        recommend_fn=fake_recommend,
    )
    assert rc == 0
    assert recommend_calls == ["error: redis timeout on reconnect"]
    assert any("recommend: confidence=0.8" in line for line in outputs)
    conn.close()


def test_run_agent_console_mode_action_and_stats(tmp_path: Path, monkeypatch) -> None:
    conn = connect_db(tmp_path / "assistant.db")
    outputs: list[str] = []
    prompts = iter(["mode assist", "action status_check", "stats", "quit"])

    def input_fn(_prompt: str) -> str:
        return next(prompts)

    def output_fn(line: str) -> None:
        outputs.append(str(line))

    def fake_live_once(_conn):  # type: ignore[no-untyped-def]
        return "LIVE_OK"

    def fake_run_allowlisted_action(**kwargs):  # type: ignore[no-untyped-def]
        _ = kwargs
        return ActuatorResult(
            status="executed_ok",
            commands=[["python", "scripts/check_wicap_status.py", "--local-only", "--json"]],
            detail="ok",
        )

    def fake_collect_live_cycle(_conn):  # type: ignore[no-untyped-def]
        return {
            "ts": "2026-02-12T00:00:00+00:00",
            "service_status": {
                "docker": {
                    "services": {
                        "wicap-ui": {"state": "up", "status": "Up 1m"},
                        "wicap-processor": {"state": "up", "status": "Up 1m"},
                        "wicap-scout": {"state": "down", "status": "Exited (1)"},
                        "wicap-redis": {"state": "up", "status": "Up 1m"},
                    }
                }
            },
            "top_signatures": [
                {"category": "error", "signature": "ui push failed", "count": 3},
            ],
            "recommended": [
                {
                    "signature": "ui push failed",
                    "recommendation": {
                        "recommended_action": "Set WICAP_UI_URL",
                        "confidence": 0.8,
                    },
                    "safe_verify_steps": ["grep -E 'WICAP_UI_URL' .env"],
                }
            ],
            "alert": "services_down=wicap-scout",
            "operator_guidance": ["Run status check"],
        }

    monkeypatch.setattr("wicap_assist.agent_console.run_allowlisted_action", fake_run_allowlisted_action)
    monkeypatch.setattr("wicap_assist.agent_console.collect_live_cycle", fake_collect_live_cycle)

    rc = run_agent_console(
        conn,
        input_fn=input_fn,
        output_fn=output_fn,
        live_once_fn=fake_live_once,
    )
    assert rc == 0
    assert any("agent: mode set to assist" in line for line in outputs)
    assert any("action: mode=assist requested=status_check status=executed_ok" in line for line in outputs)
    assert any("command_center: mode=assist" in line for line in outputs)
    assert any("working_memory:" in line for line in outputs)
    conn.close()
