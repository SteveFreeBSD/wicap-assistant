from __future__ import annotations

from pathlib import Path

from wicap_assist.cli import _normalize_control_mode, main


def test_normalize_control_mode_accepts_monitor_alias() -> None:
    assert _normalize_control_mode("monitor") == "observe"
    assert _normalize_control_mode(" observe ") == "observe"
    assert _normalize_control_mode("assist") == "assist"
    assert _normalize_control_mode("autonomous") == "autonomous"


def test_live_command_maps_monitor_to_observe(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, str] = {}

    def fake_live_monitor(conn, **kwargs):  # type: ignore[no-untyped-def]
        seen["mode"] = str(kwargs.get("control_mode"))
        return 0

    monkeypatch.setattr("wicap_assist.cli.run_live_monitor", fake_live_monitor)
    rc = main(
        [
            "--db",
            str(tmp_path / "assistant.db"),
            "live",
            "--once",
            "--control-mode",
            "monitor",
        ]
    )
    assert rc == 0
    assert seen["mode"] == "observe"


def test_agent_command_maps_monitor_to_observe(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, str] = {}

    def fake_run_agent_console(conn, **kwargs):  # type: ignore[no-untyped-def]
        seen["mode"] = str(kwargs.get("default_control_mode"))
        return 0

    monkeypatch.setattr("wicap_assist.cli.run_agent_console", fake_run_agent_console)
    rc = main(
        [
            "--db",
            str(tmp_path / "assistant.db"),
            "agent",
            "--control-mode",
            "monitor",
        ]
    )
    assert rc == 0
    assert seen["mode"] == "observe"
