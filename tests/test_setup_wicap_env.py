from __future__ import annotations

import re
from pathlib import Path

import wicap_assist.wicap_env_setup as setup_mod
from wicap_assist.wicap_env_setup import load_env_entries, run_wicap_env_setup, validate_wicap_env


def _iter_input(values: list[str], default: str = ""):
    iterator = iter(values)

    def _reader(prompt: str = "") -> str:
        _ = prompt
        return next(iterator, default)

    return _reader


def _create_repo_root(
    tmp_path: Path,
    *,
    ui_block: str | None = None,
) -> Path:
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / ".env.example").write_text(
        "\n".join(
            [
                "# WiCAP example",
                "WICAP_SQL_PASSWORD=your_sql_password_here",
                "",
            ]
        ),
        encoding="utf-8",
    )
    compose_ui_block = ui_block or "\n".join(
        [
            "  ui:",
            "    image: wicap-ui:latest",
            "    network_mode: \"host\"",
            "    env_file: .env",
        ]
    )
    compose_text = "\n".join(
        [
            "services:",
            "  redis:",
            "    image: redis:alpine",
            "  scout:",
            "    image: wicap-core:latest",
            compose_ui_block,
            "",
        ]
    )
    (repo_root / "docker-compose.yml").write_text(compose_text, encoding="utf-8")
    return repo_root


def _parse_assigned_keys(text: str) -> list[str]:
    keys: list[str] = []
    pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE)
    for match in pattern.finditer(text):
        keys.append(match.group(1))
    return keys


def test_setup_wicap_env_writes_deterministic_env_with_no_duplicate_keys(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "wlo1")
    monkeypatch.setattr(setup_mod, "_discover_wireless_interfaces", lambda: ["wlo1", "wlx001"])
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "192.168.50.10")
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [])

    report = run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        input_fn=_iter_input([]),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )
    assert report["ui_bind_strategy"] == "host_network"

    env_text = (repo_root / ".env").read_text(encoding="utf-8")
    keys = _parse_assigned_keys(env_text)
    assert len(keys) == len(set(keys))

    entries = load_env_entries(repo_root / ".env")
    assert entries["WICAP_UI_URL"] == "http://127.0.0.1:8080"
    assert entries["WICAP_INTERFACE"] == "wlx001"
    assert "wlo1" in entries["WICAP_INTERFACE_EXCLUDE_REGEX"]
    assert "WICAP_SQL_DRIVER=ODBC Driver 18 for SQL Server" in env_text
    assert entries["WICAP_SQL_SERVER"] == entries["WICAP_SQL_HOST"]
    assert entries["WICAP_SQL_USERNAME"] == entries["WICAP_SQL_USER"]


def test_setup_wicap_env_bt_enabled_writes_bt_interface_keys_from_candidates(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    candidate = "/dev/serial/by-id/usb-ZEPHYR_nRF_Sniffer_for_Bluetooth_LE_ABCDEF123456-if00"
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "wlo1")
    monkeypatch.setattr(setup_mod, "_discover_wireless_interfaces", lambda: ["wlo1", "wlx001"])
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "10.20.30.40")
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [candidate])

    # Set BT enabled and keep defaults for the rest.
    run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        input_fn=_iter_input(
            [
                "",  # SQL host
                "",  # SQL db
                "",  # SQL user
                "",  # SQL driver
                "",  # trust cert
                "",  # secret required
                "",  # allowlist
                "",  # redis
                "",  # sql check -> no
                "",  # ui url
                "",  # captures dir
                "",  # ui capture dir
                "",  # ui pool
                "",  # replay dir
                "",  # evidence dir
                "",  # iface mode
                "",  # interface
                "",  # interface mac
                "",  # interface regex
                "",  # interface exclude regex
                "",  # bands
                "",  # capture backend
                "true",  # bt enabled
                "",  # bt interface
                "",  # bt glob
                "",  # bt serial
                "",  # bt capture dir
                "",  # bt extcap dir
                "",  # optional tuning -> no
                "",  # otlp profile
                "",  # create dirs -> yes
            ]
        ),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )

    entries = load_env_entries(repo_root / ".env")
    assert entries["WICAP_BT_ENABLED"] == "true"
    assert entries["WICAP_BT_INTERFACE"] == candidate
    assert entries["WICAP_BT_INTERFACE_GLOB"] == "/dev/serial/by-id/*nRF*"
    assert entries["WICAP_BT_SERIAL"] == "ABCDEF123456"


def test_setup_wicap_env_excludes_management_interface_by_default_from_ip_outputs(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)

    def fake_run_command(args):
        if list(args) == ["ip", "-br", "link"]:
            return "lo               UNKNOWN\nwlo1             UP\nwlxabc123        UP"
        if list(args) == ["ip", "route"]:
            return "default via 192.168.0.1 dev wlo1 proto dhcp src 192.168.0.42 metric 600"
        if list(args) == ["ip", "-4", "addr", "show", "dev", "wlo1"]:
            return "2: wlo1\n    inet 192.168.0.42/24 brd 192.168.0.255 scope global dynamic wlo1"
        if list(args) == ["ip", "-4", "route", "get", "1.1.1.1"]:
            return "1.1.1.1 via 192.168.0.1 dev wlo1 src 192.168.0.42 uid 1000"
        return ""

    monkeypatch.setattr(setup_mod, "_run_command", fake_run_command)
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [])

    run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        input_fn=_iter_input([]),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )

    entries = load_env_entries(repo_root / ".env")
    assert entries["WICAP_INTERFACE"] == "wlxabc123"
    assert "wlo1" in entries["WICAP_INTERFACE_EXCLUDE_REGEX"]


def test_setup_wicap_env_host_network_ui_strategy_requires_no_override_file(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "eth0")
    monkeypatch.setattr(setup_mod, "_discover_wireless_interfaces", lambda: ["wlx001"])
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "172.16.1.10")
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [])

    report = run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        input_fn=_iter_input([]),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )

    assert report["ui_bind_strategy"] == "host_network"
    assert report["compose_override_path"] is None
    assert not (repo_root / "compose.override.yml").exists()


def test_setup_wicap_env_can_write_ui_override_when_compose_has_no_host_mode_or_ports(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(
        tmp_path,
        ui_block="\n".join(
            [
                "  ui:",
                "    image: wicap-ui:latest",
                "    env_file: .env",
            ]
        ),
    )
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "eth0")
    monkeypatch.setattr(setup_mod, "_discover_wireless_interfaces", lambda: ["wlx001"])
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "192.168.77.20")
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [])

    # The compose override prompt appears after the headless UI fields above.
    report = run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        input_fn=_iter_input(
            [
                "",  # sql host
                "",  # sql db
                "",  # sql user
                "",  # sql driver
                "",  # trust cert
                "",  # internal secret required
                "",  # allowlist
                "",  # redis
                "",  # sql check
                "",  # ui url
                "",  # captures dir
                "",  # ui capture dir
                "",  # ui db pool
                "",  # replay dir
                "",  # evidence dir
                "y",  # write compose.override.yml
            ]
        ),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )

    override_path = repo_root / "compose.override.yml"
    assert report["ui_bind_strategy"] == "override_required"
    assert report["compose_override_path"] == str(override_path)
    assert override_path.exists()
    assert "0.0.0.0:8080:8080" in override_path.read_text(encoding="utf-8")


def test_setup_wicap_env_dry_run_does_not_write_file(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "wlo1")
    monkeypatch.setattr(setup_mod, "_discover_wireless_interfaces", lambda: ["wlo1", "wlx001"])
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "192.168.10.10")
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [])

    report = run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        dry_run=True,
        input_fn=_iter_input([]),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )

    assert report["dry_run"] is True
    assert not (repo_root / ".env").exists()


def test_setup_wicap_env_normalizes_allowlist_and_keeps_loopback(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "wlo1")
    monkeypatch.setattr(setup_mod, "_discover_wireless_interfaces", lambda: ["wlo1", "wlx001"])
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "192.168.0.50")
    monkeypatch.setattr(setup_mod, "_list_bt_serial_candidates", lambda: [])

    run_wicap_env_setup(
        repo_root=repo_root,
        assume_yes=True,
        input_fn=_iter_input(
            [
                "",  # sql host
                "",  # sql db
                "",  # sql user
                "",  # sql driver
                "",  # trust cert
                "",  # secret required
                "192.168.0.0/24, 192.168.0.0/24",  # allowlist
            ]
        ),
        secret_input_fn=_iter_input(["supersecure-pass-123", "internal-secret-123"]),
        print_fn=lambda _: None,
    )

    entries = load_env_entries(repo_root / ".env")
    assert entries["WICAP_INTERNAL_ALLOWLIST"] == "192.168.0.0/24,127.0.0.1,::1"


def test_validate_wicap_env_flags_management_interface_capture_conflict(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    env_path = repo_root / ".env"
    env_path.write_text(
        "\n".join(
            [
                "WICAP_SQL_HOST=192.168.0.10,1433",
                "WICAP_SQL_DATABASE=WifiInsanityDB",
                "WICAP_SQL_USER=steve_linux",
                "WICAP_SQL_PASSWORD=supersecure-pass-123",
                "WICAP_INTERNAL_SECRET=internal-secret-123",
                "WICAP_REDIS_URL=redis://localhost:6380/0",
                "WICAP_UI_URL=http://127.0.0.1:8080",
                "WICAP_INTERFACE=wlo1",
                "WICAP_INTERNAL_ALLOWLIST=127.0.0.1,::1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "wlo1")
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "192.168.0.42")

    report = validate_wicap_env(repo_root=repo_root, probe_live=False)

    assert report["ok"] is False
    errors = report["errors"]
    assert isinstance(errors, list)
    assert any("matches management interface" in item for item in errors)


def test_validate_wicap_env_detects_internal_emit_auth_failure(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    env_path = repo_root / ".env"
    env_path.write_text(
        "\n".join(
            [
                "WICAP_SQL_HOST=192.168.0.10,1433",
                "WICAP_SQL_DATABASE=WifiInsanityDB",
                "WICAP_SQL_USER=steve_linux",
                "WICAP_SQL_PASSWORD=supersecure-pass-123",
                "WICAP_INTERNAL_SECRET=internal-secret-123",
                "WICAP_REDIS_URL=redis://localhost:6380/0",
                "WICAP_UI_URL=http://127.0.0.1:8080",
                "WICAP_INTERFACE=wlx001",
                "WICAP_INTERNAL_ALLOWLIST=127.0.0.1,::1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(setup_mod, "_detect_management_interface", lambda: "wlo1")
    monkeypatch.setattr(setup_mod, "_detect_lan_ipv4", lambda interface: "192.168.0.42")
    monkeypatch.setattr(setup_mod, "_probe_tcp_reachability", lambda host, port: (True, "ok"))
    monkeypatch.setattr(setup_mod, "_probe_internal_emit", lambda ui_url, secret: (False, "HTTP 403"))

    report = validate_wicap_env(repo_root=repo_root, probe_live=True, require_live=True)

    assert report["ok"] is False
    errors = report["errors"]
    assert isinstance(errors, list)
    assert any("Internal emit probe failed" in item for item in errors)
