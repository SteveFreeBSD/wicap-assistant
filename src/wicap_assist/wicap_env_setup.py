"""Interactive WiCAP .env bootstrap helpers."""

from __future__ import annotations

import getpass
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Sequence

_ENV_ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")
_BOOL_TRUE = {"1", "true", "yes", "y", "on"}
_BOOL_FALSE = {"0", "false", "no", "n", "off"}
_OTLP_PROFILES = {"disabled", "self_hosted", "vendor", "cloud"}
_UI_STRATEGY_HOST_NETWORK = "host_network"
_UI_STRATEGY_PUBLISHED_PORTS = "published_ports"
_UI_STRATEGY_OVERRIDE_REQUIRED = "override_required"
_UI_STRATEGY_UNKNOWN = "unknown"
_DEFAULT_BT_INTERFACE_GLOB = "/dev/serial/by-id/*nRF*"
_DEFAULT_DOCKER_COMPOSE_FILE = "docker-compose.yml"

InputFn = Callable[[str], str]
SecretInputFn = Callable[[str], str]
PrintFn = Callable[[str], object]


@dataclass(frozen=True)
class PromptField:
    key: str
    prompt: str
    default: str | None = None
    required: bool = False
    secret: bool = False
    min_length: int = 0
    normalizer: Callable[[str], str] | None = None


@dataclass(frozen=True)
class EnvSection:
    name: str
    description: str
    keys: tuple[str, ...]


@dataclass(frozen=True)
class ComposeUiPlan:
    strategy: str
    has_ui_service: bool
    default_port: int


class SetupAbortedError(RuntimeError):
    """Raised when user aborts setup."""


# Authoritative inventory used by the wizard and documentation.
# Keys can appear in multiple categories for governance clarity.
ENV_COVERAGE: dict[str, tuple[str, ...]] = {
    "A_required_to_boot": (
        "WICAP_SQL_HOST",
        "WICAP_SQL_SERVER",
        "WICAP_SQL_DATABASE",
        "WICAP_SQL_USER",
        "WICAP_SQL_USERNAME",
        "WICAP_SQL_PASSWORD",
        "WICAP_SQL_DRIVER",
        "WICAP_SQL_TRUST_CERT",
        "WICAP_INTERNAL_SECRET",
        "WICAP_INTERNAL_SECRET_REQUIRED",
        "WICAP_INTERNAL_ALLOWLIST",
        "WICAP_REDIS_URL",
    ),
    "B_required_for_headless_lan_ui": (
        "WICAP_UI_URL",
        "WICAP_CAPTURE_DIR",
        "WICAP_CAPTURES_DIR",
        "WICAP_UI_DB_POOL_SIZE",
    ),
    "C_required_for_wifi_capture": (
        "WICAP_INTERFACE",
        "WICAP_INTERFACE_MAC",
        "WICAP_INTERFACE_REGEX",
        "WICAP_INTERFACE_EXCLUDE_REGEX",
        "WICAP_BANDS",
        "WICAP_CAPTURE_BACKEND",
    ),
    "D_required_for_bluetooth_capture": (
        "WICAP_BT_ENABLED",
        "WICAP_BT_INTERFACE",
        "WICAP_BT_INTERFACE_GLOB",
        "WICAP_BT_SERIAL",
        "WICAP_BT_CAPTURE_DIR",
        "WICAP_BT_EXTCAP_DIR",
    ),
    "E_recommended_safety_rails": (
        "WICAP_INTERNAL_SECRET_REQUIRED",
        "WICAP_INTERNAL_ALLOWLIST",
        "WICAP_INTERFACE_EXCLUDE_REGEX",
        "WICAP_UI_URL",
    ),
    "F_optional_tuning_knobs": (
        "WICAP_DWELL_THRESHOLD",
        "WICAP_DWELL_DURATION",
        "WICAP_QUEUE_MAX_BYTES",
        "WICAP_QUEUE_MAX_FILES",
        "WICAP_QUEUE_BACKPRESSURE_MAX_BYTES",
        "WICAP_QUEUE_BACKPRESSURE_ACTION",
        "WICAP_DEDUP_MAX_ENTRIES",
        "WICAP_REPLAY_LOG_DIR",
        "WICAP_EVIDENCE_BUNDLE_DIR",
        "WICAP_OTLP_PROFILE",
        "WICAP_OTLP_HTTP_ENDPOINT",
        "WICAP_OTLP_HEADERS",
        "WICAP_OTLP_AUTH_BEARER",
        "WICAP_OTLP_API_KEY",
        "WICAP_OTLP_TIMEOUT_SECONDS",
        "WICAP_OTLP_MAX_QUEUE",
        "WICAP_OTLP_MAX_BATCH",
        "WICAP_OTLP_RETRY_BACKOFF_SECONDS",
        "WICAP_OTLP_MAX_BACKOFF_SECONDS",
    ),
}

ENV_DEFAULTS: dict[str, str] = {
    "WICAP_SQL_HOST": "192.168.4.25",
    "WICAP_SQL_DATABASE": "WifiInsanityDB",
    "WICAP_SQL_USER": "steve_linux",
    "WICAP_SQL_DRIVER": "ODBC Driver 18 for SQL Server",
    "WICAP_SQL_TRUST_CERT": "yes",
    "WICAP_INTERNAL_SECRET_REQUIRED": "true",
    "WICAP_INTERNAL_ALLOWLIST": "127.0.0.1,::1",
    "WICAP_REDIS_URL": "redis://localhost:6380/0",
    "WICAP_INTERFACE": "auto",
    "WICAP_INTERFACE_MAC": "",
    "WICAP_INTERFACE_REGEX": "",
    "WICAP_INTERFACE_EXCLUDE_REGEX": "^wlo[0-9]+$",
    "WICAP_BANDS": "2.4ghz",
    "WICAP_CAPTURE_BACKEND": "auto",
    "WICAP_BT_ENABLED": "false",
    "WICAP_BT_INTERFACE": "auto",
    "WICAP_BT_INTERFACE_GLOB": _DEFAULT_BT_INTERFACE_GLOB,
    "WICAP_BT_SERIAL": "",
    "WICAP_BT_CAPTURE_DIR": "./captures/bt",
    "WICAP_BT_EXTCAP_DIR": "tools/bluetooth/extcap",
    "WICAP_CAPTURES_DIR": "./captures",
    "WICAP_CAPTURE_DIR": "./captures",
    "WICAP_UI_DB_POOL_SIZE": "5",
    "WICAP_REPLAY_LOG_DIR": "/tmp",
    "WICAP_EVIDENCE_BUNDLE_DIR": "captures/evidence/bundles",
    "WICAP_DWELL_THRESHOLD": "1",
    "WICAP_DWELL_DURATION": "30",
    "WICAP_QUEUE_MAX_BYTES": "52428800",
    "WICAP_QUEUE_MAX_FILES": "5",
    "WICAP_QUEUE_BACKPRESSURE_MAX_BYTES": "262144000",
    "WICAP_QUEUE_BACKPRESSURE_ACTION": "drop_pulse",
    "WICAP_DEDUP_MAX_ENTRIES": "10000",
    "WICAP_OTLP_PROFILE": "disabled",
    "WICAP_OTLP_HTTP_ENDPOINT": "",
    "WICAP_OTLP_HEADERS": "",
    "WICAP_OTLP_AUTH_BEARER": "",
    "WICAP_OTLP_API_KEY": "",
    "WICAP_OTLP_TIMEOUT_SECONDS": "1.5",
    "WICAP_OTLP_MAX_QUEUE": "2000",
    "WICAP_OTLP_MAX_BATCH": "200",
    "WICAP_OTLP_RETRY_BACKOFF_SECONDS": "1.0",
    "WICAP_OTLP_MAX_BACKOFF_SECONDS": "30.0",
}

ENV_SECTIONS: tuple[EnvSection, ...] = (
    EnvSection(
        "Required Boot (A)",
        "Required values to start WiCAP core/UI cleanly.",
        (
            "WICAP_SQL_HOST",
            "WICAP_SQL_SERVER",
            "WICAP_SQL_DATABASE",
            "WICAP_SQL_USER",
            "WICAP_SQL_USERNAME",
            "WICAP_SQL_PASSWORD",
            "WICAP_SQL_DRIVER",
            "WICAP_SQL_TRUST_CERT",
            "WICAP_INTERNAL_SECRET",
            "WICAP_INTERNAL_SECRET_REQUIRED",
            "WICAP_INTERNAL_ALLOWLIST",
            "WICAP_REDIS_URL",
        ),
    ),
    EnvSection(
        "Headless LAN UI (B)",
        "LAN reachability and capture directory mapping for headless hosts.",
        (
            "WICAP_UI_URL",
            "WICAP_CAPTURES_DIR",
            "WICAP_CAPTURE_DIR",
            "WICAP_UI_DB_POOL_SIZE",
            "WICAP_REPLAY_LOG_DIR",
            "WICAP_EVIDENCE_BUNDLE_DIR",
        ),
    ),
    EnvSection(
        "Wi-Fi Capture (C)",
        "Headless-safe Wi-Fi capture interface and selection rails.",
        (
            "WICAP_INTERFACE",
            "WICAP_INTERFACE_MAC",
            "WICAP_INTERFACE_REGEX",
            "WICAP_INTERFACE_EXCLUDE_REGEX",
            "WICAP_BANDS",
            "WICAP_CAPTURE_BACKEND",
        ),
    ),
    EnvSection(
        "Bluetooth Sniffer (D)",
        "BLE sniffer wiring with by-id interface and fallback selectors.",
        (
            "WICAP_BT_ENABLED",
            "WICAP_BT_INTERFACE",
            "WICAP_BT_INTERFACE_GLOB",
            "WICAP_BT_SERIAL",
            "WICAP_BT_CAPTURE_DIR",
            "WICAP_BT_EXTCAP_DIR",
        ),
    ),
    EnvSection(
        "Optional Tuning + OTLP (F)",
        "Operational tuning knobs and OTLP export settings.",
        (
            "WICAP_DWELL_THRESHOLD",
            "WICAP_DWELL_DURATION",
            "WICAP_QUEUE_MAX_BYTES",
            "WICAP_QUEUE_MAX_FILES",
            "WICAP_QUEUE_BACKPRESSURE_MAX_BYTES",
            "WICAP_QUEUE_BACKPRESSURE_ACTION",
            "WICAP_DEDUP_MAX_ENTRIES",
            "WICAP_OTLP_PROFILE",
            "WICAP_OTLP_HTTP_ENDPOINT",
            "WICAP_OTLP_HEADERS",
            "WICAP_OTLP_AUTH_BEARER",
            "WICAP_OTLP_API_KEY",
            "WICAP_OTLP_TIMEOUT_SECONDS",
            "WICAP_OTLP_MAX_QUEUE",
            "WICAP_OTLP_MAX_BATCH",
            "WICAP_OTLP_RETRY_BACKOFF_SECONDS",
            "WICAP_OTLP_MAX_BACKOFF_SECONDS",
        ),
    ),
)

_KEY_NOTES: dict[str, str] = {
    "WICAP_SQL_SERVER": "Alias for compatibility with components expecting WICAP_SQL_SERVER.",
    "WICAP_SQL_USERNAME": "Alias for compatibility with components expecting WICAP_SQL_USERNAME.",
}


def _normalize_bool(value: str) -> str:
    token = str(value or "").strip().lower()
    if token in _BOOL_TRUE:
        return "true"
    if token in _BOOL_FALSE:
        return "false"
    raise ValueError("Expected one of: true/false, yes/no, 1/0")


def _normalize_otlp_profile(value: str) -> str:
    token = str(value or "").strip().lower()
    if token in _OTLP_PROFILES:
        return token
    raise ValueError("Expected OTLP profile: disabled, self_hosted, vendor, or cloud")


def _normalize_interface_mode(value: str) -> str:
    token = str(value or "").strip().lower()
    if token in {"explicit", "pinned", "pin", "fixed"}:
        return "explicit"
    if token in {"auto", "automatic"}:
        return "auto"
    raise ValueError("Expected Wi-Fi capture mode: explicit or auto")


def _parse_env_value(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value[0] == value[-1] and value[0] in {"'", "\""} and len(value) >= 2:
        inner = value[1:-1]
        if value[0] == "\"":
            return inner.replace("\\\"", "\"").replace("\\\\", "\\")
        return inner
    comment_index = value.find(" #")
    if comment_index >= 0:
        value = value[:comment_index].rstrip()
    return value


def load_env_entries(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _ENV_ASSIGNMENT_RE.match(line)
        if not match:
            continue
        entries[match.group(1)] = _parse_env_value(match.group(2))
    return entries


def _resolved_default(existing: dict[str, str], field: PromptField) -> str:
    value = existing.get(field.key)
    if value is not None and str(value).strip() != "":
        return str(value)
    if field.default is None:
        return ""
    return str(field.default)


def _prompt_value(
    field: PromptField,
    *,
    existing: dict[str, str],
    input_fn: InputFn | None = None,
    secret_input_fn: SecretInputFn | None = None,
    print_fn: PrintFn | None = None,
) -> str:
    if input_fn is None:
        input_fn = input
    if secret_input_fn is None:
        secret_input_fn = getpass.getpass
    if print_fn is None:
        print_fn = print

    while True:
        default_value = _resolved_default(existing, field)
        shown_default = "<set>" if field.secret and default_value else default_value
        prompt = field.prompt
        if shown_default:
            prompt += f" [{shown_default}]"
        prompt += ": "

        raw = secret_input_fn(prompt) if field.secret else input_fn(prompt)
        candidate = str(raw or "").strip()
        if not candidate:
            candidate = default_value

        if not candidate and field.required:
            print_fn(f"{field.key} is required.")
            continue

        if candidate and field.normalizer is not None:
            try:
                candidate = field.normalizer(candidate)
            except ValueError as exc:
                print_fn(str(exc))
                continue

        if candidate and field.min_length > 0 and len(candidate) < field.min_length:
            print_fn(f"{field.key} must be at least {field.min_length} characters.")
            continue

        return candidate


def _prompt_confirm(
    message: str,
    *,
    default: bool = True,
    input_fn: InputFn | None = None,
) -> bool:
    if input_fn is None:
        input_fn = input

    suffix = "[Y/n]" if default else "[y/N]"
    accepted_yes = {"y", "yes"}
    accepted_no = {"n", "no"}
    while True:
        raw = input_fn(f"{message} {suffix}: ").strip().lower()
        if not raw:
            return bool(default)
        if raw in accepted_yes:
            return True
        if raw in accepted_no:
            return False


def _run_command(args: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _discover_wireless_interfaces() -> list[str]:
    discovered: list[str] = []
    ip_output = _run_command(["ip", "-br", "link"])
    if ip_output:
        for raw in ip_output.splitlines():
            parts = raw.split()
            if not parts:
                continue
            name = parts[0]
            if name.startswith("wl"):
                discovered.append(name)
    if discovered:
        return sorted(dict.fromkeys(discovered))

    sys_net = Path("/sys/class/net")
    if sys_net.exists():
        for entry in sorted(sys_net.iterdir()):
            name = entry.name
            if name.startswith("wl"):
                discovered.append(name)
    return sorted(dict.fromkeys(discovered))


def _detect_management_interface() -> str | None:
    route_output = _run_command(["ip", "route"])
    if not route_output:
        return None
    for raw in route_output.splitlines():
        line = raw.strip()
        if not line.startswith("default "):
            continue
        match = re.search(r"\bdev\s+(\S+)", line)
        if match:
            return match.group(1)
    return None


def _detect_lan_ipv4(interface: str | None) -> str | None:
    if interface:
        output = _run_command(["ip", "-4", "addr", "show", "dev", interface])
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", output)
        if match:
            return match.group(1)
    route_get_output = _run_command(["ip", "-4", "route", "get", "1.1.1.1"])
    match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", route_get_output)
    if match:
        return match.group(1)
    return None


def _read_interface_mac(interface: str) -> str:
    path = Path("/sys/class/net") / interface / "address"
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip().lower()
    except OSError:
        return ""


def _default_capture_interface(
    wireless_interfaces: Sequence[str],
    management_interface: str | None,
) -> str:
    if not wireless_interfaces:
        return "auto"

    mgmt = management_interface or ""
    non_mgmt = [item for item in wireless_interfaces if item != mgmt]
    preferred_usb = [item for item in non_mgmt if item.startswith("wlx")]
    preferred_internal = [item for item in non_mgmt if not item.startswith("wlo")]

    if preferred_usb:
        return preferred_usb[0]
    if preferred_internal:
        return preferred_internal[0]
    if non_mgmt:
        return non_mgmt[0]
    return wireless_interfaces[0]


def _default_exclude_regex(management_interface: str | None) -> str:
    pieces = {"wlo[0-9]+"}
    if management_interface:
        pieces.add(re.escape(management_interface))
    ordered = sorted(pieces)
    return "^(" + "|".join(ordered) + ")$"


def _list_bt_serial_candidates(serial_dir: Path = Path("/dev/serial/by-id")) -> list[str]:
    if not serial_dir.exists():
        return []
    candidates: list[str] = []
    for entry in sorted(serial_dir.iterdir()):
        path = str(entry)
        if entry.exists() or entry.is_symlink():
            candidates.append(path)
    return candidates


def _derive_bt_serial(device_path: str) -> str:
    name = Path(device_path).name
    hex_matches = re.findall(r"([A-Fa-f0-9]{8,})", name)
    if hex_matches:
        return hex_matches[-1].upper()
    tail = name.rsplit("_", 1)[-1]
    tail = tail.split("-if", 1)[0]
    if tail and tail.lower() not in {"auto", "none"}:
        return tail
    return ""


def _extract_compose_service_block(compose_text: str, service_name: str) -> list[str]:
    lines = compose_text.splitlines()
    service_pattern = re.compile(rf"^\s{{2}}{re.escape(service_name)}:\s*$")
    start = -1
    for idx, line in enumerate(lines):
        if service_pattern.match(line):
            start = idx + 1
            break
    if start < 0:
        return []

    block: list[str] = []
    service_boundary = re.compile(r"^\s{2}[A-Za-z0-9_-]+:\s*$")
    for line in lines[start:]:
        if service_boundary.match(line):
            break
        block.append(line)
    return block


def _inspect_ui_compose_strategy(repo_root: Path) -> ComposeUiPlan:
    compose_path = repo_root / _DEFAULT_DOCKER_COMPOSE_FILE
    if not compose_path.exists():
        return ComposeUiPlan(strategy=_UI_STRATEGY_UNKNOWN, has_ui_service=False, default_port=8080)

    text = compose_path.read_text(encoding="utf-8")
    ui_block = _extract_compose_service_block(text, "ui")
    if not ui_block:
        return ComposeUiPlan(strategy=_UI_STRATEGY_UNKNOWN, has_ui_service=False, default_port=8080)

    block_text = "\n".join(ui_block)
    if "network_mode: \"host\"" in block_text or "network_mode: host" in block_text:
        return ComposeUiPlan(strategy=_UI_STRATEGY_HOST_NETWORK, has_ui_service=True, default_port=8080)
    if re.search(r"^\s+ports:\s*$", block_text, flags=re.MULTILINE):
        return ComposeUiPlan(strategy=_UI_STRATEGY_PUBLISHED_PORTS, has_ui_service=True, default_port=8080)
    return ComposeUiPlan(strategy=_UI_STRATEGY_OVERRIDE_REQUIRED, has_ui_service=True, default_port=8080)


def _compose_override_content(port: int) -> str:
    return (
        "# Generated by wicap-assist setup-wicap-env for headless LAN UI access.\n"
        "services:\n"
        "  ui:\n"
        "    ports:\n"
        f"      - \"0.0.0.0:{port}:{port}\"\n"
    )


def _split_host_port(raw: str, default_port: int = 1433) -> tuple[str, int]:
    value = str(raw or "").strip()
    if not value:
        return "", default_port

    host = value
    port = default_port
    if "," in value:
        host_part, port_part = value.rsplit(",", 1)
        host = host_part.strip()
        if port_part.strip().isdigit():
            port = int(port_part.strip())
    elif ":" in value and value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        host = host_part.strip()
        if port_part.strip().isdigit():
            port = int(port_part.strip())
    return host, port


def _probe_tcp_reachability(host: str, port: int, timeout_seconds: float = 1.5) -> tuple[bool, str]:
    if not host or port <= 0:
        return False, "skipped (missing host/port)"
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True, "ok"
    except OSError as exc:
        return False, str(exc)


def _resolve_repo_relative(repo_root: Path, raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if candidate.is_absolute():
        return candidate
    return (repo_root / candidate).resolve()


def _render_env_text(
    *,
    values: dict[str, str],
    sections: Sequence[EnvSection],
    preserved_custom: dict[str, str],
) -> str:
    lines: list[str] = []
    seen: set[str] = set()

    for section in sections:
        section_keys = [key for key in section.keys if key in values and key not in seen]
        if not section_keys:
            continue
        if lines and lines[-1] != "":
            lines.append("")
        lines.append("# =============================================================================")
        lines.append(f"# {section.name}")
        lines.append(f"# {section.description}")
        lines.append("# =============================================================================")
        for key in section_keys:
            note = _KEY_NOTES.get(key)
            if note:
                lines.append(f"# {note}")
            lines.append(f"{key}={values.get(key, '')}")
            seen.add(key)

    if preserved_custom:
        if lines and lines[-1] != "":
            lines.append("")
        lines.append("# =============================================================================")
        lines.append("# Preserved Existing Custom Keys")
        lines.append("# Keys kept from previous .env to avoid dropping local overrides.")
        lines.append("# =============================================================================")
        for key in sorted(preserved_custom.keys()):
            if key in seen:
                continue
            lines.append(f"{key}={preserved_custom[key]}")
            seen.add(key)

    return "\n".join(lines).rstrip() + "\n"


def _known_wizard_keys() -> set[str]:
    keys: set[str] = set()
    for section in ENV_SECTIONS:
        keys.update(section.keys)
    return keys


def run_wicap_env_setup(
    *,
    repo_root: Path,
    env_path: Path | None = None,
    assume_yes: bool = False,
    dry_run: bool = False,
    backup_existing: bool = True,
    input_fn: InputFn | None = None,
    secret_input_fn: SecretInputFn | None = None,
    print_fn: PrintFn | None = None,
) -> dict[str, object]:
    if input_fn is None:
        input_fn = input
    if secret_input_fn is None:
        secret_input_fn = getpass.getpass
    if print_fn is None:
        print_fn = print

    resolved_repo_root = Path(repo_root).expanduser()
    if not resolved_repo_root.exists():
        raise ValueError(f"WiCAP repo root does not exist: {resolved_repo_root}")

    target_env_path = Path(env_path).expanduser() if env_path is not None else (resolved_repo_root / ".env")
    existing = load_env_entries(target_env_path)
    already_exists = target_env_path.exists()

    # Keep alias defaults in sync so blank input reuses either alias if set.
    if "WICAP_SQL_SERVER" in existing and "WICAP_SQL_HOST" not in existing:
        existing["WICAP_SQL_HOST"] = existing["WICAP_SQL_SERVER"]
    if "WICAP_SQL_USERNAME" in existing and "WICAP_SQL_USER" not in existing:
        existing["WICAP_SQL_USER"] = existing["WICAP_SQL_USERNAME"]

    compose_ui_plan = _inspect_ui_compose_strategy(resolved_repo_root)
    management_interface = _detect_management_interface()
    wireless_interfaces = _discover_wireless_interfaces()
    lan_ip = _detect_lan_ipv4(management_interface)
    hostname = socket.gethostname()

    print_fn(f"WiCAP repo root: {resolved_repo_root}")
    print_fn(f"Target .env: {target_env_path}")
    if already_exists:
        print_fn("Updating existing .env. Press Enter to keep current values.")
    else:
        print_fn("Creating fresh .env for WiCAP runtime bootstrap.")
    print_fn("Coverage categories: A=required boot, B=headless UI, C=Wi-Fi, D=Bluetooth, E=safety rails, F=optional tuning.")
    print_fn(f"Detected management interface: {management_interface or 'unknown'}")
    print_fn(f"Detected LAN IPv4: {lan_ip or 'unknown'}")
    if wireless_interfaces:
        print_fn(f"Detected wireless interfaces: {', '.join(wireless_interfaces)}")
    else:
        print_fn("No wireless interfaces detected from ip/sysfs; manual input is still allowed.")

    values: dict[str, str] = {}
    skipped_sections: list[str] = []
    warnings: list[str] = []

    # ------------------------------------------------------------------
    # A) Required boot values
    # ------------------------------------------------------------------
    print_fn("\n[Required A] Core SQL + internal auth")
    required_fields = [
        PromptField("WICAP_SQL_HOST", "SQL host (IP, hostname, optionally with ,1433)", default=ENV_DEFAULTS["WICAP_SQL_HOST"]),
        PromptField("WICAP_SQL_DATABASE", "SQL database name", default=ENV_DEFAULTS["WICAP_SQL_DATABASE"]),
        PromptField("WICAP_SQL_USER", "SQL username", default=ENV_DEFAULTS["WICAP_SQL_USER"]),
        PromptField(
            "WICAP_SQL_PASSWORD",
            "SQL password (required, min 12 chars)",
            required=True,
            secret=True,
            min_length=12,
        ),
        PromptField(
            "WICAP_INTERNAL_SECRET",
            "Internal API secret (required, min 12 chars)",
            required=True,
            secret=True,
            min_length=12,
        ),
        PromptField("WICAP_SQL_DRIVER", "SQL ODBC driver", default=ENV_DEFAULTS["WICAP_SQL_DRIVER"]),
        PromptField(
            "WICAP_SQL_TRUST_CERT",
            "Trust SQL TLS certificate",
            default=ENV_DEFAULTS["WICAP_SQL_TRUST_CERT"],
            normalizer=_normalize_bool,
        ),
        PromptField(
            "WICAP_INTERNAL_SECRET_REQUIRED",
            "Require internal secret for admin/internal APIs",
            default=ENV_DEFAULTS["WICAP_INTERNAL_SECRET_REQUIRED"],
            normalizer=_normalize_bool,
        ),
        PromptField(
            "WICAP_INTERNAL_ALLOWLIST",
            "Internal allowlist (comma-separated IPs/CIDRs)",
            default=ENV_DEFAULTS["WICAP_INTERNAL_ALLOWLIST"],
        ),
        PromptField("WICAP_REDIS_URL", "Redis URL", default=ENV_DEFAULTS["WICAP_REDIS_URL"]),
    ]
    for field in required_fields:
        values[field.key] = _prompt_value(
            field,
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )

    # Write compatibility aliases exactly once.
    values["WICAP_SQL_SERVER"] = values["WICAP_SQL_HOST"]
    values["WICAP_SQL_USERNAME"] = values["WICAP_SQL_USER"]

    if _prompt_confirm("Run SQL TCP reachability sanity check now?", default=False, input_fn=input_fn):
        sql_host, sql_port = _split_host_port(values["WICAP_SQL_HOST"], default_port=1433)
        ok, reason = _probe_tcp_reachability(sql_host, sql_port)
        if ok:
            print_fn(f"SQL TCP reachability check passed for {sql_host}:{sql_port}.")
        else:
            warning = f"SQL TCP reachability check failed for {sql_host}:{sql_port}: {reason}"
            print_fn(f"WARNING: {warning}")
            warnings.append(warning)

    # ------------------------------------------------------------------
    # B) Headless LAN UI + capture path mapping
    # ------------------------------------------------------------------
    print_fn("\n[Required B] Headless LAN UI and capture path mapping")
    ui_host = lan_ip or hostname or "localhost"
    ui_port = compose_ui_plan.default_port
    ui_default = f"http://{ui_host}:{ui_port}"
    values["WICAP_UI_URL"] = _prompt_value(
        PromptField("WICAP_UI_URL", "WiCAP UI base URL (LAN-reachable)", default=ui_default),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_CAPTURES_DIR"] = _prompt_value(
        PromptField("WICAP_CAPTURES_DIR", "Core capture output directory", default=ENV_DEFAULTS["WICAP_CAPTURES_DIR"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_CAPTURE_DIR"] = _prompt_value(
        PromptField(
            "WICAP_CAPTURE_DIR",
            "UI capture directory (should match captures dir for docker host-mount layout)",
            default=values["WICAP_CAPTURES_DIR"],
        ),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_UI_DB_POOL_SIZE"] = _prompt_value(
        PromptField("WICAP_UI_DB_POOL_SIZE", "UI SQL connection pool size", default=ENV_DEFAULTS["WICAP_UI_DB_POOL_SIZE"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_REPLAY_LOG_DIR"] = _prompt_value(
        PromptField("WICAP_REPLAY_LOG_DIR", "Admin replay log directory", default=ENV_DEFAULTS["WICAP_REPLAY_LOG_DIR"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_EVIDENCE_BUNDLE_DIR"] = _prompt_value(
        PromptField(
            "WICAP_EVIDENCE_BUNDLE_DIR",
            "Evidence bundle output directory",
            default=ENV_DEFAULTS["WICAP_EVIDENCE_BUNDLE_DIR"],
        ),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )

    compose_override_path = resolved_repo_root / "compose.override.yml"
    compose_override_written = False
    if compose_ui_plan.strategy == _UI_STRATEGY_HOST_NETWORK:
        print_fn("Compose UI strategy: host network mode detected; no port override file needed.")
    elif compose_ui_plan.strategy == _UI_STRATEGY_PUBLISHED_PORTS:
        print_fn("Compose UI strategy: published ports already configured; no override file needed.")
    elif compose_ui_plan.strategy == _UI_STRATEGY_OVERRIDE_REQUIRED:
        if _prompt_confirm(
            "Compose UI service has no host-network/ports config. Write compose.override.yml for 0.0.0.0:8080?",
            default=True,
            input_fn=input_fn,
        ):
            if dry_run:
                print_fn(f"Dry run: would write {compose_override_path}")
            else:
                compose_override_path.write_text(_compose_override_content(ui_port), encoding="utf-8")
                compose_override_written = True
                print_fn(f"Wrote {compose_override_path}")
        else:
            warning = "UI compose override skipped; verify LAN reachability manually before deployment."
            print_fn(f"WARNING: {warning}")
            warnings.append(warning)
    else:
        warning = "Could not inspect docker-compose UI networking; verify UI LAN reachability manually."
        print_fn(f"WARNING: {warning}")
        warnings.append(warning)

    # ------------------------------------------------------------------
    # C) Wi-Fi capture interface safety rails
    # ------------------------------------------------------------------
    print_fn("\n[Required C + Safety E] Wi-Fi capture interface selection")
    capture_default = _default_capture_interface(wireless_interfaces, management_interface)
    existing_interface = existing.get("WICAP_INTERFACE", "").strip()
    existing_mode_default = "auto" if existing_interface.lower() == "auto" else "explicit"
    mode_default = existing_mode_default if existing_interface else ("explicit" if capture_default != "auto" else "auto")

    interface_mode = _prompt_value(
        PromptField(
            "WICAP_INTERFACE_MODE",
            "Wi-Fi capture mode (explicit/auto)",
            default=mode_default,
            normalizer=_normalize_interface_mode,
        ),
        existing={},
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )

    safe_exclude_default = _default_exclude_regex(management_interface)
    if interface_mode == "explicit":
        suggested = capture_default if capture_default != "auto" else (existing_interface or "wlan1")
        while True:
            chosen = _prompt_value(
                PromptField("WICAP_INTERFACE", "Capture Wi-Fi interface (explicit pin)", default=suggested, required=True),
                existing=existing,
                input_fn=input_fn,
                secret_input_fn=secret_input_fn,
                print_fn=print_fn,
            )
            if management_interface and chosen == management_interface:
                print_fn(
                    "WARNING: Selected interface is also the management/default-route interface. "
                    "This can drop SSH on headless hosts."
                )
                if _prompt_confirm(
                    "Override safety rail and use management interface anyway?",
                    default=False,
                    input_fn=input_fn,
                ):
                    values["WICAP_INTERFACE"] = chosen
                    break
                continue
            values["WICAP_INTERFACE"] = chosen
            break
        mac_default = _read_interface_mac(values["WICAP_INTERFACE"])
        values["WICAP_INTERFACE_MAC"] = _prompt_value(
            PromptField("WICAP_INTERFACE_MAC", "Capture interface MAC (optional safety pin)", default=mac_default),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values["WICAP_INTERFACE_REGEX"] = _prompt_value(
            PromptField("WICAP_INTERFACE_REGEX", "Interface auto-select regex (optional)", default=""),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
    else:
        values["WICAP_INTERFACE"] = "auto"
        regex_default = "^wlx.*$" if any(item.startswith("wlx") for item in wireless_interfaces) else "^wl.*$"
        values["WICAP_INTERFACE_MAC"] = _prompt_value(
            PromptField("WICAP_INTERFACE_MAC", "Preferred interface MAC (optional, for auto mode)", default=""),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values["WICAP_INTERFACE_REGEX"] = _prompt_value(
            PromptField("WICAP_INTERFACE_REGEX", "Interface include regex (auto mode)", default=regex_default),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )

    values["WICAP_INTERFACE_EXCLUDE_REGEX"] = _prompt_value(
        PromptField(
            "WICAP_INTERFACE_EXCLUDE_REGEX",
            "Interface exclude regex (safety rail)",
            default=safe_exclude_default,
        ),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_BANDS"] = _prompt_value(
        PromptField("WICAP_BANDS", "Capture bands (2.4ghz/5ghz/6ghz/all)", default=ENV_DEFAULTS["WICAP_BANDS"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_CAPTURE_BACKEND"] = _prompt_value(
        PromptField("WICAP_CAPTURE_BACKEND", "Capture backend (auto/scapy/libpcap)", default=ENV_DEFAULTS["WICAP_CAPTURE_BACKEND"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )

    # ------------------------------------------------------------------
    # D) Bluetooth sniffer setup
    # ------------------------------------------------------------------
    print_fn("\n[Required D] Bluetooth sniffer wiring")
    values["WICAP_BT_ENABLED"] = _prompt_value(
        PromptField("WICAP_BT_ENABLED", "Enable Bluetooth capture", default=ENV_DEFAULTS["WICAP_BT_ENABLED"], normalizer=_normalize_bool),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )

    bt_candidates = _list_bt_serial_candidates()
    if values["WICAP_BT_ENABLED"] == "true" and bt_candidates:
        print_fn("Detected /dev/serial/by-id candidates:")
        for path in bt_candidates:
            print_fn(f"  - {path}")
    elif values["WICAP_BT_ENABLED"] == "true":
        print_fn("No /dev/serial/by-id sniffer candidates detected; auto fallback will still be configured.")

    bt_interface_default = existing.get("WICAP_BT_INTERFACE") or (bt_candidates[0] if bt_candidates else "auto")
    bt_glob_default = existing.get("WICAP_BT_INTERFACE_GLOB") or _DEFAULT_BT_INTERFACE_GLOB
    bt_serial_default = existing.get("WICAP_BT_SERIAL") or _derive_bt_serial(bt_interface_default)
    values["WICAP_BT_INTERFACE"] = _prompt_value(
        PromptField(
            "WICAP_BT_INTERFACE",
            "Bluetooth interface path (prefer /dev/serial/by-id/*) or auto",
            default=bt_interface_default,
        ),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_BT_INTERFACE_GLOB"] = _prompt_value(
        PromptField("WICAP_BT_INTERFACE_GLOB", "Bluetooth interface glob fallback", default=bt_glob_default),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    if not bt_serial_default:
        bt_serial_default = _derive_bt_serial(values["WICAP_BT_INTERFACE"])
    values["WICAP_BT_SERIAL"] = _prompt_value(
        PromptField("WICAP_BT_SERIAL", "Bluetooth serial substring fallback (optional)", default=bt_serial_default),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_BT_CAPTURE_DIR"] = _prompt_value(
        PromptField("WICAP_BT_CAPTURE_DIR", "Bluetooth capture directory", default=ENV_DEFAULTS["WICAP_BT_CAPTURE_DIR"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )
    values["WICAP_BT_EXTCAP_DIR"] = _prompt_value(
        PromptField("WICAP_BT_EXTCAP_DIR", "Bluetooth extcap directory", default=ENV_DEFAULTS["WICAP_BT_EXTCAP_DIR"]),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )

    # ------------------------------------------------------------------
    # E/F) Optional tuning + OTLP
    # ------------------------------------------------------------------
    print_fn("\n[Optional F] Performance/queue tuning + OTLP")
    configure_optional_tuning = _prompt_confirm(
        "Configure optional tuning knobs now?",
        default=False,
        input_fn=input_fn,
    )
    if not configure_optional_tuning:
        skipped_sections.append("optional_tuning")

    tuning_fields = [
        PromptField("WICAP_DWELL_THRESHOLD", "Dwell threshold", default=ENV_DEFAULTS["WICAP_DWELL_THRESHOLD"]),
        PromptField("WICAP_DWELL_DURATION", "Dwell duration (seconds)", default=ENV_DEFAULTS["WICAP_DWELL_DURATION"]),
        PromptField("WICAP_QUEUE_MAX_BYTES", "Queue max bytes", default=ENV_DEFAULTS["WICAP_QUEUE_MAX_BYTES"]),
        PromptField("WICAP_QUEUE_MAX_FILES", "Queue max files", default=ENV_DEFAULTS["WICAP_QUEUE_MAX_FILES"]),
        PromptField(
            "WICAP_QUEUE_BACKPRESSURE_MAX_BYTES",
            "Queue backpressure max bytes",
            default=ENV_DEFAULTS["WICAP_QUEUE_BACKPRESSURE_MAX_BYTES"],
        ),
        PromptField(
            "WICAP_QUEUE_BACKPRESSURE_ACTION",
            "Queue backpressure action (drop_pulse/drop)",
            default=ENV_DEFAULTS["WICAP_QUEUE_BACKPRESSURE_ACTION"],
        ),
        PromptField("WICAP_DEDUP_MAX_ENTRIES", "Dedup max entries", default=ENV_DEFAULTS["WICAP_DEDUP_MAX_ENTRIES"]),
    ]
    if configure_optional_tuning:
        for field in tuning_fields:
            values[field.key] = _prompt_value(
                field,
                existing=existing,
                input_fn=input_fn,
                secret_input_fn=secret_input_fn,
                print_fn=print_fn,
            )
    else:
        for field in tuning_fields:
            values[field.key] = existing.get(field.key, field.default or "")

    values["WICAP_OTLP_PROFILE"] = _prompt_value(
        PromptField(
            "WICAP_OTLP_PROFILE",
            "OTLP telemetry profile (disabled/self_hosted/vendor/cloud)",
            default=ENV_DEFAULTS["WICAP_OTLP_PROFILE"],
            normalizer=_normalize_otlp_profile,
        ),
        existing=existing,
        input_fn=input_fn,
        secret_input_fn=secret_input_fn,
        print_fn=print_fn,
    )

    otlp_fields = [
        PromptField("WICAP_OTLP_HTTP_ENDPOINT", "OTLP HTTP endpoint", default=ENV_DEFAULTS["WICAP_OTLP_HTTP_ENDPOINT"]),
        PromptField("WICAP_OTLP_HEADERS", "OTLP headers (optional)", default=ENV_DEFAULTS["WICAP_OTLP_HEADERS"]),
        PromptField("WICAP_OTLP_AUTH_BEARER", "OTLP bearer token (optional)", default=ENV_DEFAULTS["WICAP_OTLP_AUTH_BEARER"], secret=True),
        PromptField("WICAP_OTLP_API_KEY", "OTLP API key (optional)", default=ENV_DEFAULTS["WICAP_OTLP_API_KEY"], secret=True),
        PromptField("WICAP_OTLP_TIMEOUT_SECONDS", "OTLP timeout seconds", default=ENV_DEFAULTS["WICAP_OTLP_TIMEOUT_SECONDS"]),
        PromptField("WICAP_OTLP_MAX_QUEUE", "OTLP max queue", default=ENV_DEFAULTS["WICAP_OTLP_MAX_QUEUE"]),
        PromptField("WICAP_OTLP_MAX_BATCH", "OTLP max batch", default=ENV_DEFAULTS["WICAP_OTLP_MAX_BATCH"]),
        PromptField(
            "WICAP_OTLP_RETRY_BACKOFF_SECONDS",
            "OTLP retry backoff seconds",
            default=ENV_DEFAULTS["WICAP_OTLP_RETRY_BACKOFF_SECONDS"],
        ),
        PromptField(
            "WICAP_OTLP_MAX_BACKOFF_SECONDS",
            "OTLP max backoff seconds",
            default=ENV_DEFAULTS["WICAP_OTLP_MAX_BACKOFF_SECONDS"],
        ),
    ]

    if values["WICAP_OTLP_PROFILE"] == "disabled":
        for field in otlp_fields:
            values[field.key] = existing.get(field.key, field.default or "")
    else:
        # Endpoint required when OTLP is enabled.
        endpoint = _prompt_value(
            PromptField(
                "WICAP_OTLP_HTTP_ENDPOINT",
                "OTLP HTTP endpoint",
                default=ENV_DEFAULTS["WICAP_OTLP_HTTP_ENDPOINT"],
                required=True,
            ),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values["WICAP_OTLP_HTTP_ENDPOINT"] = endpoint
        for field in otlp_fields[1:]:
            values[field.key] = _prompt_value(
                field,
                existing=existing,
                input_fn=input_fn,
                secret_input_fn=secret_input_fn,
                print_fn=print_fn,
            )

    # Ensure every known key has deterministic value fallback.
    for key in _known_wizard_keys():
        if key in values:
            continue
        values[key] = existing.get(key, ENV_DEFAULTS.get(key, ""))

    # Directory validation/creation helper for headless setup.
    mkdir_targets = [
        ("WICAP_CAPTURES_DIR", values["WICAP_CAPTURES_DIR"]),
        ("WICAP_CAPTURE_DIR", values["WICAP_CAPTURE_DIR"]),
        ("WICAP_EVIDENCE_BUNDLE_DIR", values["WICAP_EVIDENCE_BUNDLE_DIR"]),
    ]
    if values.get("WICAP_BT_ENABLED") == "true":
        mkdir_targets.append(("WICAP_BT_CAPTURE_DIR", values["WICAP_BT_CAPTURE_DIR"]))

    if _prompt_confirm("Create missing capture/output directories now?", default=True, input_fn=input_fn):
        for label, raw_path in mkdir_targets:
            resolved = _resolve_repo_relative(resolved_repo_root, raw_path)
            try:
                resolved.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                warning = f"Could not create {label} at {resolved}: {exc}"
                print_fn(f"WARNING: {warning}")
                warnings.append(warning)
                continue
            if not os.access(resolved, os.W_OK):
                warning = f"{label} is not writable: {resolved}"
                print_fn(f"WARNING: {warning}")
                warnings.append(warning)
    else:
        skipped_sections.append("directory_create")

    if not assume_yes and not dry_run and not _prompt_confirm("Write values to WiCAP .env now?", input_fn=input_fn):
        raise SetupAbortedError("setup-wicap-env aborted by user")

    known_keys = _known_wizard_keys()
    preserved_custom = {
        key: value
        for key, value in existing.items()
        if key not in known_keys
    }
    rendered = _render_env_text(
        values=values,
        sections=ENV_SECTIONS,
        preserved_custom=preserved_custom,
    )

    existing_before = load_env_entries(target_env_path)
    changed_keys = sorted([key for key, value in values.items() if existing_before.get(key) != value])

    backup_path: str | None = None
    if dry_run:
        print_fn("\n--- Dry Run (.env preview) ---")
        print_fn(rendered.rstrip())
        print_fn("--- End Preview ---")
    else:
        if backup_existing and target_env_path.exists():
            timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            candidate = target_env_path.with_name(f"{target_env_path.name}.bak.{timestamp}")
            candidate.write_text(target_env_path.read_text(encoding="utf-8"), encoding="utf-8")
            backup_path = str(candidate)
        target_env_path.parent.mkdir(parents=True, exist_ok=True)
        target_env_path.write_text(rendered, encoding="utf-8")

    print_fn("\nSetup summary:")
    print_fn(f"- UI strategy: {compose_ui_plan.strategy}")
    print_fn(f"- Changed keys: {len(changed_keys)}")
    print_fn(f"- Optional sections skipped: {', '.join(skipped_sections) if skipped_sections else 'none'}")
    print_fn(f"- Warnings: {len(warnings)}")
    if backup_path:
        print_fn(f"- Backup: {backup_path}")
    if compose_override_written:
        print_fn(f"- Compose override written: {compose_override_path}")

    next_commands = [
        f"cd {resolved_repo_root}",
        "docker compose up -d --build",
        "docker compose ps",
    ]
    print_fn("Next commands:")
    for command in next_commands:
        print_fn(f"  {command}")

    return {
        "env_path": str(target_env_path),
        "repo_root": str(resolved_repo_root),
        "created": not already_exists,
        "changed_keys": changed_keys,
        "updated_keys": sorted(values.keys()),
        "skipped_sections": skipped_sections,
        "warnings": warnings,
        "dry_run": dry_run,
        "backup_path": backup_path,
        "ui_bind_strategy": compose_ui_plan.strategy,
        "compose_override_path": str(compose_override_path) if compose_override_written else None,
        "next_commands": next_commands,
    }
