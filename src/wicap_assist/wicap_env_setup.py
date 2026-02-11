"""Interactive WiCAP .env bootstrap helpers."""

from __future__ import annotations

import getpass
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_ENV_ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")
_BOOL_TRUE = {"1", "true", "yes", "y", "on"}
_BOOL_FALSE = {"0", "false", "no", "n", "off"}
_OTLP_PROFILES = {"disabled", "self_hosted", "vendor", "cloud"}

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


class SetupAbortedError(RuntimeError):
    """Raised when user aborts setup."""


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


def _format_env_value(value: str) -> str:
    text = str(value)
    if not text:
        return ""
    if any(char.isspace() for char in text) or "#" in text or "\"" in text:
        escaped = text.replace("\\", "\\\\").replace("\"", "\\\"")
        return f"\"{escaped}\""
    return text


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


def _upsert_env_file(
    path: Path,
    *,
    updates: dict[str, str],
    order: list[str],
    template_path: Path | None = None,
) -> None:
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    elif template_path is not None and template_path.exists():
        lines = template_path.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    seen: set[str] = set()
    for index, line in enumerate(lines):
        match = _ENV_ASSIGNMENT_RE.match(line)
        if not match:
            continue
        key = match.group(1)
        if key not in updates:
            continue
        lines[index] = f"{key}={_format_env_value(updates[key])}"
        seen.add(key)

    missing = [key for key in order if key in updates and key not in seen]
    if missing:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("# Added by wicap-assist setup-wicap-env")
        for key in missing:
            lines.append(f"{key}={_format_env_value(updates[key])}")

    rendered = "\n".join(lines).rstrip() + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


def run_wicap_env_setup(
    *,
    repo_root: Path,
    env_path: Path | None = None,
    assume_yes: bool = False,
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
    template_path = resolved_repo_root / ".env.example"
    existing = load_env_entries(target_env_path)
    already_exists = target_env_path.exists()

    print_fn(f"WiCAP repo root: {resolved_repo_root}")
    print_fn(f"Target .env: {target_env_path}")
    if already_exists:
        print_fn("Updating existing .env. Press Enter to keep current values.")
    else:
        print_fn("Creating fresh .env for WiCAP runtime bootstrap.")

    values: dict[str, str] = {}
    order: list[str] = []

    fields = [
        PromptField("WICAP_SQL_HOST", "SQL host", default="192.168.4.25"),
        PromptField("WICAP_SQL_DATABASE", "SQL database name", default="WifiInsanityDB"),
        PromptField("WICAP_SQL_USER", "SQL username", default="steve_linux"),
        PromptField(
            "WICAP_SQL_PASSWORD",
            "SQL password (min 12 chars)",
            required=True,
            secret=True,
            min_length=12,
        ),
        PromptField(
            "WICAP_INTERNAL_SECRET",
            "Internal API secret (min 12 chars)",
            required=True,
            secret=True,
            min_length=12,
        ),
        PromptField("WICAP_SQL_DRIVER", "SQL ODBC driver", default="ODBC Driver 18 for SQL Server"),
        PromptField(
            "WICAP_SQL_TRUST_CERT",
            "Trust SQL TLS certificate",
            default="yes",
            normalizer=_normalize_bool,
        ),
        PromptField(
            "WICAP_INTERNAL_SECRET_REQUIRED",
            "Require internal secret for admin/internal APIs",
            default="true",
            normalizer=_normalize_bool,
        ),
        PromptField("WICAP_INTERNAL_ALLOWLIST", "Internal allowlist", default="127.0.0.1,::1"),
        PromptField("WICAP_REDIS_URL", "Redis URL", default="redis://localhost:6380/0"),
        PromptField("WICAP_INTERFACE", "Wi-Fi interface", default="wlan1"),
        PromptField("WICAP_UI_URL", "WiCAP UI base URL", default="http://localhost:8080"),
        PromptField("WICAP_BT_ENABLED", "Enable Bluetooth capture", default="false", normalizer=_normalize_bool),
        PromptField(
            "WICAP_OTLP_PROFILE",
            "OTLP telemetry profile",
            default="disabled",
            normalizer=_normalize_otlp_profile,
        ),
    ]

    # Keep alias defaults in sync so blank input reuses either alias if set.
    if "WICAP_SQL_SERVER" in existing and "WICAP_SQL_HOST" not in existing:
        existing["WICAP_SQL_HOST"] = existing["WICAP_SQL_SERVER"]
    if "WICAP_SQL_USERNAME" in existing and "WICAP_SQL_USER" not in existing:
        existing["WICAP_SQL_USER"] = existing["WICAP_SQL_USERNAME"]

    for field in fields:
        value = _prompt_value(
            field,
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values[field.key] = value
        order.append(field.key)

    if values["WICAP_OTLP_PROFILE"] != "disabled":
        otlp_endpoint = _prompt_value(
            PromptField(
                "WICAP_OTLP_HTTP_ENDPOINT",
                "OTLP HTTP endpoint",
                required=True,
            ),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values["WICAP_OTLP_HTTP_ENDPOINT"] = otlp_endpoint
        order.append("WICAP_OTLP_HTTP_ENDPOINT")

        otlp_bearer = _prompt_value(
            PromptField(
                "WICAP_OTLP_AUTH_BEARER",
                "OTLP bearer token (optional)",
                secret=True,
            ),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values["WICAP_OTLP_AUTH_BEARER"] = otlp_bearer
        order.append("WICAP_OTLP_AUTH_BEARER")

        otlp_api_key = _prompt_value(
            PromptField(
                "WICAP_OTLP_API_KEY",
                "OTLP API key (optional)",
                secret=True,
            ),
            existing=existing,
            input_fn=input_fn,
            secret_input_fn=secret_input_fn,
            print_fn=print_fn,
        )
        values["WICAP_OTLP_API_KEY"] = otlp_api_key
        order.append("WICAP_OTLP_API_KEY")

    if values.get("WICAP_SQL_HOST"):
        values["WICAP_SQL_SERVER"] = values["WICAP_SQL_HOST"]
        order.append("WICAP_SQL_SERVER")
    if values.get("WICAP_SQL_USER"):
        values["WICAP_SQL_USERNAME"] = values["WICAP_SQL_USER"]
        order.append("WICAP_SQL_USERNAME")

    if not assume_yes and not _prompt_confirm("Write values to WiCAP .env now?", input_fn=input_fn):
        raise SetupAbortedError("setup-wicap-env aborted by user")

    existing_before = load_env_entries(target_env_path)
    changed_keys = sorted([key for key, value in values.items() if existing_before.get(key) != value])
    _upsert_env_file(
        target_env_path,
        updates=values,
        order=order,
        template_path=template_path,
    )

    return {
        "env_path": str(target_env_path),
        "repo_root": str(resolved_repo_root),
        "created": not already_exists,
        "updated_keys": list(order),
        "changed_keys": changed_keys,
    }
