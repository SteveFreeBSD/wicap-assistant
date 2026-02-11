"""OTLP endpoint/profile resolution and validation for assistant telemetry."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Mapping
from urllib.parse import urlparse


_PROFILE_ALIASES = {
    "": "disabled",
    "off": "disabled",
    "none": "disabled",
    "disabled": "disabled",
    "self-hosted": "self_hosted",
    "self_hosted": "self_hosted",
    "selfhosted": "self_hosted",
    "vendor": "vendor",
    "cloud": "cloud",
}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(slots=True)
class OtlpProfile:
    profile: str
    enabled: bool
    endpoint: str | None
    headers: dict[str, str]
    timeout_seconds: float
    errors: list[str]
    warnings: list[str]

    @property
    def is_valid(self) -> bool:
        return self.enabled and not self.errors and bool(self.endpoint)


def _normalize_profile(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return _PROFILE_ALIASES.get(normalized, normalized)


def _parse_headers(raw: str) -> dict[str, str]:
    text = str(raw or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(payload, dict):
            return {str(k): str(v) for k, v in payload.items() if str(k).strip()}
        return {}

    out: dict[str, str] = {}
    for pair in text.split(","):
        key, sep, value = pair.partition("=")
        if not sep:
            continue
        key_text = key.strip()
        if not key_text:
            continue
        out[key_text] = value.strip()
    return out


def resolve_otlp_profile(env: Mapping[str, str] | None = None) -> OtlpProfile:
    mapping = dict(env or os.environ)
    raw_profile = mapping.get("WICAP_ASSIST_OTLP_PROFILE", "")
    profile = _normalize_profile(raw_profile)

    endpoint = str(mapping.get("WICAP_ASSIST_OTLP_HTTP_ENDPOINT", "")).strip() or None
    headers = _parse_headers(mapping.get("WICAP_ASSIST_OTLP_HEADERS", ""))
    warnings: list[str] = []
    errors: list[str] = []

    raw_timeout = str(mapping.get("WICAP_ASSIST_OTLP_TIMEOUT_SECONDS", "1.5")).strip()
    timeout_seconds = 1.5
    try:
        timeout_seconds = max(0.1, float(raw_timeout))
    except ValueError:
        timeout_seconds = 1.5
        warnings.append("invalid timeout, defaulted to 1.5s")

    # Backward-compatible behavior: endpoint without explicit profile implies self_hosted.
    if profile == "disabled" and endpoint:
        profile = "self_hosted"

    bearer = str(mapping.get("WICAP_ASSIST_OTLP_AUTH_BEARER", "")).strip()
    api_key = str(mapping.get("WICAP_ASSIST_OTLP_API_KEY", "")).strip()
    header_keys = {str(key).strip().lower() for key in headers.keys()}
    if bearer and "authorization" not in header_keys:
        headers["Authorization"] = f"Bearer {bearer}"
    if api_key and "x-api-key" not in header_keys:
        headers["x-api-key"] = api_key

    if profile not in {"disabled", "self_hosted", "vendor", "cloud"}:
        errors.append(f"unknown profile '{profile}'")

    enabled = profile != "disabled"
    if enabled and not endpoint:
        errors.append("endpoint is required for enabled OTLP profile")

    parsed = urlparse(endpoint) if endpoint else None
    if endpoint and parsed is not None:
        scheme = str(parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            errors.append("endpoint must use http or https")
        host = str(parsed.hostname or "").strip().lower()
        if profile in {"vendor", "cloud"} and scheme != "https" and host not in _LOCAL_HOSTS:
            errors.append("vendor/cloud profiles require https endpoint (except localhost)")

    has_auth = any(key in {"authorization", "x-api-key"} for key in header_keys) or bool(
        headers.get("Authorization") or headers.get("x-api-key")
    )
    if profile in {"vendor", "cloud"} and not has_auth:
        errors.append("vendor/cloud profiles require auth via bearer token, api key, or headers")
    if profile == "self_hosted" and not has_auth:
        warnings.append("self_hosted profile configured without auth headers")

    return OtlpProfile(
        profile=profile,
        enabled=bool(enabled),
        endpoint=endpoint,
        headers=headers,
        timeout_seconds=float(timeout_seconds),
        errors=errors,
        warnings=warnings,
    )
