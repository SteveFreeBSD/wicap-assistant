from __future__ import annotations

from wicap_assist.otlp_profile import resolve_otlp_profile


def test_resolve_otlp_profile_defaults_to_disabled() -> None:
    profile = resolve_otlp_profile({})
    assert profile.profile == "disabled"
    assert profile.enabled is False
    assert profile.endpoint is None
    assert profile.errors == []


def test_resolve_otlp_profile_endpoint_only_defaults_to_self_hosted() -> None:
    profile = resolve_otlp_profile(
        {
            "WICAP_ASSIST_OTLP_HTTP_ENDPOINT": "http://localhost:4318/v1/logs",
        }
    )
    assert profile.profile == "self_hosted"
    assert profile.is_valid is True
    assert profile.endpoint == "http://localhost:4318/v1/logs"


def test_resolve_otlp_profile_vendor_requires_auth() -> None:
    profile = resolve_otlp_profile(
        {
            "WICAP_ASSIST_OTLP_PROFILE": "vendor",
            "WICAP_ASSIST_OTLP_HTTP_ENDPOINT": "https://otlp.example.com/v1/logs",
        }
    )
    assert profile.enabled is True
    assert profile.is_valid is False
    assert any("require auth" in item for item in profile.errors)


def test_resolve_otlp_profile_cloud_with_bearer_is_valid() -> None:
    profile = resolve_otlp_profile(
        {
            "WICAP_ASSIST_OTLP_PROFILE": "cloud",
            "WICAP_ASSIST_OTLP_HTTP_ENDPOINT": "https://otlp.example.com/v1/logs",
            "WICAP_ASSIST_OTLP_AUTH_BEARER": "secret-token",
            "WICAP_ASSIST_OTLP_TIMEOUT_SECONDS": "2.5",
        }
    )
    assert profile.is_valid is True
    assert profile.headers["Authorization"].startswith("Bearer ")
    assert float(profile.timeout_seconds) == 2.5


def test_resolve_otlp_profile_vendor_requires_https_for_non_localhost() -> None:
    profile = resolve_otlp_profile(
        {
            "WICAP_ASSIST_OTLP_PROFILE": "vendor",
            "WICAP_ASSIST_OTLP_HTTP_ENDPOINT": "http://otlp.example.com/v1/logs",
            "WICAP_ASSIST_OTLP_API_KEY": "abc",
        }
    )
    assert profile.is_valid is False
    assert any("require https" in item for item in profile.errors)
