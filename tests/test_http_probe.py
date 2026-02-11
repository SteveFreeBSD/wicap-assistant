from __future__ import annotations

from urllib.error import URLError

from wicap_assist.probes.http_probe import probe_http_health


def test_probe_http_health_handles_urlerror(monkeypatch) -> None:
    def raise_error(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise URLError("connection refused")

    monkeypatch.setattr("wicap_assist.probes.http_probe.urlopen", raise_error)
    payload = probe_http_health(url="http://127.0.0.1:8080/health", timeout_seconds=0.1)
    assert payload["ok"] is False
    assert payload["status_code"] is None
    assert "refused" in str(payload["error"]).lower()


def test_probe_http_health_handles_timeout(monkeypatch) -> None:
    def raise_timeout(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise TimeoutError("timed out")

    monkeypatch.setattr("wicap_assist.probes.http_probe.urlopen", raise_timeout)
    payload = probe_http_health(url="http://127.0.0.1:8080/health", timeout_seconds=0.1)
    assert payload["ok"] is False
    assert payload["status_code"] is None
    assert "timed out" in str(payload["error"]).lower()
