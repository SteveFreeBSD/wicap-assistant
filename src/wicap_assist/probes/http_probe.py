"""Optional read-only localhost HTTP health probe."""

from __future__ import annotations

from urllib.error import URLError
from urllib.request import Request, urlopen


def probe_http_health(
    *,
    url: str = "http://127.0.0.1:8080/health",
    timeout_seconds: float = 2.0,
) -> dict[str, object]:
    """Probe a local health endpoint with GET request (read-only)."""
    req = Request(url=url, method="GET")
    try:
        with urlopen(req, timeout=timeout_seconds) as resp:  # noqa: S310 - localhost probe only
            status = int(getattr(resp, "status", 0) or 0)
            return {
                "url": url,
                "ok": 200 <= status < 400,
                "status_code": status,
                "error": None,
            }
    except URLError as exc:
        return {
            "url": url,
            "ok": False,
            "status_code": None,
            "error": str(exc),
        }
