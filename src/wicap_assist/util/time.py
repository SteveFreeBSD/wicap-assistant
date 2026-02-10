"""Time helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_iso(value: object) -> str | None:
    """Best-effort conversion of common timestamp shapes into ISO-8601 UTC."""
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="seconds")

    if not isinstance(value, str):
        return None

    raw = value.strip()
    if not raw:
        return None

    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"

    # Normalize soak-log comma milliseconds to period for fromisoformat
    # e.g. "2026-01-30 02:52:13,585" -> "2026-01-30 02:52:13.585"
    raw = raw.replace(",", ".", 1) if "," in raw and raw[0].isdigit() else raw

    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="seconds")
        except (TypeError, ValueError):
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
