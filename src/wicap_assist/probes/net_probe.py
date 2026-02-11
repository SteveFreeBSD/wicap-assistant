"""Read-only socket/port probes for local WICAP runtime."""

from __future__ import annotations

import re
import subprocess
from typing import Any, Callable

Runner = Callable[..., subprocess.CompletedProcess[str]]
_PORT_RE = re.compile(r":(\d+)\s")


def probe_network(
    *,
    expected_ports: tuple[int, ...] = (8080, 6380),
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Probe listening tcp ports via `ss -ltnp` (read-only)."""
    result = runner(["ss", "-ltnp"], capture_output=True, text=True, check=False)

    listening_ports: set[int] = set()
    if result.returncode == 0:
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line or line.startswith("State"):
                continue
            match = _PORT_RE.search(line)
            if not match:
                continue
            try:
                listening_ports.add(int(match.group(1)))
            except ValueError:
                continue

    expected: dict[str, bool] = {}
    for port in expected_ports:
        expected[str(int(port))] = int(port) in listening_ports

    return {
        "ss_ok": result.returncode == 0,
        "listening_ports": sorted(listening_ports),
        "expected_ports": expected,
    }
