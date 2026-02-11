from __future__ import annotations

from wicap_assist.probes.net_probe import probe_network


class _DummyResult:
    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_probe_network_defaults_match_runtime_contract_ports() -> None:
    def fake_runner(cmd, capture_output, text, check):  # type: ignore[no-untyped-def]
        assert cmd == ["ss", "-ltnp"]
        return _DummyResult(
            0,
            stdout=(
                "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(('python',pid=1,fd=3))\n"
                "LISTEN 0 128 127.0.0.1:6380 0.0.0.0:* users:(('redis-server',pid=2,fd=5))\n"
            ),
        )

    payload = probe_network(runner=fake_runner)

    assert payload["expected_ports"] == {"8080": True, "6380": True}
    assert "6379" not in payload["expected_ports"]
