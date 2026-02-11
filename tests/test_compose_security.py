from __future__ import annotations

from pathlib import Path


def test_observe_profile_does_not_mount_docker_socket() -> None:
    compose_path = Path(__file__).resolve().parents[1] / "compose.assistant.yml"
    text = compose_path.read_text(encoding="utf-8")

    # Observe profile block must not include docker.sock mount.
    start = text.find("wicap-assist-live:")
    end = text.find("\n  wicap-assist-control:", start)
    assert start >= 0
    assert end > start
    live_block = text[start:end]
    assert "profiles: [\"observe\"]" in live_block
    assert "/var/run/docker.sock" not in live_block


def test_control_profile_mounts_docker_socket() -> None:
    compose_path = Path(__file__).resolve().parents[1] / "compose.assistant.yml"
    text = compose_path.read_text(encoding="utf-8")
    assert "wicap-assist-control:" in text
    assert "profiles: [\"control\"]" in text
    assert "- /var/run/docker.sock:/var/run/docker.sock" in text
