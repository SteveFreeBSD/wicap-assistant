from wicap_assist.extract.signals import session_gate


def test_gate_passes_for_cwd_prefix() -> None:
    assert session_gate("/home/steve/apps/wicap", None, False, False)


def test_gate_passes_for_repo_url() -> None:
    assert session_gate(None, "https://github.com/SteveFreeBSD/wicap.git", False, False)


def test_gate_passes_for_wicap_text_with_operational_signal() -> None:
    assert session_gate(None, None, True, True)


def test_gate_fails_for_wicap_text_without_operational_signal() -> None:
    assert not session_gate(None, None, True, False)
