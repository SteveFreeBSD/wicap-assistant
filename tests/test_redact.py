from wicap_assist.util.redact import redact_text, to_snippet


def test_redact_common_secret_patterns() -> None:
    source = (
        "password=hunter2 token:abc123 api_key=xyz789 "
        "Authorization: Bearer verysecrettoken"
    )
    redacted = redact_text(source)

    assert "hunter2" not in redacted
    assert "abc123" not in redacted
    assert "xyz789" not in redacted
    assert "verysecrettoken" not in redacted
    assert redacted.count("<redacted>") >= 3


def test_to_snippet_respects_max_len() -> None:
    text = "a" * 600
    snippet = to_snippet(text, max_len=200)
    assert len(snippet) == 200
