from __future__ import annotations

from pathlib import Path

from wicap_assist.cli import main
from wicap_assist.wicap_env_setup import load_env_entries


def _patch_prompts(
    monkeypatch,
    *,
    input_values: list[str],
    secret_values: list[str],
) -> None:
    input_iter = iter(input_values)
    secret_iter = iter(secret_values)

    def fake_input(prompt: str = "") -> str:
        try:
            return next(input_iter)
        except StopIteration as exc:  # pragma: no cover - defensive
            raise AssertionError(f"Unexpected input prompt: {prompt}") from exc

    def fake_getpass(prompt: str = "") -> str:
        try:
            return next(secret_iter)
        except StopIteration as exc:  # pragma: no cover - defensive
            raise AssertionError(f"Unexpected secret prompt: {prompt}") from exc

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr("wicap_assist.wicap_env_setup.getpass.getpass", fake_getpass)


def _create_repo_root(tmp_path: Path) -> Path:
    repo_root = tmp_path / "wicap"
    repo_root.mkdir(parents=True, exist_ok=True)
    (repo_root / ".env.example").write_text(
        "\n".join(
            [
                "# WiCAP example",
                "WICAP_SQL_PASSWORD=your_sql_password_here",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return repo_root


def test_setup_wicap_env_creates_wicap_dotenv(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    _patch_prompts(
        monkeypatch,
        input_values=[
            "10.10.0.25",
            "OpsDB",
            "ops_user",
            "",
            "yes",
            "true",
            "",
            "",
            "wlan0",
            "",
            "false",
            "disabled",
            "y",
        ],
        secret_values=[
            "supersecure-pass-123",
            "internal-secret-123",
        ],
    )

    rc = main(["setup-wicap-env", "--repo-root", str(repo_root)])
    assert rc == 0

    entries = load_env_entries(repo_root / ".env")
    assert entries["WICAP_SQL_HOST"] == "10.10.0.25"
    assert entries["WICAP_SQL_SERVER"] == "10.10.0.25"
    assert entries["WICAP_SQL_DATABASE"] == "OpsDB"
    assert entries["WICAP_SQL_USER"] == "ops_user"
    assert entries["WICAP_SQL_USERNAME"] == "ops_user"
    assert entries["WICAP_SQL_PASSWORD"] == "supersecure-pass-123"
    assert entries["WICAP_INTERNAL_SECRET"] == "internal-secret-123"
    assert entries["WICAP_OTLP_PROFILE"] == "disabled"


def test_setup_wicap_env_keeps_existing_values_on_blank_input(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    env_path = repo_root / ".env"
    env_path.write_text(
        "\n".join(
            [
                "WICAP_SQL_HOST=old-host",
                "WICAP_SQL_SERVER=old-host",
                "WICAP_SQL_DATABASE=OldDB",
                "WICAP_SQL_USER=old_user",
                "WICAP_SQL_USERNAME=old_user",
                "WICAP_SQL_PASSWORD=old-password-123",
                "WICAP_INTERNAL_SECRET=old-internal-123",
                "CUSTOM_KEEP=1",
                "",
            ]
        ),
        encoding="utf-8",
    )

    _patch_prompts(
        monkeypatch,
        input_values=[
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
        ],
        secret_values=["", ""],
    )

    rc = main(["setup-wicap-env", "--repo-root", str(repo_root)])
    assert rc == 0

    entries = load_env_entries(env_path)
    assert entries["WICAP_SQL_HOST"] == "old-host"
    assert entries["WICAP_SQL_DATABASE"] == "OldDB"
    assert entries["WICAP_SQL_PASSWORD"] == "old-password-123"
    assert entries["WICAP_INTERNAL_SECRET"] == "old-internal-123"
    assert entries["CUSTOM_KEEP"] == "1"


def test_setup_wicap_env_reprompts_short_sql_password(tmp_path: Path, monkeypatch) -> None:
    repo_root = _create_repo_root(tmp_path)
    _patch_prompts(
        monkeypatch,
        input_values=[
            "",
            "NetOps",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "y",
        ],
        secret_values=[
            "short",
            "long-enough-password",
            "another-internal-secret",
        ],
    )

    rc = main(["setup-wicap-env", "--repo-root", str(repo_root)])
    assert rc == 0

    entries = load_env_entries(repo_root / ".env")
    assert entries["WICAP_SQL_PASSWORD"] == "long-enough-password"
    assert entries["WICAP_SQL_DATABASE"] == "NetOps"
