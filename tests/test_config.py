from __future__ import annotations

from pathlib import Path

import pytest

from sna_mcp.config import ISEConfig, SNAConfig, load_dotenv


def _set_sna_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SNA_HOST", "sna.example.com")
    monkeypatch.setenv("SNA_USERNAME", "test-user")
    monkeypatch.setenv("SNA_PASSWORD", "test-password")


def test_sna_from_env_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_sna_env(monkeypatch)
    cfg = SNAConfig.from_env()
    assert cfg.base_url == "https://sna.example.com"
    assert cfg.tenant_id is None
    assert cfg.verify_tls is False
    assert cfg.timeout == 30.0
    assert cfg.poll_timeout == 300.0


def test_sna_missing_vars_are_named_without_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SNA_HOST", "sna.example.com")
    with pytest.raises(RuntimeError) as exc:
        SNAConfig.from_env()
    msg = str(exc.value)
    assert "SNA_USERNAME" in msg and "SNA_PASSWORD" in msg
    assert "sna.example.com" not in msg


def test_sna_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_sna_env(monkeypatch)
    monkeypatch.setenv("SNA_TENANT_ID", "202")
    monkeypatch.setenv("SNA_VERIFY_TLS", "yes")
    monkeypatch.setenv("SNA_TIMEOUT", "5")
    cfg = SNAConfig.from_env()
    assert cfg.tenant_id == "202"
    assert cfg.verify_tls is True
    assert cfg.timeout == 5.0


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("sna.example.com", "https://sna.example.com"),
        ("https://sna.example.com/", "https://sna.example.com"),
        ("http://sna.example.com", "http://sna.example.com"),
    ],
)
def test_sna_base_url(host: str, expected: str) -> None:
    assert SNAConfig(host=host, username="u", password="p").base_url == expected


def test_ise_actions_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ISE_HOST", "ise.example.com")
    monkeypatch.setenv("ISE_USERNAME", "ers-admin")
    monkeypatch.setenv("ISE_PASSWORD", "test-password")
    cfg = ISEConfig.from_env()
    assert cfg.enable_anc_actions is False
    assert cfg.base_url == "https://ise.example.com:9060"


def test_ise_actions_enabled_only_when_opted_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ISE_HOST", "ise.example.com")
    monkeypatch.setenv("ISE_USERNAME", "ers-admin")
    monkeypatch.setenv("ISE_PASSWORD", "test-password")
    monkeypatch.setenv("ISE_ENABLE_ANC_ACTIONS", "true")
    assert ISEConfig.from_env().enable_anc_actions is True


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("ise.example.com", "https://ise.example.com:9060"),
        ("https://ise.example.com", "https://ise.example.com:9060"),
        ("https://ise.example.com:9443", "https://ise.example.com:9443"),
    ],
)
def test_ise_base_url(host: str, expected: str) -> None:
    assert ISEConfig(host=host, username="u", password="p").base_url == expected


def test_ise_missing_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError, match="ISE_HOST"):
        ISEConfig.from_env()


def test_load_dotenv_parses_and_never_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\n"
        "\n"
        "export SNA_HOST=sna.example.com\n"
        'SNA_USERNAME="quoted-user"\n'
        "SNA_PASSWORD='from-file'\n"
        "NOT_A_PAIR\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SNA_PASSWORD", "from-shell")

    assert load_dotenv(str(env_file)) == env_file

    import os

    assert os.environ["SNA_HOST"] == "sna.example.com"
    assert os.environ["SNA_USERNAME"] == "quoted-user"
    assert os.environ["SNA_PASSWORD"] == "from-shell"
    assert "NOT_A_PAIR" not in os.environ
