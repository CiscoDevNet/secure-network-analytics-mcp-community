"""Shared test fixtures.

Every test is hermetic: no ``SNA_*`` / ``ISE_*`` variable from the developer's
real shell or ``.env`` file leaks in, and all HTTP goes through the
``pytest-httpx`` mock transport (no network, no real credentials).
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from sna_mcp import config as config_module
from sna_mcp import server
from sna_mcp.client import SNAClient
from sna_mcp.config import ISEConfig, SNAConfig
from sna_mcp.ise_client import ISEAncClient

SNA_BASE = "https://sna.example.com"
ISE_BASE = "https://ise.example.com:9060"
TENANT_ID = "101"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip real SNA/ISE env and stop ``from_env`` from reading a local .env."""
    for key in list(os.environ):
        if key.startswith(("SNA_", "ISE_")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(config_module, "load_dotenv", lambda *a, **k: None)


@pytest.fixture
def sna_config() -> SNAConfig:
    return SNAConfig(
        host="sna.example.com",
        username="test-user",
        password="test-password",
        tenant_id=TENANT_ID,
        poll_interval=0,
        poll_timeout=2,
    )


@pytest.fixture
def sna_client(sna_config: SNAConfig) -> Iterator[SNAClient]:
    client = SNAClient(sna_config)
    yield client
    client._client.close()


def ise_config(*, enable_anc_actions: bool) -> ISEConfig:
    return ISEConfig(
        host="ise.example.com",
        username="ers-admin",
        password="test-password",
        enable_anc_actions=enable_anc_actions,
    )


@pytest.fixture
def ise_readonly() -> Iterator[ISEAncClient]:
    client = ISEAncClient(ise_config(enable_anc_actions=False))
    yield client
    client.close()


@pytest.fixture
def ise_actions_enabled() -> Iterator[ISEAncClient]:
    client = ISEAncClient(ise_config(enable_anc_actions=True))
    yield client
    client.close()


@pytest.fixture
def wired_server(
    monkeypatch: pytest.MonkeyPatch, sna_client: SNAClient, ise_readonly: ISEAncClient
) -> None:
    """Point the server's lazy singletons at the mocked clients."""
    monkeypatch.setattr(server, "_client", sna_client)
    monkeypatch.setattr(server, "_ise_client", ise_readonly)


def add_login(httpx_mock, xsrf: str = "xsrf-123") -> None:
    httpx_mock.add_response(
        method="POST",
        url=f"{SNA_BASE}/token/v2/authenticate",
        headers={"Set-Cookie": f"XSRF-TOKEN={xsrf}; Path=/"},
    )
