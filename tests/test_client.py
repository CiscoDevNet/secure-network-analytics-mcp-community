from __future__ import annotations

import time

import pytest

from sna_mcp.client import SESSION_MAX_AGE_SECONDS, SNAClient, SNAError
from sna_mcp.config import SNAConfig
from tests.conftest import SNA_BASE, TENANT_ID, add_login

USER_CONTEXT = f"{SNA_BASE}/smc-users/rest/v1/user-context"


def test_login_sends_form_and_echoes_xsrf_on_writes(httpx_mock, sna_client: SNAClient) -> None:
    add_login(httpx_mock, xsrf="xsrf-abc")
    httpx_mock.add_response(method="POST", url=f"{SNA_BASE}/some/write", json={"ok": True})

    assert sna_client.request("POST", "/some/write", json={"a": 1}) == {"ok": True}

    login, write = httpx_mock.get_requests()
    assert login.headers["content-type"] == "application/x-www-form-urlencoded"
    assert b"username=test-user" in login.content
    assert write.headers["X-XSRF-TOKEN"] == "xsrf-abc"


def test_login_failure_does_not_leak_password(httpx_mock, sna_client: SNAClient) -> None:
    httpx_mock.add_response(
        method="POST", url=f"{SNA_BASE}/token/v2/authenticate", status_code=401
    )
    with pytest.raises(SNAError) as exc:
        sna_client.request("GET", "/smc-users/rest/v1/user-context")
    assert "HTTP 401" in str(exc.value)
    assert "test-password" not in str(exc.value)


def test_session_reused_within_max_age(httpx_mock, sna_client: SNAClient) -> None:
    add_login(httpx_mock)
    httpx_mock.add_response(url=USER_CONTEXT, json={"data": {}}, is_reusable=True)

    sna_client.request("GET", "/smc-users/rest/v1/user-context")
    sna_client.request("GET", "/smc-users/rest/v1/user-context")

    logins = [r for r in httpx_mock.get_requests() if r.url.path == "/token/v2/authenticate"]
    assert len(logins) == 1


def test_expired_session_triggers_relogin(httpx_mock, sna_client: SNAClient) -> None:
    add_login(httpx_mock)
    add_login(httpx_mock)
    httpx_mock.add_response(url=USER_CONTEXT, json={"data": {}}, is_reusable=True)

    sna_client.request("GET", "/smc-users/rest/v1/user-context")
    sna_client._authenticated_at = time.monotonic() - SESSION_MAX_AGE_SECONDS - 1
    sna_client.request("GET", "/smc-users/rest/v1/user-context")

    logins = [r for r in httpx_mock.get_requests() if r.url.path == "/token/v2/authenticate"]
    assert len(logins) == 2


def test_401_mid_session_reauths_and_retries_once(httpx_mock, sna_client: SNAClient) -> None:
    add_login(httpx_mock)
    add_login(httpx_mock)
    httpx_mock.add_response(url=USER_CONTEXT, status_code=401)
    httpx_mock.add_response(url=USER_CONTEXT, json={"data": {"user": "ok"}})

    assert sna_client.request("GET", "/smc-users/rest/v1/user-context") == {
        "data": {"user": "ok"}
    }


def test_unexpected_status_raises_sna_error(httpx_mock, sna_client: SNAClient) -> None:
    add_login(httpx_mock)
    httpx_mock.add_response(url=USER_CONTEXT, status_code=500, text="boom")
    with pytest.raises(SNAError, match="HTTP 500: boom"):
        sna_client.request("GET", "/smc-users/rest/v1/user-context")


def test_tenant_id_auto_resolves_first_tenant(httpx_mock) -> None:
    client = SNAClient(SNAConfig(host="sna.example.com", username="u", password="p"))
    add_login(httpx_mock)
    httpx_mock.add_response(
        url=f"{SNA_BASE}/sw-reporting/v1/tenants/",
        json={"data": [{"id": 303, "displayName": "Lab"}, {"id": 404}]},
    )
    assert client.tenant_id() == "303"
    assert client.tenant_id() == "303"
    client._client.close()


def test_tenant_id_errors_when_none_found(httpx_mock) -> None:
    client = SNAClient(SNAConfig(host="sna.example.com", username="u", password="p"))
    add_login(httpx_mock)
    httpx_mock.add_response(url=f"{SNA_BASE}/sw-reporting/v1/tenants/", json={"data": []})
    with pytest.raises(SNAError, match="No tenants"):
        client.tenant_id()
    client._client.close()


def test_v2_flow_query_polls_until_complete(httpx_mock, sna_client: SNAClient) -> None:
    base = f"{SNA_BASE}/sw-reporting/v2/tenants/{TENANT_ID}/flows/queries"
    add_login(httpx_mock)
    httpx_mock.add_response(method="POST", url=base, json={"data": {"query": {"id": "q1"}}})
    httpx_mock.add_response(url=f"{base}/q1", json={"data": {"query": {"percentComplete": 40}}})
    httpx_mock.add_response(url=f"{base}/q1", json={"data": {"query": {"percentComplete": 100}}})
    httpx_mock.add_response(url=f"{base}/q1/results", json={"data": {"flows": [{"id": 1}]}})

    assert sna_client.run_v2_flow_query({"recordLimit": 10}) == [{"id": 1}]


def test_poll_timeout_raises(httpx_mock, sna_config: SNAConfig) -> None:
    from dataclasses import replace

    client = SNAClient(replace(sna_config, poll_timeout=0))
    base = f"{SNA_BASE}/sw-reporting/v2/tenants/{TENANT_ID}/flows/queries"
    add_login(httpx_mock)
    httpx_mock.add_response(method="POST", url=base, json={"data": {"query": {"id": "q1"}}})
    httpx_mock.add_response(
        url=f"{base}/q1", json={"data": {"query": {"percentComplete": 10}}}, is_reusable=True
    )
    with pytest.raises(SNAError, match="timed out"):
        client.run_v2_flow_query({})
    client._client.close()


def test_raw_get_substitutes_tenant_and_never_raises(httpx_mock, sna_client: SNAClient) -> None:
    add_login(httpx_mock)
    httpx_mock.add_response(
        url=f"{SNA_BASE}/sw-reporting/v2/tenants/{TENANT_ID}/devices",
        status_code=404,
        json={"error": "not here"},
    )
    out = sna_client.raw_get("/sw-reporting/v2/tenants/{tenantId}/devices")
    assert out["status"] == 404
    assert out["path"] == f"/sw-reporting/v2/tenants/{TENANT_ID}/devices"
    assert out["body"] == {"error": "not here"}


@pytest.mark.parametrize("path", ["//evil.example.net/steal", "/https://evil.example.net/x"])
def test_raw_get_stays_on_configured_host(httpx_mock, sna_client: SNAClient, path: str) -> None:
    add_login(httpx_mock)
    httpx_mock.add_response(method="GET", status_code=404)
    sna_client.raw_get(path)
    sent = httpx_mock.get_requests()[-1]
    assert sent.url.host == "sna.example.com"
