"""ISE ANC tests. The gate tests are the safety contract for the mutating tools."""

from __future__ import annotations

import json

import pytest

from sna_mcp.ise_client import ISEAncClient, ISEError
from tests.conftest import ISE_BASE

POLICY_LIST = {
    "SearchResult": {"total": 1, "resources": [{"id": "p1", "name": "Quarantine"}]}
}


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        ("quarantine", {"policy_name": "Quarantine", "mac_address": "00:11:22:33:44:55"}),
        ("clear", {"policy_name": "Quarantine", "ip_address": "192.0.2.10"}),
        ("create_policy", {"name": "Quarantine"}),
    ],
)
def test_mutating_actions_blocked_when_disabled(
    httpx_mock, ise_readonly: ISEAncClient, method: str, kwargs: dict
) -> None:
    with pytest.raises(ISEError, match="ISE_ENABLE_ANC_ACTIONS"):
        getattr(ise_readonly, method)(**kwargs)
    assert httpx_mock.get_requests() == []


def test_reads_work_while_actions_disabled(httpx_mock, ise_readonly: ISEAncClient) -> None:
    httpx_mock.add_response(url=f"{ISE_BASE}/ers/config/ancpolicy", json=POLICY_LIST)
    assert ise_readonly.list_policies() == [{"id": "p1", "name": "Quarantine"}]


def test_test_connection_reports_gate_state(httpx_mock, ise_readonly: ISEAncClient) -> None:
    httpx_mock.add_response(url=f"{ISE_BASE}/ers/config/ancpolicy", json=POLICY_LIST)
    out = ise_readonly.test_connection()
    assert out == {
        "connected": True,
        "base_url": ISE_BASE,
        "anc_actions_enabled": False,
        "anc_policy_count": 1,
    }


def test_quarantine_payload_when_enabled(httpx_mock, ise_actions_enabled: ISEAncClient) -> None:
    httpx_mock.add_response(
        method="PUT", url=f"{ISE_BASE}/ers/config/ancendpoint/apply", status_code=204
    )
    out = ise_actions_enabled.quarantine("Quarantine", mac_address="00:11:22:33:44:55")
    assert out["applied"] is True

    sent = json.loads(httpx_mock.get_requests()[0].content)
    assert sent == {
        "OperationAdditionalData": {
            "additionalData": [
                {"name": "macAddress", "value": "00:11:22:33:44:55"},
                {"name": "policyName", "value": "Quarantine"},
            ]
        }
    }


def test_quarantine_requires_mac_or_ip(httpx_mock, ise_actions_enabled: ISEAncClient) -> None:
    with pytest.raises(ISEError, match="mac_address or ip_address"):
        ise_actions_enabled.quarantine("Quarantine")
    assert httpx_mock.get_requests() == []


def test_create_policy_returns_id_from_location(
    httpx_mock, ise_actions_enabled: ISEAncClient
) -> None:
    httpx_mock.add_response(
        method="POST",
        url=f"{ISE_BASE}/ers/config/ancpolicy",
        status_code=201,
        headers={"Location": f"{ISE_BASE}/ers/config/ancpolicy/abc-123"},
    )
    out = ise_actions_enabled.create_policy("Quarantine")
    assert out["created"] is True
    assert out["id"] == "abc-123"


def test_get_missing_policy_returns_none(httpx_mock, ise_readonly: ISEAncClient) -> None:
    httpx_mock.add_response(url=f"{ISE_BASE}/ers/config/ancpolicy/name/Nope", status_code=404)
    assert ise_readonly.get_policy("Nope") is None


def test_auth_failure_is_actionable(httpx_mock, ise_readonly: ISEAncClient) -> None:
    httpx_mock.add_response(url=f"{ISE_BASE}/ers/config/ancpolicy", status_code=401)
    with pytest.raises(ISEError, match="ERS Admin") as exc:
        ise_readonly.list_policies()
    assert "test-password" not in str(exc.value)
