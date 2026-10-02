"""Tool-level tests: discovery without credentials, gating, and response shapes."""

from __future__ import annotations

import asyncio

from sna_mcp import server
from tests.conftest import SNA_BASE, TENANT_ID, add_login

EXPECTED_TOOLS = {
    "sna_test_connection",
    "sna_list_tenants",
    "sna_get_user_context",
    "sna_list_users",
    "sna_list_host_groups",
    "sna_search_host_groups",
    "sna_get_host_group",
    "sna_query_flows",
    "sna_get_security_events",
    "sna_top_ports",
    "sna_top_conversations",
    "sna_top_hosts",
    "sna_get_cta_incidents",
    "sna_raw_get",
    "sna_get_flow_sources",
    "sna_get_domain_info",
    "sna_list_data_roles",
    "sna_get_host_group_app_traffic",
    "sna_validate_segmentation",
    "ise_anc_test_connection",
    "ise_anc_list_policies",
    "ise_anc_get_policy",
    "ise_anc_list_endpoint_assignments",
    "ise_anc_create_policy",
    "ise_anc_quarantine",
    "ise_anc_clear",
}
MUTATING_TOOLS = {"ise_anc_create_policy", "ise_anc_quarantine", "ise_anc_clear"}


def _tools() -> dict:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_tool_discovery_needs_no_credentials(httpx_mock) -> None:
    assert set(_tools()) >= EXPECTED_TOOLS
    assert httpx_mock.get_requests() == []


def test_mutating_tools_are_labelled_in_descriptions() -> None:
    tools = _tools()
    for name in MUTATING_TOOLS:
        assert "MUTATING" in (tools[name].description or ""), name


def test_gated_tools_fail_soft_without_calling_ise(httpx_mock, wired_server) -> None:
    out = server.ise_anc_quarantine("Quarantine", mac_address="00:11:22:33:44:55")
    assert out["applied"] is False
    assert "ISE_ENABLE_ANC_ACTIONS" in out["error"]
    assert server.ise_anc_clear(ip_address="192.0.2.10")["cleared"] is False
    assert server.ise_anc_create_policy("Quarantine")["created"] is False
    assert httpx_mock.get_requests() == []


def test_ise_test_connection_fails_soft_without_env() -> None:
    server._ise_client = None
    try:
        out = server.ise_anc_test_connection()
    finally:
        server._ise_client = None
    assert out["connected"] is False
    assert "ISE_HOST" in out["error"]


def test_search_host_groups_is_case_insensitive(httpx_mock, wired_server) -> None:
    add_login(httpx_mock)
    httpx_mock.add_response(
        url=f"{SNA_BASE}/smc-configuration/rest/v1/tenants/{TENANT_ID}/tags/",
        json={"data": [{"id": 1, "name": "Machines"}, {"id": 2, "name": "Printers"}]},
    )
    out = server.sna_search_host_groups("MACH")
    assert out["total"] == 1
    assert out["items"] == [{"id": 1, "name": "Machines"}]


def test_raw_get_prefixes_missing_slash(httpx_mock, wired_server) -> None:
    add_login(httpx_mock)
    httpx_mock.add_response(url=f"{SNA_BASE}/smc-users/rest/v1/users", json={"data": []})
    assert server.sna_raw_get("smc-users/rest/v1/users")["status"] == 200


def test_validate_segmentation_builds_query_and_flags_violations(
    httpx_mock, wired_server
) -> None:
    import json

    base = f"{SNA_BASE}/sw-reporting/v2/tenants/{TENANT_ID}/flows/queries"
    add_login(httpx_mock)
    httpx_mock.add_response(method="POST", url=base, json={"data": {"query": {"id": "q9"}}})
    httpx_mock.add_response(url=f"{base}/q9", json={"data": {"query": {"percentComplete": 100}}})
    httpx_mock.add_response(
        url=f"{base}/q9/results", json={"data": {"flows": [{"id": 7}, {"id": 8}]}}
    )

    out = server.sna_validate_segmentation(
        subject_tag_id=10, excluded_peer_tag_ids=[20], excluded_peer_ips=["192.0.2.5"]
    )
    assert out["violation_count"] == 2
    assert out["segmentation_intact"] is False

    submitted = json.loads(
        next(r for r in httpx_mock.get_requests() if r.method == "POST" and r.url.path.endswith("/queries")).content
    )
    assert submitted["subject"] == {"hostGroups": {"includes": [10]}}
    assert submitted["peer"] == {
        "hostGroups": {"excludes": [20]},
        "ipAddresses": {"excludes": ["192.0.2.5"]},
    }
