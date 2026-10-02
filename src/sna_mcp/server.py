"""FastMCP server exposing read-only Cisco Secure Network Analytics tools.

Scope: read-only (per project decision). Write operations (create/update host
groups, create users) are intentionally omitted from this iteration.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from .client import SNAClient, SNAError, utc_window
from .config import ISEConfig, SNAConfig
from .ise_client import ISEAncClient, ISEError
from .shaping import DEFAULT_MAX_ITEMS, shape_list

mcp = MCPServer("sna-mcp")

_client: SNAClient | None = None
_ise_client: ISEAncClient | None = None


def _get_client() -> SNAClient:
    """Lazily build the client so tool discovery works without env vars set."""
    global _client
    if _client is None:
        _client = SNAClient(SNAConfig.from_env())
    return _client


def _get_ise_client() -> ISEAncClient:
    """Lazily build the ISE ANC client (only needed by ise_anc_* tools)."""
    global _ise_client
    if _ise_client is None:
        _ise_client = ISEAncClient(ISEConfig.from_env())
    return _ise_client


def _subject_filter(ip_address: str | None) -> dict[str, Any]:
    if not ip_address:
        return {}
    return {"subject": {"ipAddresses": {"includes": [ip_address]}}}


# --------------------------------------------------------------- tools ---
@mcp.tool()
def sna_test_connection() -> dict[str, Any]:
    """Authenticate to the SNA Manager and confirm connectivity.

    Returns the current user context and the list of available tenants/domains.
    Use this first to verify the lab is reachable and credentials are valid.
    """
    client = _get_client()
    try:
        user = client.user_context()
        tenants = client.list_tenants()
        return {
            "connected": True,
            "base_url": client._config.base_url,  # noqa: SLF001
            "user_context": user,
            "tenants": tenants,
            "resolved_tenant_id": client.tenant_id(),
        }
    except SNAError as exc:
        return {"connected": False, "error": str(exc)}


@mcp.tool()
def sna_list_tenants() -> list[dict[str, Any]]:
    """List tenants/domains configured on the SNA Manager."""
    return _get_client().list_tenants()


@mcp.tool()
def sna_get_user_context() -> Any:
    """Get the user context (username, roles, permissions) for the API user."""
    return _get_client().user_context()


@mcp.tool()
def sna_list_users(
    max_items: int = DEFAULT_MAX_ITEMS, fields: list[str] | None = None
) -> dict[str, Any]:
    """List all configured SNA Manager users.

    Args:
        max_items: Cap on returned users (default 50).
        fields: Optional dot-path fields to keep per user (e.g. ["userName"]).
    """
    return shape_list(_get_client().list_users(), max_items, fields)


@mcp.tool()
def sna_list_host_groups(
    max_items: int = DEFAULT_MAX_ITEMS, fields: list[str] | None = None
) -> dict[str, Any]:
    """List host groups (a.k.a. tags) for the tenant.

    Args:
        max_items: Cap on returned host groups (default 50).
        fields: Optional dot-path fields to keep (e.g. ["id", "name"]).
    """
    return shape_list(_get_client().list_host_groups(), max_items, fields)


@mcp.tool()
def sna_search_host_groups(
    name_contains: str,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Search host groups by name substring (case-insensitive).

    This tenant can have hundreds of host groups, so use this instead of
    listing them all when you know part of the name.

    Args:
        name_contains: Case-insensitive substring to match against the name.
        max_items: Cap on returned matches (default 50).
        fields: Optional dot-path fields to keep (e.g. ["id", "name"]).
    """
    needle = name_contains.strip().lower()
    matches = [
        hg
        for hg in _get_client().list_host_groups()
        if isinstance(hg, dict) and needle in str(hg.get("name", "")).lower()
    ]
    return shape_list(matches, max_items, fields)


@mcp.tool()
def sna_get_host_group(tag_id: int) -> Any:
    """Get the full definition of a single host group (tag) by its numeric id."""
    return _get_client().get_host_group(tag_id)


@mcp.tool()
def sna_query_flows(
    ip_address: str | None = None,
    peer_ip: str | None = None,
    minutes: int = 60,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 50,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Query network flows (async v2 flow query).

    Args:
        ip_address: Optional subject IP to filter on.
        peer_ip: Optional peer/other-side IP to filter on.
        minutes: Relative look-back window in minutes (default 60). Ignored if
            both start_time and end_time are given.
        start_time: Absolute start (ISO 8601, e.g. '2026-09-09T08:00:00Z').
        end_time: Absolute end (ISO 8601). Use with start_time for a fixed range.
        limit: Max flow records to request from SNA (server-side, default 50).
        max_items: Cap on records returned to you (client-side, default 50).
        fields: Optional dot-path fields to keep per flow, e.g.
            ["subject.ipAddress", "peer.ipAddress", "statistics.byteCount"].
    """
    if start_time and end_time:
        start, end = start_time, end_time
    else:
        start, end = utc_window(minutes)
    body: dict[str, Any] = {
        "startDateTime": start,
        "endDateTime": end,
        "recordLimit": limit,
    }
    if ip_address:
        body["subject"] = {"ipAddresses": {"includes": [ip_address]}}
    if peer_ip:
        body["peer"] = {"ipAddresses": {"includes": [peer_ip]}}
    return shape_list(_get_client().run_v2_flow_query(body), max_items, fields)


@mcp.tool()
def sna_get_security_events(
    ip_address: str,
    minutes: int = 60,
    direction: str = "source",
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Get security events for a host over the last N minutes (async v1 query).

    Args:
        ip_address: The host IP to query security events for.
        minutes: Look-back window in minutes (default 60).
        direction: 'source' or 'target' (how the host participates).
        max_items: Cap on returned events (default 50).
        fields: Optional dot-path fields to keep per event.
    """
    start, end = utc_window(minutes)
    body = {
        "timeRange": {"from": start, "to": end},
        "hosts": [{"ipAddress": ip_address, "type": direction}],
    }
    return shape_list(_get_client().run_v1_security_events(body), max_items, fields)


@mcp.tool()
def sna_top_ports(
    ip_address: str,
    minutes: int = 60,
    max_rows: int = 50,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Top ports report for a host over the last N minutes (async v1 report)."""
    start, end = utc_window(minutes, microseconds=True)
    body: dict[str, Any] = {"startTime": start, "endTime": end, "maxRows": max_rows}
    body.update(_subject_filter(ip_address))
    return shape_list(
        _get_client().run_v1_flow_report("top-ports", body), max_items, fields
    )


@mcp.tool()
def sna_top_conversations(
    ip_address: str,
    minutes: int = 60,
    max_rows: int = 50,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Top conversations report for a host over the last N minutes (v1 report)."""
    start, end = utc_window(minutes, microseconds=True)
    body: dict[str, Any] = {"startTime": start, "endTime": end, "maxRows": max_rows}
    body.update(_subject_filter(ip_address))
    return shape_list(
        _get_client().run_v1_flow_report("top-conversations", body),
        max_items,
        fields,
    )


@mcp.tool()
def sna_top_hosts(
    ip_address: str | None = None,
    minutes: int = 60,
    max_rows: int = 50,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Top hosts (by traffic) report over the last N minutes (async v1 report)."""
    start, end = utc_window(minutes, microseconds=True)
    body: dict[str, Any] = {"startTime": start, "endTime": end, "maxRows": max_rows}
    body.update(_subject_filter(ip_address))
    return shape_list(
        _get_client().run_v1_flow_report("top-hosts", body), max_items, fields
    )


@mcp.tool()
def sna_get_cta_incidents(ip_address: str) -> Any:
    """Get Cognitive/Threat Analytics (CTA) incidents for a specific IP."""
    return _get_client().get_cta_incidents(ip_address)


@mcp.tool()
def sna_raw_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """READ-ONLY discovery helper: issue a raw GET to any SNA API path.

    Only GET is permitted (safe for exploration). Use the literal token
    '{tenantId}' anywhere in the path to have it replaced with the current
    tenant id. Does not raise on 404/406/etc.; returns the HTTP status,
    content type, resolved path, and parsed body so you can discover which
    endpoints exist on this SNA build.

    Examples:
        path='/sw-reporting/v2/tenants/{tenantId}/devices'
        path='/smc-configuration/rest/v1/tenants/{tenantId}/tags/'
    """
    if not path.startswith("/"):
        path = "/" + path
    return _get_client().raw_get(path, params=params)


@mcp.tool()
def sna_get_flow_sources(
    max_items: int = DEFAULT_MAX_ITEMS, fields: list[str] | None = None
) -> dict[str, Any]:
    """List flow exporters/sources feeding this tenant (telemetry health check).

    Each entry includes the collector (swaName), exporter IP, optional DNS name,
    and type (e.g. 'exporter' or 'firewall'). Use this to confirm which devices
    are actually sending NetFlow to Secure Network Analytics.

    Args:
        max_items: Cap on returned exporters (default 50).
        fields: Optional dot-path fields to keep (e.g. ["ipAddress", "type"]).
    """
    return shape_list(_get_client().get_flow_sources(), max_items, fields)


@mcp.tool()
def sna_get_domain_info() -> Any:
    """Get domain/tenant metadata (name, dataStoreType, resetHour, asNumbers)."""
    return _get_client().get_domain_info()


@mcp.tool()
def sna_list_data_roles() -> list[dict[str, Any]]:
    """List the data-role catalog (e.g. All Data Read-Only / Read-Write)."""
    return _get_client().list_data_roles()


@mcp.tool()
def sna_get_host_group_app_traffic(
    tag_id: int,
    minutes: int = 60,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Application traffic for hosts in a host group over the last N minutes.

    Supports the segmentation-validation use case ("what are the hosts in this
    group actually talking to?"). Synchronous (no job polling).

    Args:
        tag_id: Numeric host-group (tag) id — see sna_list_host_groups.
        minutes: Look-back window in minutes (default 60).
        max_items: Cap on returned rows (default 50).
        fields: Optional dot-path fields to keep per row.
    """
    return shape_list(
        _get_client().get_host_group_app_traffic(tag_id, minutes), max_items, fields
    )


@mcp.tool()
def sna_validate_segmentation(
    subject_tag_id: int,
    excluded_peer_tag_ids: list[int] | None = None,
    excluded_peer_ips: list[str] | None = None,
    minutes: int = 1440,
    limit: int = 100,
    max_items: int = DEFAULT_MAX_ITEMS,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Validate network segmentation for a host group (Story Guide Scenario 2).

    Finds flows where the subject host group communicated with anything OTHER
    than its allowed peers. If nothing is returned, segmentation is holding; any
    returned flows are potential policy violations.

    Example: subject = 'Machines', excluded peers = ['ControlSystems'] → any
    remaining flow means a machine talked to something outside ControlSystems.

    Args:
        subject_tag_id: Host-group (tag) id to protect/validate.
        excluded_peer_tag_ids: Allowed peer host-group ids to exclude.
        excluded_peer_ips: Additional allowed peer IPs to exclude.
        minutes: Look-back window in minutes (default 1440 = 24h).
        limit: Max flow records to request from SNA (server-side).
        max_items: Cap on violating flows returned to you.
        fields: Optional dot-path fields to keep per flow.
    """
    start, end = utc_window(minutes)
    body: dict[str, Any] = {
        "startDateTime": start,
        "endDateTime": end,
        "recordLimit": limit,
        "subject": {"hostGroups": {"includes": [subject_tag_id]}},
    }
    peer: dict[str, Any] = {}
    if excluded_peer_tag_ids:
        peer["hostGroups"] = {"excludes": excluded_peer_tag_ids}
    if excluded_peer_ips:
        peer["ipAddresses"] = {"excludes": excluded_peer_ips}
    if peer:
        body["peer"] = peer

    flows = _get_client().run_v2_flow_query(body)
    envelope = shape_list(flows, max_items, fields)
    total = envelope["total"] if isinstance(envelope, dict) else len(flows)
    return {
        "subject_host_group_id": subject_tag_id,
        "excluded_peer_host_group_ids": excluded_peer_tag_ids or [],
        "excluded_peer_ips": excluded_peer_ips or [],
        "window_minutes": minutes,
        "violation_count": total,
        "segmentation_intact": total == 0,
        "violations": envelope,
    }


# ------------------------------------------------------- ISE ANC tools ---
# ANC (quarantine) is an ISE ERS capability, not SNA. These tools complete the
# SNA-detect -> ISE-quarantine chain. Reads are always available; the mutating
# quarantine/clear actions require ISE_ENABLE_ANC_ACTIONS=true.
@mcp.tool()
def ise_anc_test_connection() -> dict[str, Any]:
    """Verify the ISE ERS API is reachable and credentials are valid.

    Returns policy count and whether mutating ANC actions are enabled.
    """
    try:
        return _get_ise_client().test_connection()
    except (ISEError, RuntimeError) as exc:
        return {"connected": False, "error": str(exc)}


@mcp.tool()
def ise_anc_list_policies(
    max_items: int = DEFAULT_MAX_ITEMS, fields: list[str] | None = None
) -> dict[str, Any]:
    """List ISE Adaptive Network Control (ANC) policies (e.g. 'Quarantine')."""
    return shape_list(_get_ise_client().list_policies(), max_items, fields)


@mcp.tool()
def ise_anc_get_policy(name: str) -> Any:
    """Get an ISE ANC policy by name (shows its action, e.g. QUARANTINE)."""
    return _get_ise_client().get_policy(name)


@mcp.tool()
def ise_anc_list_endpoint_assignments(
    max_items: int = DEFAULT_MAX_ITEMS, fields: list[str] | None = None
) -> dict[str, Any]:
    """List endpoints that currently have an ANC policy applied."""
    return shape_list(
        _get_ise_client().list_endpoint_assignments(), max_items, fields
    )


@mcp.tool()
def ise_anc_create_policy(name: str, action: str = "QUARANTINE") -> dict[str, Any]:
    """Create an ISE ANC policy (MUTATING; gated).

    Requires ISE_ENABLE_ANC_ACTIONS=true. Use this to create the 'Quarantine'
    policy the runbooks rely on. Allowed actions: QUARANTINE, PORTBOUNCE,
    SHUTDOWN.
    """
    try:
        return _get_ise_client().create_policy(name, action)
    except (ISEError, RuntimeError) as exc:
        return {"created": False, "error": str(exc)}


@mcp.tool()
def ise_anc_quarantine(
    policy_name: str,
    mac_address: str | None = None,
    ip_address: str | None = None,
) -> dict[str, Any]:
    """Apply an ANC policy to quarantine an endpoint (MUTATING; gated).

    Requires ISE_ENABLE_ANC_ACTIONS=true. Provide either mac_address or
    ip_address plus the ANC policy_name (see ise_anc_list_policies).
    """
    try:
        return _get_ise_client().quarantine(policy_name, mac_address, ip_address)
    except (ISEError, RuntimeError) as exc:
        return {"applied": False, "error": str(exc)}


@mcp.tool()
def ise_anc_clear(
    policy_name: str | None = None,
    mac_address: str | None = None,
    ip_address: str | None = None,
) -> dict[str, Any]:
    """Clear an ANC policy from an endpoint (MUTATING; gated).

    Requires ISE_ENABLE_ANC_ACTIONS=true. Provide either mac_address or
    ip_address (policy_name optional depending on ISE version).
    """
    try:
        return _get_ise_client().clear(policy_name, mac_address, ip_address)
    except (ISEError, RuntimeError) as exc:
        return {"cleared": False, "error": str(exc)}


def run() -> None:
    """Run the MCP server over stdio."""
    mcp.run()
