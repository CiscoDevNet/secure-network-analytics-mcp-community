# Cisco Secure Network Analytics MCP Server (Community)

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent connect to and
query a **Cisco Secure Network Analytics (SNA)** deployment — formerly Stealthwatch
Enterprise — over its REST API.

Tested against SNA Manager **7.6.0**.

## What it does

All **SNA tools are read-only**. They cover connectivity checks, flow/security-event
queries, top-N reports, host groups, users, and CTA incidents. An optional ISE ANC
module (below) can quarantine endpoints; its mutating tools are **disabled by
default** and only run when `ISE_ENABLE_ANC_ACTIONS=true`.

| Tool | Purpose | SNA endpoint(s) |
| --- | --- | --- |
| `sna_test_connection` | Auth + sanity check | `POST /token/v2/authenticate`, `GET /smc-users/rest/v1/user-context`, `GET /sw-reporting/v1/tenants/` |
| `sna_list_tenants` | List tenants/domains | `GET /sw-reporting/v1/tenants/` |
| `sna_get_user_context` | Current API user + roles | `GET /smc-users/rest/v1/user-context` |
| `sna_list_users` | All Manager users | `GET /smc-users/rest/v1/users` |
| `sna_list_host_groups` | Host groups (tags) | `GET /smc-configuration/rest/v1/tenants/{t}/tags/` |
| `sna_get_host_group` | One host group by id | `GET .../tags/{id}` |
| `sna_query_flows` | Flow records (async) | `POST/GET /sw-reporting/v2/tenants/{t}/flows/queries` |
| `sna_get_security_events` | Security events for a host (async) | `POST/GET /sw-reporting/v1/.../security-events/...` |
| `sna_top_ports` | Top ports (async) | `.../flow-reports/top-ports/...` |
| `sna_top_conversations` | Top conversations (async) | `.../flow-reports/top-conversations/...` |
| `sna_top_hosts` | Top hosts (async) | `.../flow-reports/top-hosts/...` |
| `sna_get_cta_incidents` | Cognitive/Threat Analytics incidents | `GET /sw-reporting/v2/tenants/0/incidents?ipAddress=` |
| `sna_get_flow_sources` | Flow exporters/sources (telemetry health) | `GET /smc-configuration/rest/v1/tenants/{t}/exporters` |
| `sna_get_domain_info` | Domain metadata incl. `dataStoreType` | `GET /smc-configuration/rest/v1/tenants/{t}` |
| `sna_list_data_roles` | Data-role catalog | `GET /smc-users/rest/v1/roles/data-roles` |
| `sna_get_host_group_app_traffic` | Host-group application traffic (segmentation) | `GET /sw-reporting/v1/tenants/{t}/internalHosts/tags/{id}/applications/traffic/raw` |
| `sna_search_host_groups` | Find host groups by name substring | (client-side filter over tags) |
| `sna_validate_segmentation` | Flows from a host group to non-allowed peers | `POST /sw-reporting/v2/tenants/{t}/flows/queries` (hostGroups include/exclude) |
| `sna_raw_get` | Read-only discovery GET to any path | (any) |

### ISE ANC quarantine module (`ise_anc_*`)
The SNA→ISE **Adaptive Network Control (ANC)** quarantine is **not exposed by
SNA's REST API** (in SNA it's configured under Configure → Response Management
and executed internally over pxGrid). Programmatic quarantine lives on **ISE's
ERS API** (TCP 9060, Basic auth). This server includes a small ISE ANC module so
you can complete the detect→quarantine chain:

| Tool | Purpose | ISE ERS endpoint |
| --- | --- | --- |
| `ise_anc_test_connection` | Verify ERS reachability/auth | `GET /ers/config/ancpolicy` |
| `ise_anc_list_policies` | List ANC policies | `GET /ers/config/ancpolicy` |
| `ise_anc_get_policy` | Get a policy by name | `GET /ers/config/ancpolicy/name/{name}` |
| `ise_anc_list_endpoint_assignments` | Current ANC assignments | `GET /ers/config/ancendpoint` |
| `ise_anc_create_policy` | Create an ANC policy (**gated**) | `POST /ers/config/ancpolicy` |
| `ise_anc_quarantine` | Apply ANC to an endpoint (**gated**) | `PUT /ers/config/ancendpoint/apply` |
| `ise_anc_clear` | Clear ANC from an endpoint (**gated**) | `PUT /ers/config/ancendpoint/clear` |

Requirements: ERS enabled in ISE (Administration → System → Settings → ERS
Settings) and an **ERS Admin** account. The mutating `quarantine`/`clear` tools
only run when `ISE_ENABLE_ANC_ACTIONS=true`; reads work without it.

### Notes on the SNA API
- **Auth is cookie/session based** (not bearer). Login returns `stealthwatch.jwt`
  and `XSRF-TOKEN` cookies; the XSRF value must be echoed as `X-XSRF-TOKEN` on
  every non-GET request (SNA 7.3.2+). Sessions expire after ~20 min — the client
  re-authenticates automatically.
- **Reporting is asynchronous**: submit a query, poll for completion, then fetch
  results. The client handles both the v1 (`status == COMPLETED` / `percentComplete`)
  and v2 (`percentComplete`) flavours.
- SNA Managers ship a **self-signed TLS cert**; `SNA_VERIFY_TLS` defaults to
  `false` for lab use. Enable it (with a proper CA/cert) for production.
- On deployments with a **Data Store** (`dataStoreType: CDS`, see
  `sna_get_domain_info`), the legacy **SOAP** API (e.g. host snapshot) is **not
  supported**, so this server uses REST endpoints exclusively.

## Output shaping (keeps results readable)

List-returning tools (flows, top-N reports, security events, host-group traffic,
flow sources, host groups, users) accept two optional args:

- `max_items` (default 50) — caps how many items are returned to you.
- `fields` — a list of dot-path field names to project, e.g.
  `["subject.ipAddress", "peer.ipAddress", "statistics.byteCount"]`.

They return an envelope so you always know if data was truncated:

```json
{ "total": 1234, "returned": 50, "truncated": true, "items": [ ... ] }
```

## Setup

```bash
git clone https://github.com/CiscoDevNet/secure-network-analytics-mcp-community.git
cd secure-network-analytics-mcp-community
python3 -m venv .venv && source .venv/bin/activate
pip install -e .        # add ".[dev]" for tests
cp .env.example .env    # then fill in your SNA (and optional ISE) credentials
```

The server auto-loads `.env` from the project root (or `$SNA_ENV_FILE`), and
real environment variables always take precedence.

## Configuration

All settings come from environment variables (never hardcoded):

| Var | Required | Default | Description |
| --- | --- | --- | --- |
| `SNA_HOST` | yes | — | Manager IP/host (e.g. `sna-manager.example.com`) |
| `SNA_USERNAME` | yes | — | API username (ideally a dedicated read-only API user) |
| `SNA_PASSWORD` | yes | — | API password |
| `SNA_TENANT_ID` | no | first tenant | Pin a tenant/domain id |
| `SNA_VERIFY_TLS` | no | `false` | TLS cert verification |
| `SNA_TIMEOUT` | no | `30` | HTTP timeout (s) |
| `SNA_POLL_INTERVAL` | no | `1` | Async poll interval (s) |
| `SNA_POLL_TIMEOUT` | no | `300` | Async poll timeout (s) |

## Run

```bash
# stdio transport (how MCP clients launch it)
sna-mcp
# or
python -m sna_mcp
```

## Register in Cursor

Add to your MCP config (e.g. `~/.cursor/mcp.json`), pointing at the venv python.
Keep credentials in `.env` rather than in the MCP config file:

```json
{
  "mcpServers": {
    "sna": {
      "command": "/path/to/secure-network-analytics-mcp-community/.venv/bin/python",
      "args": ["-m", "sna_mcp"]
    }
  }
}
```

## Tests

All tests are offline (HTTP is mocked with `pytest-httpx`); no SNA or ISE
system is needed. They include checks that the mutating ISE ANC tools refuse to
run unless `ISE_ENABLE_ANC_ACTIONS=true`.

```bash
pip install -e ".[dev]"
pytest
```

## References
- Cisco DevNet: <https://developer.cisco.com/docs/stealthwatch/enterprise/>
- Sample scripts: <https://github.com/CiscoDevNet/stealthwatch-enterprise-sample-scripts>

## Contributing, security, and license

- Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) and the
  [Code of Conduct](./CODE_OF_CONDUCT.md).
- Please report security issues privately as described in [SECURITY.md](./SECURITY.md).
- Licensed under the [Apache License 2.0](./LICENSE).
