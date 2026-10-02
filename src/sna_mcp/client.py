"""HTTP client for the Cisco Secure Network Analytics (SNA) REST API.

Implements the specifics learned from Cisco's official DevNet documentation and
sample scripts (CiscoDevNet/stealthwatch-enterprise-sample-scripts):

* Cookie/session based auth via ``POST /token/v2/authenticate`` (form-encoded).
* The XSRF-TOKEN cookie returned on login must be echoed back on every
  non-GET request as the ``X-XSRF-TOKEN`` header (SNA 7.3.2+).
* Sessions expire after ~20 minutes, so we transparently re-authenticate.
* Reporting APIs are asynchronous "query" jobs (submit -> poll -> results),
  and there are two flavours (v1 flow-reports/security-events, v2 flows) with
  slightly different response shapes.

This module is intentionally free of any hardcoded credentials.
"""

from __future__ import annotations

import datetime as _dt
import threading
import time
from typing import Any

import httpx

from .config import SNAConfig

XSRF_COOKIE_NAME = "XSRF-TOKEN"
XSRF_HEADER_NAME = "X-XSRF-TOKEN"
# Sessions expire at 20 min; refresh a little early to be safe.
SESSION_MAX_AGE_SECONDS = 18 * 60


class SNAError(RuntimeError):
    """Raised for SNA API errors with a human-readable message."""


class SNAClient:
    """Thread-safe-ish client wrapping an ``httpx.Client`` session."""

    def __init__(self, config: SNAConfig) -> None:
        self._config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            verify=config.verify_tls,
            timeout=config.timeout,
            follow_redirects=True,
        )
        self._authenticated_at: float | None = None
        self._lock = threading.Lock()
        self._resolved_tenant_id: str | None = config.tenant_id

    # ---------------------------------------------------------------- auth ---
    def _login(self) -> None:
        resp = self._client.post(
            "/token/v2/authenticate",
            data={
                "username": self._config.username,
                "password": self._config.password,
            },
        )
        if resp.status_code != 200:
            raise SNAError(
                f"Authentication failed (HTTP {resp.status_code}). "
                "Check SNA_HOST/SNA_USERNAME/SNA_PASSWORD."
            )

        xsrf = self._client.cookies.get(XSRF_COOKIE_NAME)
        if xsrf:
            self._client.headers[XSRF_HEADER_NAME] = xsrf
        self._authenticated_at = time.monotonic()

    def _ensure_session(self) -> None:
        with self._lock:
            if (
                self._authenticated_at is None
                or (time.monotonic() - self._authenticated_at) > SESSION_MAX_AGE_SECONDS
            ):
                self._login()

    def logout(self) -> None:
        try:
            self._client.delete("/token")
        except httpx.HTTPError:
            pass
        finally:
            self._authenticated_at = None
            self._client.headers.pop(XSRF_HEADER_NAME, None)

    def close(self) -> None:
        self.logout()
        self._client.close()

    # ------------------------------------------------------------- request ---
    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200, 201),
    ) -> Any:
        """Perform an authenticated request and return the parsed JSON body.

        Retries once after re-authenticating if the session appears expired.
        """
        self._ensure_session()
        resp = self._do(method, path, json=json, params=params)
        if resp.status_code in (401, 403):
            # Session likely expired mid-flight; re-auth once and retry.
            with self._lock:
                self._login()
            resp = self._do(method, path, json=json, params=params)

        if resp.status_code not in expected:
            body = resp.text[:500]
            raise SNAError(
                f"{method} {path} returned HTTP {resp.status_code}: {body}"
            )
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    def _do(
        self,
        method: str,
        path: str,
        *,
        json: Any | None,
        params: dict[str, Any] | None,
    ) -> httpx.Response:
        # Some SNA endpoints (e.g. /sw-reporting/v1/tenants/) only advertise a
        # text/plain representation and will reject a strict application/json
        # Accept header with HTTP 406. Send a permissive Accept (like browsers /
        # axios) so the server may respond with text/plain; we still parse the
        # JSON body regardless of the declared content type.
        headers = {"Accept": "application/json, text/plain, */*"}
        if json is not None:
            headers["Content-Type"] = "application/json"
        return self._client.request(
            method.upper(), path, json=json, params=params, headers=headers
        )

    # ------------------------------------------------------- raw discovery ---
    def raw_get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """READ-ONLY GET against an arbitrary API path (for endpoint discovery).

        Does not raise on non-2xx; returns the status code and parsed body so
        callers can probe which endpoints exist on this build. ``{tenantId}`` in
        the path is substituted with the resolved tenant id.
        """
        self._ensure_session()
        if "{tenantId}" in path:
            path = path.replace("{tenantId}", self.tenant_id())
        resp = self._do("GET", path, json=None, params=params)
        if resp.status_code in (401, 403):
            with self._lock:
                self._login()
            resp = self._do("GET", path, json=None, params=params)

        body: Any = None
        if resp.content:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
        content_type = resp.headers.get("content-type", "")
        return {
            "status": resp.status_code,
            "content_type": content_type,
            "path": path,
            "body": body,
        }

    # -------------------------------------------------------------- tenants ---
    def list_tenants(self) -> list[dict[str, Any]]:
        body = self.request("GET", "/sw-reporting/v1/tenants/")
        return _extract_list(body)

    def tenant_id(self) -> str:
        """Return the configured tenant id, or auto-resolve the first one."""
        if self._resolved_tenant_id:
            return self._resolved_tenant_id
        tenants = self.list_tenants()
        if not tenants:
            raise SNAError(
                "No tenants/domains found on this SNA Manager. "
                "Set SNA_TENANT_ID explicitly if you know it."
            )
        tid = str(tenants[0].get("id"))
        self._resolved_tenant_id = tid
        return tid

    # ------------------------------------------------------ generic queries ---
    def _poll_until_done(
        self,
        status_path: str,
        *,
        status_getter,
    ) -> None:
        deadline = time.monotonic() + self._config.poll_timeout
        while True:
            body = self.request("GET", status_path)
            if status_getter(body):
                return
            if time.monotonic() > deadline:
                raise SNAError(f"Query timed out while polling {status_path}")
            time.sleep(self._config.poll_interval)

    def run_v2_flow_query(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """v2 flows: submit -> poll percentComplete==100 -> results.flows."""
        tid = self.tenant_id()
        base = f"/sw-reporting/v2/tenants/{tid}/flows/queries"
        submit = self.request("POST", base, json=body, expected=(200, 201))
        query = submit["data"]["query"]
        query_id = query["id"]
        status_path = f"{base}/{query_id}"

        self._poll_until_done(
            status_path,
            status_getter=lambda b: float(
                b["data"]["query"].get("percentComplete", 0)
            )
            >= 100.0,
        )
        results = self.request("GET", f"{base}/{query_id}/results")
        return results["data"].get("flows", results["data"])

    def run_v1_security_events(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """v1 security-events: submit -> poll -> /results."""
        tid = self.tenant_id()
        submit_path = f"/sw-reporting/v1/tenants/{tid}/security-events/queries"
        submit = self.request("POST", submit_path, json=body)
        search = submit["data"]["searchJob"]
        search_id = search["id"]
        status_path = f"{submit_path}/{search_id}"

        self._poll_until_done(
            status_path,
            status_getter=lambda b: float(b["data"].get("percentComplete", 0)) >= 100.0,
        )
        results = self.request(
            "GET",
            f"/sw-reporting/v1/tenants/{tid}/security-events/results/{search_id}",
        )
        return results["data"].get("results", results["data"])

    def run_v1_flow_report(
        self, report: str, body: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """v1 flow-reports (top-hosts/top-ports/top-conversations).

        submit -> poll status==COMPLETED -> /results/{queryId}
        """
        tid = self.tenant_id()
        base = f"/sw-reporting/v1/tenants/{tid}/flow-reports/{report}"
        submit = self.request("POST", f"{base}/queries", json=body)
        query_id = submit["data"]["queryId"]
        status_path = f"{base}/queries/{query_id}"

        self._poll_until_done(
            status_path,
            status_getter=lambda b: str(b["data"].get("status")) == "COMPLETED",
        )
        results = self.request("GET", f"{base}/results/{query_id}")
        return results["data"].get("results", results["data"])

    # ------------------------------------------------- config / users / cta ---
    def list_host_groups(self) -> list[dict[str, Any]]:
        tid = self.tenant_id()
        body = self.request(
            "GET", f"/smc-configuration/rest/v1/tenants/{tid}/tags/"
        )
        return _extract_list(body)

    def get_host_group(self, tag_id: str | int) -> Any:
        tid = self.tenant_id()
        body = self.request(
            "GET", f"/smc-configuration/rest/v1/tenants/{tid}/tags/{tag_id}"
        )
        return body.get("data", body) if isinstance(body, dict) else body

    def list_users(self) -> list[dict[str, Any]]:
        body = self.request("GET", "/smc-users/rest/v1/users")
        return _extract_list(body)

    def user_context(self) -> Any:
        body = self.request("GET", "/smc-users/rest/v1/user-context")
        return body.get("data", body) if isinstance(body, dict) else body

    def get_cta_incidents(self, ip_address: str) -> Any:
        # CTA/Cognitive incidents are reported under tenant 0 regardless of domain.
        body = self.request(
            "GET",
            "/sw-reporting/v2/tenants/0/incidents",
            params={"ipAddress": ip_address},
        )
        return body.get("data", body) if isinstance(body, dict) else body

    # ------------------------------------------- inventory / config (read) ---
    def get_flow_sources(self) -> list[dict[str, Any]]:
        """Flow exporters/sources feeding this tenant (telemetry health)."""
        tid = self.tenant_id()
        body = self.request(
            "GET", f"/smc-configuration/rest/v1/tenants/{tid}/exporters"
        )
        return _extract_list(body)

    def get_domain_info(self) -> Any:
        """Domain/tenant metadata (name, dataStoreType, resetHour, asNumbers)."""
        tid = self.tenant_id()
        body = self.request("GET", f"/smc-configuration/rest/v1/tenants/{tid}")
        return body.get("data", body) if isinstance(body, dict) else body

    def list_data_roles(self) -> list[dict[str, Any]]:
        """Data-role catalog (e.g. All Data Read-Only / Read-Write)."""
        body = self.request("GET", "/smc-users/rest/v1/roles/data-roles")
        return _extract_list(body)

    def get_host_group_app_traffic(
        self, tag_id: int, minutes: int = 60
    ) -> list[dict[str, Any]]:
        """Application traffic for hosts in a host group over the last N minutes.

        Uses the synchronous 'raw' filtered-traffic endpoint (no job polling).
        """
        tid = self.tenant_id()
        start_relative_ms = int(minutes) * 60 * 1000
        body = self.request(
            "GET",
            f"/sw-reporting/v1/tenants/{tid}/internalHosts/tags/{tag_id}"
            "/applications/traffic/raw",
            params={"filter[startRelative]": start_relative_ms},
        )
        return _extract_list(body)


# --------------------------------------------------------------- helpers ---
def _extract_list(body: Any) -> list[dict[str, Any]]:
    """SNA usually nests list payloads under a ``data`` key."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        data = body.get("data", body)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Some endpoints nest one level deeper (e.g. {"data": {"tags": [...]}}).
            for value in data.values():
                if isinstance(value, list):
                    return value
            return [data]
    return []


def utc_window(minutes: int, *, microseconds: bool = False) -> tuple[str, str]:
    """Return (start, end) ISO timestamps for the last ``minutes`` minutes.

    ``microseconds=True`` produces the ``...T%H:%M:%S.000`` form required by the
    v1 flow-report endpoints; otherwise the ``...Z`` form used elsewhere.
    """
    end = _dt.datetime.now(_dt.timezone.utc)
    start = end - _dt.timedelta(minutes=minutes)
    if microseconds:
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        return start.strftime(fmt), end.strftime(fmt)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return start.strftime(fmt), end.strftime(fmt)
