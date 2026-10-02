"""ISE ERS API client for Adaptive Network Control (ANC) quarantine actions.

The SNA→ISE quarantine seen in the lab runbooks is executed by ISE, not SNA.
This client talks to the ISE External RESTful Services (ERS) API (TCP 9060,
HTTP Basic auth) to list/get ANC policies, view ANC endpoint assignments, and
(when explicitly enabled) apply or clear a quarantine on an endpoint.

Reference endpoints:
  GET  /ers/config/ancpolicy                 -> list policies
  GET  /ers/config/ancpolicy/name/{name}     -> policy by name
  GET  /ers/config/ancendpoint               -> current ANC assignments
  PUT  /ers/config/ancendpoint/apply         -> quarantine (macAddress|ipAddress + policyName)
  PUT  /ers/config/ancendpoint/clear         -> clear quarantine

No credentials are hardcoded; everything comes from ISEConfig/env vars.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import ISEConfig


class ISEError(RuntimeError):
    """Raised for ISE ERS API errors with a human-readable message."""


class ISEAncClient:
    def __init__(self, config: ISEConfig) -> None:
        self._config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            verify=config.verify_tls,
            timeout=config.timeout,
            auth=(config.username, config.password),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    # --------------------------------------------------------------- core ---
    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        expected: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        try:
            resp = self._client.request(method.upper(), path, json=json)
        except httpx.HTTPError as exc:
            raise ISEError(f"ISE ERS request failed: {exc}") from exc

        if resp.status_code == 401:
            raise ISEError(
                "ISE ERS authentication failed (401). Check ISE_USERNAME/"
                "ISE_PASSWORD and that the account is an ERS Admin."
            )
        if resp.status_code == 404 and method.upper() == "GET":
            return None
        if resp.status_code not in expected:
            raise ISEError(
                f"{method} {path} returned HTTP {resp.status_code}: {resp.text[:400]}"
            )
        if not resp.content:
            return {"status": resp.status_code}
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # -------------------------------------------------------------- reads ---
    def test_connection(self) -> dict[str, Any]:
        body = self._request("GET", "/ers/config/ancpolicy")
        policies = _search_resources(body)
        return {
            "connected": True,
            "base_url": self._config.base_url,
            "anc_actions_enabled": self._config.enable_anc_actions,
            "anc_policy_count": len(policies),
        }

    def list_policies(self) -> list[dict[str, Any]]:
        return _search_resources(self._request("GET", "/ers/config/ancpolicy"))

    def get_policy(self, name: str) -> Any:
        body = self._request("GET", f"/ers/config/ancpolicy/name/{name}")
        if isinstance(body, dict):
            return body.get("ErsAncPolicy", body)
        return body

    def list_endpoint_assignments(self) -> list[dict[str, Any]]:
        return _search_resources(self._request("GET", "/ers/config/ancendpoint"))

    # ------------------------------------------------------------- writes ---
    def _require_actions_enabled(self) -> None:
        if not self._config.enable_anc_actions:
            raise ISEError(
                "ANC actions are disabled. Set ISE_ENABLE_ANC_ACTIONS=true to "
                "allow quarantine/clear operations."
            )

    def _operation_body(
        self, policy_name: str | None, mac: str | None, ip: str | None
    ) -> dict[str, Any]:
        additional: list[dict[str, str]] = []
        if mac:
            additional.append({"name": "macAddress", "value": mac})
        if ip:
            additional.append({"name": "ipAddress", "value": ip})
        if not additional:
            raise ISEError("Provide either mac_address or ip_address.")
        if policy_name:
            additional.append({"name": "policyName", "value": policy_name})
        return {"OperationAdditionalData": {"additionalData": additional}}

    def create_policy(
        self, name: str, action: str = "QUARANTINE"
    ) -> dict[str, Any]:
        """Create an ANC policy. Allowed actions: QUARANTINE, PORTBOUNCE, SHUTDOWN."""
        self._require_actions_enabled()
        body = {"ErsAncPolicy": {"name": name, "actions": [action]}}
        try:
            resp = self._client.request(
                "POST", "/ers/config/ancpolicy", json=body
            )
        except httpx.HTTPError as exc:
            raise ISEError(f"ISE ERS request failed: {exc}") from exc
        if resp.status_code == 401:
            raise ISEError("ISE ERS authentication failed (401).")
        if resp.status_code not in (200, 201):
            raise ISEError(
                f"Create ANC policy returned HTTP {resp.status_code}: "
                f"{resp.text[:400]}"
            )
        location = resp.headers.get("Location")
        policy_id = location.rsplit("/", 1)[-1] if location else None
        return {
            "created": True,
            "name": name,
            "action": action,
            "id": policy_id,
            "location": location,
        }

    def quarantine(
        self,
        policy_name: str,
        mac_address: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        self._require_actions_enabled()
        body = self._operation_body(policy_name, mac_address, ip_address)
        result = self._request(
            "PUT", "/ers/config/ancendpoint/apply", json=body, expected=(200, 204)
        )
        return {
            "applied": True,
            "policy_name": policy_name,
            "mac_address": mac_address,
            "ip_address": ip_address,
            "result": result,
        }

    def clear(
        self,
        policy_name: str | None = None,
        mac_address: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        self._require_actions_enabled()
        body = self._operation_body(policy_name, mac_address, ip_address)
        result = self._request(
            "PUT", "/ers/config/ancendpoint/clear", json=body, expected=(200, 204)
        )
        return {
            "cleared": True,
            "policy_name": policy_name,
            "mac_address": mac_address,
            "ip_address": ip_address,
            "result": result,
        }


def _search_resources(body: Any) -> list[dict[str, Any]]:
    """ERS list responses nest items under SearchResult.resources."""
    if isinstance(body, dict):
        sr = body.get("SearchResult")
        if isinstance(sr, dict) and isinstance(sr.get("resources"), list):
            return sr["resources"]
    if isinstance(body, list):
        return body
    return []
