"""Minimal Wazuh client.

Wazuh has two APIs we use:

  * Wazuh server API (default port 55000) - manager info and agents.
    Login: POST /security/user/authenticate with HTTP Basic auth -> a JWT,
    then send "Authorization: Bearer <token>" on later calls.
  * Wazuh indexer (OpenSearch, default port 9200) - where alerts are stored,
    in indices named wazuh-alerts-*. Queried with the OpenSearch _search API.

TLS: the Wazuh OVA uses a self-signed certificate. The SAFE fix is to point
WAZUH_CA_CERT at the Wazuh root CA file so the certificate is verified.
Setting WAZUH_VERIFY_TLS=false also works in an isolated lab, but then a
machine-in-the-middle could read the credentials - the status page warns.
"""

from datetime import datetime

import httpx

from app.core.config import Settings

TIMEOUT = httpx.Timeout(10.0, connect=5.0)


class WazuhError(RuntimeError):
    """Error with a message that is safe to show (never contains credentials)."""


class WazuhClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.s = settings
        verify: bool | str = settings.wazuh_ca_cert or settings.wazuh_verify_tls
        self.http = httpx.Client(timeout=TIMEOUT, verify=verify, transport=transport)
        self._token: str | None = None

    def close(self) -> None:
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------ helpers
    def _request(self, method: str, url: str, what: str, **kwargs) -> dict:
        try:
            resp = self.http.request(method, url, **kwargs)
        except httpx.ConnectError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                raise WazuhError(f"{what}: TLS certificate not trusted. Set WAZUH_CA_CERT to the Wazuh root CA "
                                 "(or WAZUH_VERIFY_TLS=false in an isolated lab).") from None
            raise WazuhError(f"{what}: cannot connect ({url.split('/')[2]}). Is the Wazuh VM running?") from None
        except httpx.TimeoutException:
            raise WazuhError(f"{what}: connection timed out.") from None
        except httpx.HTTPError as exc:
            raise WazuhError(f"{what}: {exc.__class__.__name__}") from None
        if resp.status_code in (401, 403):
            raise WazuhError(f"{what}: authentication failed (check username/password in .env).")
        if resp.status_code >= 400:
            raise WazuhError(f"{what}: HTTP {resp.status_code}.")
        try:
            return resp.json()
        except ValueError:
            raise WazuhError(f"{what}: unexpected non-JSON response.") from None

    def _api(self, method: str, path: str, **kwargs) -> dict:
        if not self.s.wazuh_api_url:
            raise WazuhError("Wazuh server API is not configured (WAZUH_API_URL).")
        if self._token is None:
            data = self._request("POST", f"{self.s.wazuh_api_url}/security/user/authenticate", "Wazuh API login",
                                 auth=(self.s.wazuh_api_user, self.s.wazuh_api_password))
            self._token = data.get("data", {}).get("token")
            if not self._token:
                raise WazuhError("Wazuh API login: no token in response.")
        return self._request(method, f"{self.s.wazuh_api_url}{path}", "Wazuh API",
                             headers={"Authorization": f"Bearer {self._token}"}, **kwargs)

    # ------------------------------------------------------------ public
    def manager_info(self) -> dict:
        items = self._api("GET", "/manager/info").get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    def agents(self, limit: int = 200) -> list[dict]:
        params = {"limit": limit, "select": "id,name,ip,status,os.name,version,lastKeepAlive"}
        return self._api("GET", "/agents", params=params).get("data", {}).get("affected_items", [])

    def search_alerts(self, since: datetime, min_level: int, size: int = 500) -> list[dict]:
        if not self.s.wazuh_indexer_url:
            raise WazuhError("Wazuh indexer is not configured (WAZUH_INDEXER_URL).")
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": [
                {"range": {"rule.level": {"gte": min_level}}},
                {"range": {"timestamp": {"gt": since.isoformat()}}},
            ]}},
        }
        data = self._request("POST", f"{self.s.wazuh_indexer_url}/wazuh-alerts-*/_search", "Wazuh indexer",
                             json=query, auth=(self.s.wazuh_indexer_user, self.s.wazuh_indexer_password))
        return data.get("hits", {}).get("hits", [])
