"""
Wazuh Manager REST API client.

Authentication: JWT tokens obtained via Basic Auth.
Tokens are cached and refreshed automatically on expiry or 401.
"""

from __future__ import annotations

import time

import httpx

from wazuh_mcp.config import Config


class WazuhManagerClient:
    def __init__(self, config: Config) -> None:
        self._base_url = config.manager_url
        self._username = config.manager_username
        self._password = config.manager_password
        self._token_ttl = config.token_ttl_seconds

        self._token: str | None = None
        self._token_expiry: float = 0.0

        self._http = httpx.AsyncClient(
            verify=config.manager_verify_ssl,
            timeout=30.0,
        )

    async def _authenticate(self) -> str:
        resp = await self._http.post(
            f"{self._base_url}/security/user/authenticate",
            auth=(self._username, self._password),
        )
        resp.raise_for_status()
        token: str = resp.json()["data"]["token"]
        self._token = token
        self._token_expiry = time.monotonic() + self._token_ttl
        return token

    async def _get_token(self) -> str:
        if self._token is None or time.monotonic() >= self._token_expiry:
            return await self._authenticate()
        return self._token

    async def request(self, method: str, path: str, **kwargs) -> dict:
        """Make an authenticated request; retries once on 401 with a fresh token."""
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = await self._http.request(
            method, f"{self._base_url}{path}", headers=headers, **kwargs
        )

        if resp.status_code == 401:
            # Token invalidated server-side (e.g. manager restart) — force refresh
            self._token = None
            token = await self._authenticate()
            headers = {"Authorization": f"Bearer {token}"}
            resp = await self._http.request(
                method, f"{self._base_url}{path}", headers=headers, **kwargs
            )

        resp.raise_for_status()
        return resp.json()

    async def get(self, path: str, **kwargs) -> dict:
        return await self.request("GET", path, **kwargs)

    async def aclose(self) -> None:
        await self._http.aclose()
