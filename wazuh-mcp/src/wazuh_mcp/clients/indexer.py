"""
Wazuh Indexer client (OpenSearch / Elasticsearch).

Alerts are stored here, not in the Manager REST API.
Authentication: HTTP Basic Auth on every request.
"""

from __future__ import annotations

import httpx

from wazuh_mcp.config import Config


class WazuhIndexerClient:
    def __init__(self, config: Config) -> None:
        self._index = config.alert_index
        self._http = httpx.AsyncClient(
            base_url=config.indexer_url,
            auth=(config.indexer_username, config.indexer_password),
            verify=config.indexer_verify_ssl,
            timeout=30.0,
            headers={"Content-Type": "application/json"},
        )

    async def search(
        self,
        query: dict,
        size: int = 100,
        from_: int = 0,
        sort: list[dict] | None = None,
    ) -> dict:
        """Run an OpenSearch search query and return the raw response dict."""
        payload: dict = {
            "query": query,
            "size": size,
            "from": from_,
            "sort": sort or [{"timestamp": {"order": "desc"}}],
        }
        resp = await self._http.post(f"/{self._index}/_search", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def search_with_aggs(self, query: dict, aggs: dict) -> dict:
        """Run an aggregation-only query (size=0) and return the raw response dict."""
        payload: dict = {"query": query, "size": 0, "aggs": aggs}
        resp = await self._http.post(f"/{self._index}/_search", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._http.aclose()
