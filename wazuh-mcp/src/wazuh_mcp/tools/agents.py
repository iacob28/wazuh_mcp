"""
Agent tools: get_agents.

Uses the Wazuh Manager REST API (port 55000).
"""

from __future__ import annotations

import httpx
from fastmcp import FastMCP

from wazuh_mcp.clients.manager import WazuhManagerClient
from wazuh_mcp.config import Config

_VALID_STATUSES = {"active", "disconnected", "never_connected", "pending"}


def register_agent_tools(
    mcp: FastMCP, client: WazuhManagerClient, config: Config
) -> None:

    @mcp.tool()
    async def get_agents(
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict] | dict:
        """
        List Wazuh agents registered on the manager.

        Args:
            status: Filter by agent status. One of: active, disconnected, never_connected, pending.
                    Omit to return agents of all statuses.
            limit: Number of results to return.
            offset: Pagination offset.
        """
        try:
            if status and status not in _VALID_STATUSES:
                valid = ", ".join(sorted(_VALID_STATUSES))
                return {"error": f"Invalid status '{status}'. Valid values: {valid}"}

            size = min(limit, config.max_limit)
            params: dict = {"limit": size, "offset": offset}
            if status:
                params["status"] = status

            result = await client.get("/agents", params=params)
            items = result.get("data", {}).get("affected_items", [])

            return [
                {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "ip": a.get("ip"),
                    "status": a.get("status"),
                    "os_name": a.get("os", {}).get("name") if a.get("os") else None,
                    "version": a.get("version"),
                    "last_keep_alive": a.get("lastKeepAlive"),
                }
                for a in items
            ]

        except httpx.HTTPStatusError as e:
            return {"error": f"Manager API error {e.response.status_code}: {e.response.text[:300]}"}
        except httpx.ConnectError:
            return {"error": "Cannot connect to Wazuh Manager. Check WAZUH_MANAGER_URL in config.toml."}
        except Exception as e:
            return {"error": f"Unexpected error: {e}"}
