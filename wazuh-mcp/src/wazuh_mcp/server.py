"""
Wazuh MCP server entrypoint.

Wires together config, clients, and tools into a FastMCP application.
Transport: stdio (works for both standalone and Docker MCP gateway).
"""

from __future__ import annotations

from fastmcp import FastMCP

from wazuh_mcp.clients.indexer import WazuhIndexerClient
from wazuh_mcp.clients.manager import WazuhManagerClient
from wazuh_mcp.config import Config
from wazuh_mcp.tools.agents import register_agent_tools
from wazuh_mcp.tools.alerts import register_alert_tools

config = Config()

manager_client = WazuhManagerClient(config)
indexer_client = WazuhIndexerClient(config)

mcp = FastMCP(
    name="wazuh-mcp",
    instructions=(
        "Query Wazuh SIEM data. "
        "Use get_alerts or search_alerts to retrieve security alerts from the Wazuh Indexer. "
        "Use get_alert_summary for aggregated statistics. "
        "Use get_agents to list monitored endpoints."
    ),
)

register_alert_tools(mcp, indexer_client, config)
register_agent_tools(mcp, manager_client, config)


def main() -> None:
    mcp.run(transport="stdio")
