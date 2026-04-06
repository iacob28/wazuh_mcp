"""
Alert tools: get_alerts, search_alerts, get_alert_summary.

All alerts are queried from the Wazuh Indexer (OpenSearch) — NOT from the Manager API.
"""

from __future__ import annotations

import httpx
from fastmcp import FastMCP

from wazuh_mcp.clients.indexer import WazuhIndexerClient
from wazuh_mcp.config import Config

# Valid time range suffixes and their OpenSearch date-math equivalents
_TIME_RANGE_MAP: dict[str, str] = {
    "15m": "now-15m",
    "1h": "now-1h",
    "6h": "now-6h",
    "12h": "now-12h",
    "24h": "now-24h",
    "2d": "now-2d",
    "7d": "now-7d",
    "14d": "now-14d",
    "30d": "now-30d",
}


def _parse_time_range(time_range: str) -> str:
    """Convert a human-readable time range to an OpenSearch date-math string."""
    key = time_range.lower().strip()
    if key not in _TIME_RANGE_MAP:
        valid = ", ".join(_TIME_RANGE_MAP.keys())
        raise ValueError(f"Invalid time_range '{time_range}'. Valid values: {valid}")
    return _TIME_RANGE_MAP[key]


def _time_filter(time_range: str) -> dict:
    """Build an OpenSearch range filter on the timestamp field."""
    gte = _parse_time_range(time_range)
    return {"range": {"timestamp": {"gte": gte, "lte": "now"}}}


def _extract_alert(hit: dict) -> dict:
    """Flatten a raw OpenSearch hit into a clean alert dict."""
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    return {
        "id": hit.get("_id"),
        "timestamp": src.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "location": src.get("location"),
        "full_log": src.get("full_log"),
    }


def register_alert_tools(
    mcp: FastMCP, client: WazuhIndexerClient, config: Config
) -> None:

    @mcp.tool()
    async def get_alerts(
        time_range: str = "24h",
        min_level: int = 0,
        agent_name: str | None = None,
        rule_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict] | dict:
        """
        Retrieve Wazuh alerts with optional filters.

        Args:
            time_range: Lookback window. One of: 15m, 1h, 6h, 12h, 24h, 2d, 7d, 14d, 30d.
            min_level: Minimum Wazuh rule severity level (0–16).
            agent_name: Filter by exact agent name.
            rule_id: Filter by rule ID.
            limit: Number of results to return (max enforced by server config).
            offset: Pagination offset.
        """
        try:
            size = min(limit, config.max_limit)
            filters: list[dict] = [_time_filter(time_range)]

            if min_level > 0:
                filters.append({"range": {"rule.level": {"gte": min_level}}})
            if agent_name:
                filters.append({"term": {"agent.name": agent_name}})
            if rule_id:
                filters.append({"term": {"rule.id": rule_id}})

            query = {"bool": {"filter": filters}}
            result = await client.search(query, size=size, from_=offset)
            hits = result.get("hits", {}).get("hits", [])
            return [_extract_alert(h) for h in hits]

        except ValueError as e:
            return {"error": str(e)}
        except httpx.HTTPStatusError as e:
            return {"error": f"Indexer API error {e.response.status_code}: {e.response.text[:300]}"}
        except httpx.ConnectError:
            return {"error": "Cannot connect to Wazuh Indexer. Check WAZUH_INDEXER_URL in config.toml."}
        except Exception as e:
            return {"error": f"Unexpected error: {e}"}

    @mcp.tool()
    async def search_alerts(
        query: str,
        time_range: str = "24h",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict] | dict:
        """
        Full-text search across Wazuh alert fields.

        Args:
            query: Search string. Matched against log content, rule description, agent name, and data fields.
            time_range: Lookback window. One of: 15m, 1h, 6h, 12h, 24h, 2d, 7d, 14d, 30d.
            limit: Number of results to return.
            offset: Pagination offset.
        """
        try:
            size = min(limit, config.max_limit)
            os_query = {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query,
                                "fields": [
                                    "full_log",
                                    "rule.description",
                                    "agent.name",
                                    "data.*",
                                    "location",
                                ],
                                "type": "best_fields",
                            }
                        }
                    ],
                    "filter": [_time_filter(time_range)],
                }
            }
            result = await client.search(os_query, size=size, from_=offset)
            hits = result.get("hits", {}).get("hits", [])
            return [_extract_alert(h) for h in hits]

        except ValueError as e:
            return {"error": str(e)}
        except httpx.HTTPStatusError as e:
            return {"error": f"Indexer API error {e.response.status_code}: {e.response.text[:300]}"}
        except httpx.ConnectError:
            return {"error": "Cannot connect to Wazuh Indexer. Check WAZUH_INDEXER_URL in config.toml."}
        except Exception as e:
            return {"error": f"Unexpected error: {e}"}

    @mcp.tool()
    async def get_alert_summary(
        time_range: str = "24h",
    ) -> dict:
        """
        Aggregate Wazuh alerts — total count, distribution by severity level,
        top triggered rules, and most active agents.

        Args:
            time_range: Lookback window. One of: 15m, 1h, 6h, 12h, 24h, 2d, 7d, 14d, 30d.
        """
        try:
            query = {"bool": {"filter": [_time_filter(time_range)]}}
            aggs = {
                "by_level": {
                    "terms": {"field": "rule.level", "size": 17}
                },
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 20},
                    "aggs": {
                        "rule_desc": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description"],
                            }
                        }
                    },
                },
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 20}
                },
            }

            result = await client.search_with_aggs(query, aggs)
            total = result.get("hits", {}).get("total", {}).get("value", 0)
            buckets = result.get("aggregations", {})

            by_level = {
                str(b["key"]): b["doc_count"]
                for b in buckets.get("by_level", {}).get("buckets", [])
            }

            top_rules = []
            for b in buckets.get("by_rule", {}).get("buckets", []):
                hits = b.get("rule_desc", {}).get("hits", {}).get("hits", [])
                desc = ""
                if hits:
                    desc = hits[0].get("_source", {}).get("rule", {}).get("description", "")
                top_rules.append({
                    "rule_id": str(b["key"]),
                    "description": desc,
                    "count": b["doc_count"],
                })

            top_agents = [
                {"agent_name": b["key"], "count": b["doc_count"]}
                for b in buckets.get("by_agent", {}).get("buckets", [])
            ]

            return {
                "time_range": time_range,
                "total_alerts": total,
                "by_level": by_level,
                "top_rules": top_rules,
                "top_agents": top_agents,
            }

        except ValueError as e:
            return {"error": str(e)}
        except httpx.HTTPStatusError as e:
            return {"error": f"Indexer API error {e.response.status_code}: {e.response.text[:300]}"}
        except httpx.ConnectError:
            return {"error": "Cannot connect to Wazuh Indexer. Check WAZUH_INDEXER_URL in config.toml."}
        except Exception as e:
            return {"error": f"Unexpected error: {e}"}
