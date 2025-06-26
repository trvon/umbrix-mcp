#!/usr/bin/env python3
"""
Umbrix MCP Server
Provides threat intelligence capabilities to AI assistants via MCP protocol
"""

import os
import sys
import json
import logging
from typing import Optional
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
from mcp.server.fastmcp import FastMCP, Context

# Configure logging - send to stderr to avoid interfering with MCP stdio
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("umbrix-mcp")

# Environment configuration
UMBRIX_API_KEY = os.getenv("UMBRIX_API_KEY")
UMBRIX_API_BASE_URL = os.getenv("UMBRIX_API_BASE_URL", "https://umbrix.dev/api")


@dataclass
class AppContext:
    """Application context with HTTP client"""

    client: httpx.AsyncClient


class UmbrixClient:
    """HTTP client for Umbrix API"""

    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(
            headers=self.headers,
            timeout=30.0,
        )

    # All API calls now go through the backend tool execution system
    # Individual method implementations removed to prevent confusion

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


# Global client instance
umbrix_client: Optional[UmbrixClient] = None


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle"""
    global umbrix_client

    if not UMBRIX_API_KEY:
        logger.error("UMBRIX_API_KEY environment variable is required")
        sys.exit(1)

    logger.info("Starting Umbrix MCP server...")
    logger.info(f"API URL: {UMBRIX_API_BASE_URL}")

    # Initialize the client
    umbrix_client = UmbrixClient(UMBRIX_API_KEY, UMBRIX_API_BASE_URL)

    try:
        yield AppContext(client=umbrix_client.client)
    finally:
        # Cleanup
        if umbrix_client:
            await umbrix_client.close()


# Create MCP server instance with lifecycle management
mcp = FastMCP("umbrix-mcp", lifespan=app_lifespan)


@mcp.tool()
async def search_threats(query: str, ctx: Context, limit: int = 10) -> str:
    """Search for threat intelligence across all data sources

    Args:
        query: Search query (threat actor, campaign, malware, etc.)
        limit: Maximum number of results to return (default: 10)
    """
    try:
        logger.info(f"Searching threats: {query}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": f"Search for threats related to: {query}",
                "query_type": "natural_language",
                "max_results": limit,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            answer = data.get("answer", "No results found")
            graph_results = data.get("graph_results", [])

            summary = f"Threat Intelligence Search Results:\n\n{answer}"

            if graph_results:
                summary += "\n\nRelevant Threats Found:"
                for i, item in enumerate(graph_results[:limit], 1):
                    summary += f"\n{i}. {item}"

            return summary
        else:
            return f"Error: {result.get('message', 'Search failed')}"
    except Exception as e:
        logger.error(f"Error searching threats: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def analyze_indicator(
    indicator: str, ctx: Context, indicator_type: str = "auto"
) -> str:
    """Analyze an indicator of compromise (IP, domain, hash, etc.)

    Args:
        indicator: The indicator to analyze (e.g., IP address, domain, file hash)
        indicator_type: Type of indicator (ip, domain, hash, url, email, auto)
    """
    try:
        logger.info(f"Analyzing indicator: {indicator}")

        # Auto-detect indicator type if needed
        if indicator_type == "auto":
            if "." in indicator and not indicator.replace(".", "").isdigit():
                indicator_type = "domain"
            elif indicator.replace(".", "").isdigit():
                indicator_type = "ip"
            elif len(indicator) in [32, 40, 64]:
                indicator_type = "hash"
            else:
                indicator_type = "unknown"

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/get_indicator_details",
            json={
                "indicator_value": indicator,
                "indicator_type": indicator_type,
                "include_context": True,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            indicator_info = data.get("indicator_info", {})
            threat_context = data.get("threat_context", {})

            summary = f"Indicator Analysis: {indicator}\n"
            summary += f"Type: {indicator_type.upper()}\n\n"

            if indicator_info:
                summary += f"Status: {indicator_info.get('status', 'Unknown')}\n"
                summary += (
                    f"Risk Level: {indicator_info.get('risk_level', 'Unknown')}\n"
                )
                if indicator_info.get("first_seen"):
                    summary += f"First Seen: {indicator_info.get('first_seen')}\n"
                if indicator_info.get("last_seen"):
                    summary += f"Last Seen: {indicator_info.get('last_seen')}\n"

            if threat_context:
                summary += f"\nThreat Context:\n{threat_context.get('description', 'No additional context')}"

            return summary
        else:
            return f"Error: {result.get('error', 'Indicator analysis failed')}"
    except Exception as e:
        logger.error(f"Error analyzing indicator: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_threat_actor(actor_name: str, ctx: Context) -> str:
    """Get detailed information about a specific threat actor

    Args:
        actor_name: Name of the threat actor (e.g., APT28, Lazarus Group)
    """
    try:
        logger.info(f"Getting threat actor: {actor_name}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/campaign_analysis",
            json={
                "campaign_or_actor": actor_name,
                "analysis_type": "threat_actor",
                "include_infrastructure": True,
                "include_tactics": True,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("success"):
            data = result.get("data", {})
            actor_info = data.get("actor_info", {})
            infrastructure = data.get("infrastructure", [])
            tactics = data.get("tactics", [])

            summary = f"Threat Actor Analysis: {actor_name}\n\n"

            if actor_info:
                summary += f"Name: {actor_info.get('name', actor_name)}\n"
                if actor_info.get("aliases"):
                    summary += f"Aliases: {', '.join(actor_info.get('aliases', []))}\n"
                if actor_info.get("country"):
                    summary += f"Origin: {actor_info.get('country')}\n"
                if actor_info.get("first_seen"):
                    summary += f"First Seen: {actor_info.get('first_seen')}\n"
                if actor_info.get("description"):
                    summary += f"\nDescription: {actor_info.get('description')}\n"

            if infrastructure:
                summary += f"\nKnown Infrastructure ({len(infrastructure)} items):\n"
                for i, infra in enumerate(infrastructure[:5], 1):  # Show first 5
                    summary += f"  {i}. {infra}\n"
                if len(infrastructure) > 5:
                    summary += f"  ... and {len(infrastructure) - 5} more\n"

            if tactics:
                summary += "\nTactics & Techniques:\n"
                for tactic in tactics[:5]:  # Show first 5
                    summary += f"  • {tactic}\n"
                if len(tactics) > 5:
                    summary += f"  ... and {len(tactics) - 5} more\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Threat actor analysis failed')}"
    except Exception as e:
        logger.error(f"Error getting threat actor: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def visualize_threat_graph(query: str, ctx: Context) -> str:
    """Generate a graph visualization of threat relationships

    Args:
        query: Graph query (e.g., 'APT28 infrastructure', 'ransomware connections')
    """
    try:
        logger.info(f"Visualizing threat graph: {query}")

        # Convert natural language query to graph query
        cypher_query = f"MATCH (n)-[r]-(m) WHERE n.name CONTAINS '{query}' OR m.name CONTAINS '{query}' RETURN n, r, m LIMIT 20"

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/graph_query",
            json={"cypher_query": cypher_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("success"):
            data = result.get("data", {})
            results = data.get("results", [])

            if not results:
                return f"No graph relationships found for query: {query}"

            summary = f"Graph Visualization Results for: {query}\n\n"
            summary += f"Found {len(results)} relationships:\n\n"

            # Group and format the relationships
            relationships = []
            nodes = set()

            for result_item in results[:10]:  # Limit to first 10
                if isinstance(result_item, dict):
                    # Extract node and relationship information
                    for key, value in result_item.items():
                        if isinstance(value, dict):
                            if "name" in value:
                                nodes.add(value["name"])
                            elif "type" in value:
                                relationships.append(value.get("type", "RELATED"))

            summary += f"Key Nodes ({len(nodes)} total):\n"
            for i, node in enumerate(list(nodes)[:8], 1):  # Show first 8 nodes
                summary += f"  {i}. {node}\n"

            if relationships:
                unique_relationships = list(set(relationships))
                summary += "\nRelationship Types:\n"
                for rel_type in unique_relationships[:5]:
                    summary += f"  • {rel_type}\n"

            summary += "\nNote: Use the graph visualization interface at /visualize.html for interactive exploration."
            summary += f"\nCypher query used: {cypher_query}"

            return summary
        else:
            return f"Error: {result.get('error', 'Graph visualization failed')}"
    except Exception as e:
        logger.error(f"Error visualizing threat graph: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def quick_ioc_check(ioc: str, ctx: Context) -> str:
    """Quickly check if an IoC is known to be malicious

    Args:
        ioc: Indicator of compromise to check
    """
    try:
        logger.info(f"Quick IoC check: {ioc}")

        # Auto-detect indicator type
        indicator_type = "unknown"
        if "." in ioc and not ioc.replace(".", "").replace(":", "").isdigit():
            indicator_type = "domain"
        elif ioc.replace(".", "").replace(":", "").isdigit():
            indicator_type = "ip"
        elif len(ioc) in [32, 40, 64] and all(
            c in "0123456789abcdefABCDEF" for c in ioc
        ):
            indicator_type = "hash"
        elif ioc.startswith(("http://", "https://")):
            indicator_type = "url"
        elif "@" in ioc:
            indicator_type = "email"

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/indicator_lookup",
            json={
                "indicator": ioc,
                "indicator_type": indicator_type,
                "include_context": True,
                "quick_check": True,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("success"):
            data = result.get("data", {})
            indicator_info = data.get("indicator_info", {})
            threat_context = data.get("threat_context", {})

            # Determine malicious status
            risk_level = indicator_info.get("risk_level", "unknown").lower()
            status = indicator_info.get("status", "unknown").lower()

            if risk_level in ["high", "critical"] or status in [
                "malicious",
                "suspicious",
            ]:
                status_emoji = "🚨 MALICIOUS"
            elif risk_level in ["medium"] or status in ["flagged"]:
                status_emoji = "⚠️ SUSPICIOUS"
            elif risk_level in ["low"] or status in ["clean", "safe"]:
                status_emoji = "✅ CLEAN"
            else:
                status_emoji = "❓ UNKNOWN"

            confidence = indicator_info.get("confidence", 0)
            if isinstance(confidence, (int, float)):
                confidence_str = f"{confidence}%"
            else:
                confidence_str = "Unknown"

            summary = f"""IoC Quick Check Result: {status_emoji}
            
Indicator: {ioc}
Type: {indicator_type.upper()}
Risk Level: {risk_level.title()}
Confidence: {confidence_str}
"""

            if indicator_info.get("first_seen"):
                summary += f"First Seen: {indicator_info.get('first_seen')}\n"
            if indicator_info.get("last_seen"):
                summary += f"Last Seen: {indicator_info.get('last_seen')}\n"

            if threat_context and threat_context.get("description"):
                summary += f"\nThreat Context: {threat_context.get('description')}"

            # Add quick recommendation
            if risk_level in ["high", "critical"]:
                summary += "\n\n⛔ RECOMMENDATION: Block this indicator immediately"
            elif risk_level == "medium":
                summary += "\n\n⚠️ RECOMMENDATION: Monitor and investigate further"
            elif risk_level == "low":
                summary += (
                    "\n\n✅ RECOMMENDATION: Appears safe, but continue monitoring"
                )
            else:
                summary += "\n\n❓ RECOMMENDATION: Insufficient data for assessment"

            return summary
        else:
            return f"Error: {result.get('error', 'IoC check failed')}"
    except Exception as e:
        logger.error(f"Error checking IoC: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def graph_statistics(ctx: Context) -> str:
    """Get graph database statistics including node and relationship counts

    Returns detailed statistics about the threat intelligence graph database
    """
    try:
        logger.info("Fetching graph statistics")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/graph_statistics", json={}
        )
        response.raise_for_status()
        result = response.json()

        if result.get("success"):
            stats = result.get("data", {})
            summary = f"""Graph Database Statistics:
• Total Nodes: {stats.get('total_nodes', 'Unknown')}
• Source Nodes: {stats.get('source_nodes', 'Unknown')}
• Relationships: {stats.get('relationships', 'Unknown')}
• Indicators: {stats.get('indicators', 'Unknown')}

The graph contains threat intelligence data including threat actors, indicators of compromise, 
attack patterns, and their relationships. This forms the knowledge base for analysis and correlation."""
            return summary
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error fetching graph statistics: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def execute_graph_query(cypher_query: str, ctx: Context) -> str:
    """Execute a Cypher query against the threat intelligence graph database

    Args:
        cypher_query: Cypher query to execute (must start with MATCH)
    """
    try:
        logger.info(f"Executing graph query: {cypher_query}")

        # Validate query starts with MATCH for security
        if not cypher_query.strip().upper().startswith("MATCH"):
            return "Error: Only MATCH queries are allowed for security reasons"

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/graph_query",
            json={"cypher_query": cypher_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("success"):
            data = result.get("data", {})
            results = data.get("results", [])
            if not results:
                return "Query executed successfully but returned no results."

            # Format results for readability
            formatted_results = []
            for i, row in enumerate(results[:10]):  # Limit to first 10 results
                formatted_results.append(f"Result {i+1}: {json.dumps(row, indent=2)}")

            summary = f"Graph Query Results ({len(results)} total, showing first {min(len(results), 10)}):\n\n"
            summary += "\n\n".join(formatted_results)

            if len(results) > 10:
                summary += f"\n\n... and {len(results) - 10} more results"

            return summary
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error executing graph query: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def feed_management(action: str, ctx: Context, feed_url: str = "") -> str:
    """Manage threat intelligence feeds

    Args:
        action: Action to perform (status, add_discovered)
        feed_url: Feed URL (required for add_discovered action)
    """
    try:
        logger.info(f"Feed management action: {action}")

        if action == "status":
            response = await umbrix_client.client.post(
                f"{umbrix_client.base_url}/v1/tools/feed_status",
                json={
                    "status_filter": "all",
                    "include_metrics": True,
                    "include_recent_items": False,
                },
            )
            response.raise_for_status()
            result = response.json()

            if result.get("success"):
                data = result.get("data", {})
                feeds = data.get("feeds", [])
                if not feeds:
                    return "No feeds found."

                summary = f"Feed Status Summary ({len(feeds)} total):\n\n"
                for feed in feeds[:10]:  # Show first 10
                    summary += f"• {feed.get('name', 'Unknown Feed')}\n"
                    summary += f"  Status: {feed.get('status', 'Unknown')}\n"
                    summary += f"  Type: {feed.get('type', 'Unknown')}\n"
                    summary += f"  Quality Score: {feed.get('quality_score', 'N/A')}\n"
                    summary += f"  Items Today: {feed.get('items_today', 'N/A')}\n\n"

                if len(feeds) > 10:
                    summary += f"... and {len(feeds) - 10} more feeds"

                return summary
            else:
                return f"Error: {result.get('error', 'Unknown error')}"

        elif action == "add_discovered":
            if not feed_url:
                return "Error: feed_url is required for add_discovered action"

            response = await umbrix_client.client.post(
                f"{umbrix_client.base_url}/system/feeds/discovered",
                json={
                    "feed_url": feed_url,
                    "feed_type": "rss",
                    "title": None,
                    "description": "Added via MCP tool",
                    "requires_auth": False,
                    "payment_required": False,
                },
            )
            response.raise_for_status()
            result = response.json()

            return f"Successfully added discovered feed: {feed_url}\nFeed ID: {result.get('id')}"

        else:
            return f"Error: Unknown action '{action}'. Supported actions: status, add_discovered"

    except Exception as e:
        logger.error(f"Error in feed management: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def system_health(ctx: Context) -> str:
    """Check system health and metrics

    Returns health status of various system components
    """
    try:
        logger.info("Checking system health")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/system_health",
            json={"component": "all", "include_metrics": True},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            health = result.get("data", {})
            overall_status = health.get("overall_status", "unknown")
            components = health.get("components", {})

            # Format status emoji
            status_emoji = {"healthy": "🟢", "degraded": "🟡", "unhealthy": "🔴"}.get(
                overall_status, "⚪"
            )

            summary = f"""System Health Check: {status_emoji} {overall_status.upper()}

"""
            # Add component statuses
            for component_name, component_data in components.items():
                status = component_data.get("status", "unknown")
                summary += f"{component_name.title()}: {status.upper()}\n"

            summary += "\nSystem components are being monitored for availability and performance."
            return summary
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error checking system health: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def threat_intel_chat(question: str, ctx: Context) -> str:
    """Ask natural language questions about threat intelligence

    Args:
        question: Natural language question about threats, actors, indicators, etc.
    """
    try:
        logger.info(f"Processing threat intelligence question: {question}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": question,
                "query_type": "natural_language",
                "max_results": 10,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            answer = data.get("answer", "No response received")
            cypher_query = data.get("cypher_query")
            graph_results = data.get("graph_results", [])
            confidence = data.get("confidence", 0)

            summary = f"Threat Intelligence Analysis:\n\n{answer}"

            if confidence:
                summary += f"\n\nConfidence: {confidence:.1%}"

            if cypher_query:
                summary += f"\n\nGraph Query: {cypher_query}"

            if graph_results:
                summary += "\n\nRelevant Data:"
                for i, result_item in enumerate(
                    graph_results[:3], 1
                ):  # Show up to 3 results
                    summary += f"\n{i}. {result_item}"

            return summary
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error in threat intel chat: {e}")
        return f"Error: {str(e)}"


def main():
    """Run the MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
