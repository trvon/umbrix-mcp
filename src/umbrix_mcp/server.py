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
    """Search for threat intelligence across all data sources using natural language

    Args:
        query: Natural language search query (threat actor, campaign, malware, etc.)
        limit: Maximum number of results to return (default: 10)
    """
    try:
        logger.info(f"Searching threats: {query}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": query,
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
            confidence = data.get("confidence", 0)

            summary = f"Threat Intelligence Search Results:\n\n{answer}"

            if confidence:
                summary += f"\n\nConfidence: {confidence:.1%}"

            if graph_results:
                summary += "\n\nRelevant Threats Found:"
                for i, item in enumerate(graph_results[:limit], 1):
                    summary += f"\n{i}. {item}"

            return summary
        else:
            return f"Error: {result.get('error', 'Search failed')}"
    except Exception as e:
        logger.error(f"Error searching threats: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def analyze_indicator(
    indicator: str, ctx: Context, indicator_type: str = None
) -> str:
    """Analyze an indicator of compromise (IP, domain, hash, etc.)

    Args:
        indicator: The indicator to analyze (e.g., IP address, domain, file hash)
        indicator_type: Optional STIX type (e.g., 'ipv4-addr', 'domain-name', 'file:hashes.MD5')
    """
    try:
        logger.info(f"Analyzing indicator: {indicator}")

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/get_indicator_details",
            json={
                "indicator_value": indicator,
                "indicator_type": indicator_type,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Indicator Analysis: {indicator}\n"

            if data.get("id"):
                summary += f"ID: {data.get('id')}\n"
            if data.get("name"):
                summary += f"Name: {data.get('name')}\n"
            if data.get("value"):
                summary += f"Value: {data.get('value')}\n"
            if data.get("pattern"):
                summary += f"Pattern: {data.get('pattern')}\n"
            if data.get("indicator_types"):
                summary += f"Types: {', '.join(data.get('indicator_types', []))}\n"
            if data.get("description"):
                summary += f"\nDescription: {data.get('description')}\n"
            if data.get("valid_from"):
                summary += f"Valid From: {data.get('valid_from')}\n"
            if data.get("valid_until"):
                summary += f"Valid Until: {data.get('valid_until')}\n"

            # Associated entities
            if data.get("associated_ttps"):
                summary += f"\nAssociated TTPs ({len(data['associated_ttps'])}):\n"
                for ttp in data["associated_ttps"][:5]:
                    summary += f"  • {ttp.get('name', ttp.get('id'))}\n"

            if data.get("associated_malware"):
                summary += (
                    f"\nAssociated Malware ({len(data['associated_malware'])}):\n"
                )
                for malware in data["associated_malware"][:5]:
                    summary += f"  • {malware.get('name', malware.get('id'))}\n"

            if data.get("associated_actors"):
                summary += f"\nAssociated Actors ({len(data['associated_actors'])}):\n"
                for actor in data["associated_actors"][:5]:
                    summary += f"  • {actor.get('name', actor.get('id'))}\n"

            if data.get("associated_campaigns"):
                summary += (
                    f"\nAssociated Campaigns ({len(data['associated_campaigns'])}):\n"
                )
                for campaign in data["associated_campaigns"][:5]:
                    summary += f"  • {campaign.get('name', campaign.get('id'))}\n"

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
            f"{umbrix_client.base_url}/v1/tools/get_threat_actor_summary",
            json={
                "actor_name": actor_name,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Threat Actor Analysis: {actor_name}\n\n"

            if data.get("id"):
                summary += f"ID: {data.get('id')}\n"
            if data.get("name"):
                summary += f"Name: {data.get('name')}\n"
            if data.get("labels"):
                summary += f"Labels: {', '.join(data.get('labels', []))}\n"
            if data.get("aliases"):
                summary += f"Aliases: {', '.join(data.get('aliases', []))}\n"
            if data.get("first_seen"):
                summary += f"First Seen: {data.get('first_seen')}\n"
            if data.get("last_seen"):
                summary += f"Last Seen: {data.get('last_seen')}\n"
            if data.get("description"):
                summary += f"\nDescription: {data.get('description')}\n"
            if data.get("sophistication"):
                summary += f"Sophistication: {data.get('sophistication')}\n"
            if data.get("resource_level"):
                summary += f"Resource Level: {data.get('resource_level')}\n"
            if data.get("primary_motivation"):
                summary += f"Primary Motivation: {data.get('primary_motivation')}\n"

            # Goals
            if data.get("goals"):
                summary += f"\nGoals ({len(data['goals'])}):\n"
                for goal in data["goals"][:5]:
                    summary += f"  • {goal}\n"

            # Tactics
            if data.get("common_tactics"):
                summary += f"\nCommon Tactics ({len(data['common_tactics'])}):\n"
                for tactic in data["common_tactics"][:5]:
                    summary += f"  • {tactic.get('name', tactic.get('id'))}\n"

            # Associated entities
            if data.get("associated_malware"):
                summary += (
                    f"\nAssociated Malware ({len(data['associated_malware'])}):\n"
                )
                for malware in data["associated_malware"][:5]:
                    summary += f"  • {malware.get('name', malware.get('id'))}\n"

            if data.get("associated_campaigns"):
                summary += (
                    f"\nAssociated Campaigns ({len(data['associated_campaigns'])}):\n"
                )
                for campaign in data["associated_campaigns"][:5]:
                    summary += f"  • {campaign.get('name', campaign.get('id'))}\n"

            if data.get("attributed_indicators"):
                summary += (
                    f"\nAttributed Indicators: {data.get('attributed_indicators')}\n"
                )

            return summary
        else:
            return f"Error: {result.get('error', 'Threat actor analysis failed')}"
    except Exception as e:
        logger.error(f"Error getting threat actor: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def execute_graph_query(cypher_query: str, ctx: Context) -> str:
    """Execute a Cypher query against the threat intelligence graph database

    Args:
        cypher_query: Cypher query to execute
    """
    try:
        logger.info(f"Executing graph query: {cypher_query}")

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": cypher_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            results = data.get("results", [])
            query_metadata = data.get("query_metadata", {})

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

            # Add query metadata if available
            if query_metadata:
                summary += f"\n\nQuery Metadata:"
                if query_metadata.get("execution_time_ms"):
                    summary += (
                        f"\n  • Execution Time: {query_metadata['execution_time_ms']}ms"
                    )
                if query_metadata.get("nodes_visited"):
                    summary += f"\n  • Nodes Visited: {query_metadata['nodes_visited']}"

            return summary
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error executing graph query: {e}")
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


# Add all missing backend tools


@mcp.tool()
async def get_malware_details(malware_name: str, ctx: Context) -> str:
    """Get detailed information about a specific malware

    Args:
        malware_name: Name of the malware (e.g., WannaCry, Emotet)
    """
    try:
        logger.info(f"Getting malware details: {malware_name}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/get_malware_details",
            json={"malware_name": malware_name},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Malware Analysis: {malware_name}\n\n"

            if data.get("id"):
                summary += f"ID: {data.get('id')}\n"
            if data.get("name"):
                summary += f"Name: {data.get('name')}\n"
            if data.get("labels"):
                summary += f"Labels: {', '.join(data.get('labels', []))}\n"
            if data.get("aliases"):
                summary += f"Aliases: {', '.join(data.get('aliases', []))}\n"
            if data.get("malware_types"):
                summary += f"Types: {', '.join(data.get('malware_types', []))}\n"
            if data.get("is_family"):
                summary += f"Is Family: {data.get('is_family')}\n"
            if data.get("first_seen"):
                summary += f"First Seen: {data.get('first_seen')}\n"
            if data.get("last_seen"):
                summary += f"Last Seen: {data.get('last_seen')}\n"
            if data.get("description"):
                summary += f"\nDescription: {data.get('description')}\n"

            # Capabilities
            if data.get("capabilities"):
                summary += f"\nCapabilities ({len(data['capabilities'])}):\n"
                for capability in data["capabilities"][:5]:
                    summary += f"  • {capability}\n"

            # Kill chain phases
            if data.get("kill_chain_phases"):
                summary += f"\nKill Chain Phases ({len(data['kill_chain_phases'])}):\n"
                for phase in data["kill_chain_phases"][:5]:
                    summary += f"  • {phase.get('kill_chain_name', '')}: {phase.get('phase_name', '')}\n"

            # Associated entities
            if data.get("associated_actors"):
                summary += f"\nAssociated Actors ({len(data['associated_actors'])}):\n"
                for actor in data["associated_actors"][:5]:
                    summary += f"  • {actor.get('name', actor.get('id'))}\n"

            if data.get("associated_campaigns"):
                summary += (
                    f"\nAssociated Campaigns ({len(data['associated_campaigns'])}):\n"
                )
                for campaign in data["associated_campaigns"][:5]:
                    summary += f"  • {campaign.get('name', campaign.get('id'))}\n"

            if data.get("associated_vulnerabilities"):
                summary += f"\nExploited Vulnerabilities ({len(data['associated_vulnerabilities'])}):\n"
                for vuln in data["associated_vulnerabilities"][:5]:
                    summary += f"  • {vuln.get('name', vuln.get('id'))}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Malware analysis failed')}"
    except Exception as e:
        logger.error(f"Error getting malware details: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_campaign_details(campaign_name: str, ctx: Context) -> str:
    """Get detailed information about a specific threat campaign

    Args:
        campaign_name: Name of the campaign (e.g., Operation Aurora, SolarWinds)
    """
    try:
        logger.info(f"Getting campaign details: {campaign_name}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/get_campaign_details",
            json={"campaign_name": campaign_name},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Campaign Analysis: {campaign_name}\n\n"

            if data.get("id"):
                summary += f"ID: {data.get('id')}\n"
            if data.get("name"):
                summary += f"Name: {data.get('name')}\n"
            if data.get("aliases"):
                summary += f"Aliases: {', '.join(data.get('aliases', []))}\n"
            if data.get("first_seen"):
                summary += f"First Seen: {data.get('first_seen')}\n"
            if data.get("last_seen"):
                summary += f"Last Seen: {data.get('last_seen')}\n"
            if data.get("description"):
                summary += f"\nDescription: {data.get('description')}\n"
            if data.get("objective"):
                summary += f"Objective: {data.get('objective')}\n"

            # Associated entities
            if data.get("attributed_to_actors"):
                summary += (
                    f"\nAttributed to Actors ({len(data['attributed_to_actors'])}):\n"
                )
                for actor in data["attributed_to_actors"][:5]:
                    summary += f"  • {actor.get('name', actor.get('id'))}\n"

            if data.get("uses_malware"):
                summary += f"\nMalware Used ({len(data['uses_malware'])}):\n"
                for malware in data["uses_malware"][:5]:
                    summary += f"  • {malware.get('name', malware.get('id'))}\n"

            if data.get("targets"):
                summary += f"\nTargets ({len(data['targets'])}):\n"
                for target in data["targets"][:5]:
                    summary += f"  • {target.get('name', target.get('id'))}\n"

            if data.get("uses_attack_patterns"):
                summary += f"\nAttack Patterns ({len(data['uses_attack_patterns'])}):\n"
                for pattern in data["uses_attack_patterns"][:5]:
                    summary += f"  • {pattern.get('name', pattern.get('id'))}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Campaign analysis failed')}"
    except Exception as e:
        logger.error(f"Error getting campaign details: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_attack_pattern_details(pattern_name: str, ctx: Context) -> str:
    """Get detailed information about a specific attack pattern

    Args:
        pattern_name: Name of the attack pattern (e.g., T1055, Process Injection)
    """
    try:
        logger.info(f"Getting attack pattern details: {pattern_name}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/get_attack_pattern_details",
            json={"pattern_name": pattern_name},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Attack Pattern Analysis: {pattern_name}\n\n"

            if data.get("id"):
                summary += f"ID: {data.get('id')}\n"
            if data.get("name"):
                summary += f"Name: {data.get('name')}\n"
            if data.get("external_references"):
                for ref in data["external_references"]:
                    if ref.get("source_name") == "mitre-attack":
                        summary += f"MITRE ATT&CK ID: {ref.get('external_id')}\n"
            if data.get("description"):
                summary += f"\nDescription: {data.get('description')}\n"

            # Kill chain phases
            if data.get("kill_chain_phases"):
                summary += f"\nKill Chain Phases:\n"
                for phase in data["kill_chain_phases"]:
                    summary += f"  • {phase.get('kill_chain_name', '')}: {phase.get('phase_name', '')}\n"

            # Platforms
            if data.get("x_mitre_platforms"):
                summary += (
                    f"\nPlatforms: {', '.join(data.get('x_mitre_platforms', []))}\n"
                )

            # Detection and mitigation
            if data.get("x_mitre_detection"):
                summary += f"\nDetection:\n{data.get('x_mitre_detection')}\n"

            # Associated entities
            if data.get("used_by_actors"):
                summary += f"\nUsed by Actors ({len(data['used_by_actors'])}):\n"
                for actor in data["used_by_actors"][:5]:
                    summary += f"  • {actor.get('name', actor.get('id'))}\n"

            if data.get("used_by_malware"):
                summary += f"\nUsed by Malware ({len(data['used_by_malware'])}):\n"
                for malware in data["used_by_malware"][:5]:
                    summary += f"  • {malware.get('name', malware.get('id'))}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Attack pattern analysis failed')}"
    except Exception as e:
        logger.error(f"Error getting attack pattern details: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_vulnerability_details(vulnerability_id: str, ctx: Context) -> str:
    """Get detailed information about a specific vulnerability

    Args:
        vulnerability_id: Vulnerability identifier (e.g., CVE-2021-44228, Log4Shell)
    """
    try:
        logger.info(f"Getting vulnerability details: {vulnerability_id}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/get_vulnerability_details",
            json={"vulnerability_name": vulnerability_id},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Vulnerability Analysis: {vulnerability_id}\n\n"

            if data.get("id"):
                summary += f"ID: {data.get('id')}\n"
            if data.get("name"):
                summary += f"Name: {data.get('name')}\n"
            if data.get("cve_id"):
                summary += f"CVE ID: {data.get('cve_id')}\n"
            if data.get("created"):
                summary += f"Created: {data.get('created')}\n"
            if data.get("modified"):
                summary += f"Modified: {data.get('modified')}\n"
            if data.get("description"):
                summary += f"\nDescription: {data.get('description')}\n"

            # CVSS scores
            if data.get("cvss_v3_score"):
                summary += f"\nCVSS v3 Score: {data.get('cvss_v3_score')}"
                if data.get("cvss_v3_severity"):
                    summary += f" ({data.get('cvss_v3_severity')})"
                summary += "\n"
            if data.get("cvss_v2_score"):
                summary += f"CVSS v2 Score: {data.get('cvss_v2_score')}\n"

            # External references
            if data.get("external_references"):
                summary += f"\nReferences:\n"
                for ref in data["external_references"][:5]:
                    summary += f"  • {ref.get('source_name', '')}: {ref.get('url', ref.get('external_id', ''))}\n"

            # Associated entities
            if data.get("exploited_by_malware"):
                summary += (
                    f"\nExploited by Malware ({len(data['exploited_by_malware'])}):\n"
                )
                for malware in data["exploited_by_malware"][:5]:
                    summary += f"  • {malware.get('name', malware.get('id'))}\n"

            if data.get("targeted_by_actors"):
                summary += (
                    f"\nTargeted by Actors ({len(data['targeted_by_actors'])}):\n"
                )
                for actor in data["targeted_by_actors"][:5]:
                    summary += f"  • {actor.get('name', actor.get('id'))}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Vulnerability analysis failed')}"
    except Exception as e:
        logger.error(f"Error getting vulnerability details: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def threat_correlation(
    entity_type: str, entity_name: str, correlation_type: str, ctx: Context
) -> str:
    """Find correlations between threat entities

    Args:
        entity_type: Type of entity (actor, malware, campaign, indicator)
        entity_name: Name or ID of the entity
        correlation_type: Type of correlation (related_actors, used_tools, common_ttps, infrastructure)
    """
    try:
        logger.info(f"Finding correlations for {entity_type}: {entity_name}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/threat_correlation",
            json={
                "entity_type": entity_type,
                "entity_name": entity_name,
                "correlation_type": correlation_type,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            correlations = data.get("correlations", [])

            summary = f"Threat Correlation Analysis\n"
            summary += f"Entity: {entity_name} ({entity_type})\n"
            summary += f"Correlation Type: {correlation_type}\n\n"

            if not correlations:
                summary += "No correlations found."
            else:
                summary += f"Found {len(correlations)} correlations:\n\n"
                for i, corr in enumerate(correlations[:10], 1):
                    summary += f"{i}. {corr.get('name', corr.get('id', 'Unknown'))}\n"
                    if corr.get("relationship_type"):
                        summary += f"   Relationship: {corr['relationship_type']}\n"
                    if corr.get("confidence"):
                        summary += f"   Confidence: {corr['confidence']}\n"
                    if corr.get("first_seen"):
                        summary += f"   First Seen: {corr['first_seen']}\n"
                    summary += "\n"

                if len(correlations) > 10:
                    summary += f"... and {len(correlations) - 10} more correlations"

            return summary
        else:
            return f"Error: {result.get('error', 'Correlation analysis failed')}"
    except Exception as e:
        logger.error(f"Error in threat correlation: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def indicator_reputation(indicator: str, ctx: Context) -> str:
    """Get reputation information for an indicator

    Args:
        indicator: The indicator to check (IP, domain, hash, etc.)
    """
    try:
        logger.info(f"Checking reputation for indicator: {indicator}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/indicator_reputation",
            json={"indicator": indicator},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Indicator Reputation: {indicator}\n\n"

            if data.get("reputation_score"):
                summary += f"Reputation Score: {data.get('reputation_score')}/100\n"
            if data.get("threat_level"):
                summary += f"Threat Level: {data.get('threat_level')}\n"
            if data.get("classification"):
                summary += f"Classification: {data.get('classification')}\n"
            if data.get("first_seen"):
                summary += f"First Seen: {data.get('first_seen')}\n"
            if data.get("last_seen"):
                summary += f"Last Seen: {data.get('last_seen')}\n"
            if data.get("times_reported"):
                summary += f"Times Reported: {data.get('times_reported')}\n"

            # Sources
            if data.get("sources"):
                summary += f"\nReported by Sources ({len(data['sources'])}):\n"
                for source in data["sources"][:5]:
                    summary += f"  • {source.get('name', 'Unknown')}"
                    if source.get("confidence"):
                        summary += f" (Confidence: {source['confidence']})"
                    summary += "\n"

            # Associated threats
            if data.get("associated_threats"):
                summary += f"\nAssociated Threats:\n"
                for threat in data["associated_threats"][:5]:
                    summary += (
                        f"  • {threat.get('type', '')}: {threat.get('name', '')}\n"
                    )

            # Tags
            if data.get("tags"):
                summary += f"\nTags: {', '.join(data.get('tags', []))}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Reputation check failed')}"
    except Exception as e:
        logger.error(f"Error checking indicator reputation: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def threat_actor_attribution(indicators: list[str], ctx: Context) -> str:
    """Attribute indicators to potential threat actors

    Args:
        indicators: List of indicators to analyze for attribution
    """
    try:
        logger.info(
            f"Performing threat actor attribution for {len(indicators)} indicators"
        )
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/threat_actor_attribution",
            json={"indicators": indicators},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            attributions = data.get("attributions", [])

            summary = f"Threat Actor Attribution Analysis\n"
            summary += f"Analyzed {len(indicators)} indicators\n\n"

            if not attributions:
                summary += "No threat actor attributions found."
            else:
                summary += f"Potential Attributions:\n\n"
                for i, attr in enumerate(attributions[:5], 1):
                    summary += f"{i}. {attr.get('actor_name', 'Unknown Actor')}\n"
                    summary += f"   Confidence: {attr.get('confidence', 0):.1%}\n"
                    summary += f"   Matching Indicators: {attr.get('matching_indicators', 0)}\n"
                    if attr.get("matching_ttps"):
                        summary += f"   Matching TTPs: {', '.join(attr['matching_ttps'][:3])}\n"
                    if attr.get("reasoning"):
                        summary += f"   Reasoning: {attr['reasoning']}\n"
                    summary += "\n"

                if len(attributions) > 5:
                    summary += (
                        f"... and {len(attributions) - 5} more potential attributions"
                    )

            return summary
        else:
            return f"Error: {result.get('error', 'Attribution analysis failed')}"
    except Exception as e:
        logger.error(f"Error in threat actor attribution: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def ioc_validation(ioc: str, ioc_type: str, ctx: Context) -> str:
    """Validate and enrich an indicator of compromise

    Args:
        ioc: The indicator to validate
        ioc_type: Type of indicator (ip, domain, hash, url, email)
    """
    try:
        logger.info(f"Validating IoC: {ioc} (type: {ioc_type})")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/ioc_validation",
            json={
                "ioc": ioc,
                "ioc_type": ioc_type,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"IoC Validation: {ioc}\n"
            summary += f"Type: {ioc_type}\n\n"

            if data.get("is_valid"):
                summary += "✓ Valid IoC\n"
            else:
                summary += "✗ Invalid IoC\n"
                if data.get("validation_errors"):
                    summary += f"Errors: {', '.join(data['validation_errors'])}\n"

            if data.get("normalized_value"):
                summary += f"Normalized: {data['normalized_value']}\n"

            # Enrichment data
            if data.get("enrichment"):
                enrich = data["enrichment"]
                summary += "\nEnrichment Data:\n"
                if enrich.get("geolocation"):
                    summary += f"  Location: {enrich['geolocation']}\n"
                if enrich.get("asn"):
                    summary += f"  ASN: {enrich['asn']}\n"
                if enrich.get("organization"):
                    summary += f"  Organization: {enrich['organization']}\n"
                if enrich.get("hosting_provider"):
                    summary += f"  Hosting: {enrich['hosting_provider']}\n"
                if enrich.get("reverse_dns"):
                    summary += f"  Reverse DNS: {enrich['reverse_dns']}\n"

            # Context
            if data.get("context"):
                summary += f"\nContext: {data['context']}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'IoC validation failed')}"
    except Exception as e:
        logger.error(f"Error validating IoC: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def network_analysis(network: str, ctx: Context) -> str:
    """Analyze a network range for threat intelligence

    Args:
        network: Network range in CIDR notation (e.g., 192.168.1.0/24)
    """
    try:
        logger.info(f"Analyzing network: {network}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/network_analysis",
            json={"network": network},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Network Analysis: {network}\n\n"

            if data.get("total_ips"):
                summary += f"Total IPs: {data['total_ips']}\n"
            if data.get("known_malicious"):
                summary += f"Known Malicious: {data['known_malicious']}\n"
            if data.get("suspicious"):
                summary += f"Suspicious: {data['suspicious']}\n"
            if data.get("clean"):
                summary += f"Clean: {data['clean']}\n"

            # Network info
            if data.get("network_info"):
                info = data["network_info"]
                summary += "\nNetwork Information:\n"
                if info.get("asn"):
                    summary += f"  ASN: {info['asn']}\n"
                if info.get("organization"):
                    summary += f"  Organization: {info['organization']}\n"
                if info.get("country"):
                    summary += f"  Country: {info['country']}\n"
                if info.get("network_type"):
                    summary += f"  Type: {info['network_type']}\n"

            # Threats
            if data.get("threats"):
                summary += f"\nIdentified Threats ({len(data['threats'])}):\n"
                for threat in data["threats"][:10]:
                    summary += f"  • {threat.get('ip', '')}: {threat.get('threat_type', '')} - {threat.get('description', '')}\n"

            # Statistics
            if data.get("statistics"):
                stats = data["statistics"]
                summary += "\nStatistics:\n"
                if stats.get("most_common_threat"):
                    summary += f"  Most Common Threat: {stats['most_common_threat']}\n"
                if stats.get("last_activity"):
                    summary += f"  Last Activity: {stats['last_activity']}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Network analysis failed')}"
    except Exception as e:
        logger.error(f"Error analyzing network: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def timeline_analysis(
    start_date: str, end_date: str, entity_filter: str, ctx: Context
) -> str:
    """Analyze threat activity over a time period

    Args:
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        entity_filter: Filter by entity type (all, actors, malware, campaigns, indicators)
    """
    try:
        logger.info(f"Analyzing timeline from {start_date} to {end_date}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/timeline_analysis",
            json={
                "start_date": start_date,
                "end_date": end_date,
                "entity_filter": entity_filter,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            events = data.get("events", [])

            summary = f"Timeline Analysis: {start_date} to {end_date}\n"
            summary += f"Filter: {entity_filter}\n\n"

            if data.get("total_events"):
                summary += f"Total Events: {data['total_events']}\n"

            # Summary statistics
            if data.get("summary"):
                stats = data["summary"]
                summary += "\nSummary:\n"
                if stats.get("most_active_actors"):
                    summary += f"  Most Active Actors: {', '.join(stats['most_active_actors'][:3])}\n"
                if stats.get("new_malware"):
                    summary += f"  New Malware: {stats['new_malware']}\n"
                if stats.get("major_campaigns"):
                    summary += f"  Major Campaigns: {stats['major_campaigns']}\n"
                if stats.get("peak_activity_date"):
                    summary += f"  Peak Activity: {stats['peak_activity_date']}\n"

            # Timeline events
            if events:
                summary += (
                    f"\nKey Events (showing {min(len(events), 10)} of {len(events)}):\n"
                )
                for event in events[:10]:
                    summary += (
                        f"\n{event.get('date', '')} - {event.get('event_type', '')}:\n"
                    )
                    summary += f"  {event.get('description', '')}\n"
                    if event.get("entities"):
                        summary += f"  Entities: {', '.join(event['entities'][:3])}\n"
                    if event.get("severity"):
                        summary += f"  Severity: {event['severity']}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Timeline analysis failed')}"
    except Exception as e:
        logger.error(f"Error in timeline analysis: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def threat_hunting_query_builder(
    hunt_type: str, parameters: dict, ctx: Context
) -> str:
    """Build threat hunting queries based on patterns

    Args:
        hunt_type: Type of hunt (lateral_movement, data_exfiltration, persistence, privilege_escalation)
        parameters: Hunt-specific parameters (e.g., {"timeframe": "7d", "network": "internal"})
    """
    try:
        logger.info(f"Building threat hunting query for: {hunt_type}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/threat_hunting_query_builder",
            json={
                "hunt_type": hunt_type,
                "parameters": parameters,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = f"Threat Hunting Query: {hunt_type}\n"
            summary += f"Parameters: {parameters}\n\n"

            if data.get("query"):
                summary += f"Generated Query:\n{data['query']}\n\n"

            if data.get("description"):
                summary += f"Description:\n{data['description']}\n\n"

            if data.get("expected_results"):
                summary += f"Expected Results:\n{data['expected_results']}\n\n"

            # Detection logic
            if data.get("detection_logic"):
                summary += "Detection Logic:\n"
                for step in data["detection_logic"]:
                    summary += f"  • {step}\n"
                summary += "\n"

            # Related techniques
            if data.get("related_techniques"):
                summary += f"Related MITRE Techniques:\n"
                for technique in data["related_techniques"][:5]:
                    summary += f"  • {technique}\n"

            # False positive considerations
            if data.get("false_positives"):
                summary += f"\nFalse Positive Considerations:\n"
                for fp in data["false_positives"][:3]:
                    summary += f"  • {fp}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Query building failed')}"
    except Exception as e:
        logger.error(f"Error building threat hunting query: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def report_generation(
    report_type: str, entity_name: str, format: str, ctx: Context
) -> str:
    """Generate threat intelligence reports

    Args:
        report_type: Type of report (actor_profile, incident_summary, ioc_list, executive_brief)
        entity_name: Name of the entity to report on
        format: Output format (text, markdown, json)
    """
    try:
        logger.info(f"Generating {report_type} report for: {entity_name}")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/report_generation",
            json={
                "report_type": report_type,
                "entity_name": entity_name,
                "format": format,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            if format == "json":
                return (
                    f"Report Generated:\n{json.dumps(data.get('report', {}), indent=2)}"
                )
            else:
                report_content = data.get("report", "")

                summary = f"Report: {report_type.replace('_', ' ').title()}\n"
                summary += f"Entity: {entity_name}\n"
                summary += f"Format: {format}\n"
                summary += f"Generated: {data.get('generated_at', 'Unknown')}\n"
                summary += "=" * 50 + "\n\n"
                summary += report_content

                if data.get("metadata"):
                    meta = data["metadata"]
                    summary += "\n\nReport Metadata:\n"
                    if meta.get("sources_used"):
                        summary += f"  Sources: {meta['sources_used']}\n"
                    if meta.get("confidence_level"):
                        summary += f"  Confidence: {meta['confidence_level']}\n"
                    if meta.get("data_freshness"):
                        summary += f"  Data Freshness: {meta['data_freshness']}\n"

                return summary
        else:
            return f"Error: {result.get('error', 'Report generation failed')}"
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def system_health_check(ctx: Context) -> str:
    """Check system health and component status

    Returns health status of various system components including databases, services, and agents
    """
    try:
        logger.info("Checking system health")
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/system_health",
            json={},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})

            summary = "System Health Report\n" + "=" * 50 + "\n\n"

            # Overall status
            if data.get("overall_status"):
                status = data["overall_status"]
                status_emoji = {
                    "healthy": "✅",
                    "degraded": "⚠️",
                    "unhealthy": "❌",
                }.get(status, "❓")
                summary += f"Overall Status: {status_emoji} {status.upper()}\n\n"

            # Components
            if data.get("components"):
                summary += "Component Status:\n"
                for comp_name, comp_data in data["components"].items():
                    status = comp_data.get("status", "unknown")
                    status_emoji = {
                        "healthy": "✅",
                        "degraded": "⚠️",
                        "unhealthy": "❌",
                    }.get(status, "❓")
                    summary += f"\n{comp_name.replace('_', ' ').title()}:\n"
                    summary += f"  Status: {status_emoji} {status}\n"
                    if comp_data.get("message"):
                        summary += f"  Message: {comp_data['message']}\n"
                    if comp_data.get("last_check"):
                        summary += f"  Last Check: {comp_data['last_check']}\n"
                    if comp_data.get("metrics"):
                        summary += "  Metrics:\n"
                        for metric, value in comp_data["metrics"].items():
                            summary += f"    • {metric}: {value}\n"

            # System metrics
            if data.get("system_metrics"):
                metrics = data["system_metrics"]
                summary += "\nSystem Metrics:\n"
                if metrics.get("uptime"):
                    summary += f"  Uptime: {metrics['uptime']}\n"
                if metrics.get("cpu_usage"):
                    summary += f"  CPU Usage: {metrics['cpu_usage']}%\n"
                if metrics.get("memory_usage"):
                    summary += f"  Memory Usage: {metrics['memory_usage']}%\n"
                if metrics.get("disk_usage"):
                    summary += f"  Disk Usage: {metrics['disk_usage']}%\n"
                if metrics.get("active_connections"):
                    summary += (
                        f"  Active Connections: {metrics['active_connections']}\n"
                    )

            # Recent issues
            if data.get("recent_issues"):
                summary += f"\nRecent Issues ({len(data['recent_issues'])}):\n"
                for issue in data["recent_issues"][:5]:
                    summary += f"  • [{issue.get('timestamp', '')}] {issue.get('component', '')}: {issue.get('message', '')}\n"

            return summary
        else:
            return f"Error: {result.get('error', 'Health check failed')}"
    except Exception as e:
        logger.error(f"Error checking system health: {e}")
        return f"Error: {str(e)}"


def main():
    """Run the MCP server"""
    mcp.run()


if __name__ == "__main__":
    main()
