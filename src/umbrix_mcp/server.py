#!/usr/bin/env python3
"""
Umbrix MCP Server
Provides threat intelligence capabilities to AI assistants via MCP protocol

TOOL SELECTION GUIDE FOR LLMs:
===============================

🔍 DISCOVERY & EXPLORATION:
- discover_recent_threats: Start here! Shows latest activity and data overview
- search_threats: Find specific threats, actors, malware with fallback strategies
- system_health_check: Verify platform status when other tools fail

💬 ANALYSIS & INTELLIGENCE:
- threat_intel_chat: Analytical questions and strategic intelligence
- analyze_indicator: Deep analysis of specific IOCs (IPs, domains, hashes)
- get_threat_actor: Detailed profiles of specific threat actors
- get_malware_details: Comprehensive malware family analysis
- get_campaign_details: In-depth campaign and operation intelligence

🔧 ADVANCED QUERIES:
- execute_graph_query: Direct Cypher queries for custom analysis
- threat_correlation: Find connections between entities
- timeline_analysis: Temporal patterns and activity analysis

📊 SPECIALIZED TOOLS:
- indicator_reputation: Reputation scoring for IOCs
- network_analysis: Analyze IP ranges and networks
- threat_actor_attribution: Attribute indicators to actors
- ioc_validation: Validate and enrich indicators

RECOMMENDED WORKFLOW:
1. Start with discover_recent_threats to see available data
2. Use search_threats for specific entities or topics
3. Deep dive with specialized tools (analyze_indicator, get_threat_actor, etc.)
4. Use threat_intel_chat for analytical questions
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
async def discover_recent_threats(ctx: Context, days_back: int = 30) -> str:
    """Discover recent threat activity and latest attacks

    This tool automatically finds the most recent threats, indicators, and articles
    without requiring specific search terms. Perfect for "what are the latest attacks?"

    Args:
        days_back: Number of days to look back (default: 30)
    """
    try:
        logger.info(f"Discovering recent threats for the last {days_back} days")

        # Use direct Cypher queries that we know work well
        recent_articles_query = f"""
        MATCH (a:Article) 
        WHERE a.timestamp IS NOT NULL 
        AND datetime(a.timestamp) >= datetime() - duration({{days: {days_back}}})
        RETURN a.title, a.timestamp, a.summary, a.url
        ORDER BY a.timestamp DESC 
        LIMIT 15
        """

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": recent_articles_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            results = data.get("results", "")
            count = data.get("count", 0)

            if count > 0:
                summary = f"🔍 Recent Threat Intelligence (Last {days_back} Days)\n"
                summary += f"Found {count} recent articles and threats:\n\n"

                # Parse the results to format them nicely
                import json as json_mod

                try:
                    if results.startswith("[") and results.endswith("]"):
                        articles = json_mod.loads(results)
                        for i, article in enumerate(articles[:10], 1):
                            title = article.get("a.title", "Unknown")
                            timestamp = article.get("a.timestamp", "")[:10]  # Just date
                            summary += f"{i}. {title}\n"
                            if timestamp:
                                summary += f"   📅 {timestamp}\n"
                            summary += "\n"

                        if len(articles) > 10:
                            summary += (
                                f"... and {len(articles) - 10} more recent threats\n"
                            )
                    else:
                        summary += results

                except Exception:
                    summary += results

                summary += "\n💡 For specific details, use get_threat_actor, analyze_indicator, or execute_graph_query tools."
                return summary
            else:
                return "No recent threat activity found in the specified timeframe."
        else:
            return f"Error discovering threats: {result.get('error', 'Unknown error')}"

    except Exception as e:
        logger.error(f"Error discovering recent threats: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def search_threats(query: str, ctx: Context, limit: int = 10) -> str:
    """Search for threat intelligence using multiple fallback strategies to maximize success

    This tool tries multiple approaches to find threat data:
    1. Natural language search via intelligent_graph_query
    2. Direct graph queries for common patterns
    3. Keyword-based fallback searches
    4. Query suggestions when no results found

    Use this when you want to find threat actors, campaigns, malware, indicators, or security events.
    If this doesn't find results, try discover_recent_threats for latest activity.

    Args:
        query: Search query (e.g., "APT29", "ransomware campaigns", "Russian threat actors")
        limit: Maximum number of results to return (default: 10, max: 50)
    """
    try:
        logger.info(f"Enhanced threat search: {query}")

        # Try intelligent search first with increased limit for better results
        search_limit = min(max(limit, 20), 50)  # Use at least 20, max 50

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": query,
                "query_type": "natural_language",
                "max_results": search_limit,
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            answer = data.get("answer", "")
            graph_results = data.get("graph_results", [])
            confidence = data.get("confidence", 0)

            # Check if we got meaningful results
            if graph_results and len(graph_results) > 0:
                summary = f"Threat Intelligence Search Results:\n\n{answer}"
                if confidence:
                    summary += f"\n\nConfidence: {confidence:.1%}"
                summary += "\n\nRelevant Threats Found:"
                for i, item in enumerate(graph_results[:limit], 1):
                    summary += f"\n{i}. {item}"
                return summary

        # Primary search didn't yield results - try fallback strategies
        logger.info(
            f"Primary search yielded no results, trying fallback strategies for: {query}"
        )

        # Strategy 1: Try direct Cypher queries for common patterns
        fallback_results = await _try_fallback_queries(query, limit)
        if fallback_results:
            return f"Threat Intelligence Search Results (via pattern matching):\n\n{fallback_results}"

        # Strategy 2: Try keyword-based search
        keyword_results = await _try_keyword_search(query, limit)
        if keyword_results:
            return f"Threat Intelligence Search Results (via keyword search):\n\n{keyword_results}"

        # No results found - provide helpful suggestions
        suggestions = _generate_search_suggestions(query)
        return f"No threat intelligence found for '{query}'.\n\n" + suggestions

    except Exception as e:
        logger.error(f"Error in enhanced threat search: {e}")
        # Try one more fallback - simple existence check
        try:
            basic_stats = await _get_basic_database_stats()
            return f"Error in search: {str(e)}\n\nDatabase Status: {basic_stats}\n\nTry using discover_recent_threats to see what data is available."
        except:
            return f"Error: {str(e)}\n\nSuggestion: Try discover_recent_threats to see available data or use more specific search terms."


@mcp.tool()
async def analyze_indicator(
    indicator: str, ctx: Context, indicator_type: str = None
) -> str:
    """Deep analysis of indicators of compromise (IOCs) with enrichment and context

    Provides comprehensive analysis including:
    - Threat classification and reputation
    - Associated campaigns, actors, and malware
    - Geographic and infrastructure details
    - Timeline and attribution information

    Use this for investigating specific IOCs like IP addresses, domains, file hashes, or URLs.
    For bulk analysis or discovery, use search_threats instead.

    Args:
        indicator: The IOC to analyze (IP, domain, hash, URL, email, etc.)
        indicator_type: Optional type hint for better analysis (ipv4-addr, domain-name, file:hashes.MD5, etc.)
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

            summary = f"Indicator Analysis: {indicator}\n\n"

            # Basic info
            if data.get("indicator_types"):
                summary += f"Type: {', '.join(data.get('indicator_types', []))}\n"
            if data.get("description"):
                summary += f"Description: {data.get('description')}\n"
            if data.get("valid_from"):
                summary += f"Valid: {data.get('valid_from')[:10]}"
                if data.get("valid_until"):
                    summary += f" to {data.get('valid_until')[:10]}\n"
                else:
                    summary += " (ongoing)\n"
            summary += "\n"

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
    """Comprehensive threat actor intelligence and profiling

    Provides detailed actor profiles including:
    - Operational capabilities and sophistication
    - Known aliases and attribution details
    - Geographic attribution and motivation
    - Associated campaigns, malware, and TTPs
    - Activity timeline and targeting patterns

    Use this for in-depth threat actor research when you know the specific actor name.
    For discovery, try search_threats with terms like 'Russian APT' or 'ransomware groups'.

    Args:
        actor_name: Threat actor name, alias, or identifier (APT28, Lazarus, FIN7, etc.)
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

            summary = f"Threat Actor: {data.get('name', actor_name)}\n\n"

            # Key characteristics
            if data.get("aliases"):
                summary += f"Also known as: {', '.join(data.get('aliases', []))}\n"
            if data.get("description"):
                summary += f"Description: {data.get('description')}\n\n"

            # Profile
            summary += "Profile:\n"
            if data.get("sophistication"):
                summary += f"  Sophistication: {data.get('sophistication')}\n"
            if data.get("resource_level"):
                summary += f"  Resource Level: {data.get('resource_level')}\n"
            if data.get("primary_motivation"):
                summary += f"  Primary Motivation: {data.get('primary_motivation')}\n"

            # Activity timeline
            if data.get("first_seen") or data.get("last_seen"):
                summary += "\nActivity:\n"
                if data.get("first_seen"):
                    summary += f"  First Seen: {data.get('first_seen')[:10]}\n"
                if data.get("last_seen"):
                    summary += f"  Last Seen: {data.get('last_seen')[:10]}\n"
            summary += "\n"

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
    """Execute direct Cypher queries against the threat intelligence graph database

    For advanced users who want to write custom graph database queries.
    The database contains nodes like ThreatActor, Malware, Campaign, Indicator, Article, etc.

    Common patterns:
    - Find actors: MATCH (t:ThreatActor) WHERE t.name CONTAINS 'APT' RETURN t
    - Find connections: MATCH (a:ThreatActor)-[r]-(b) WHERE a.name = 'APT29' RETURN a,r,b
    - Count data: MATCH (n:Indicator) RETURN count(n)

    For most users, search_threats or discover_recent_threats are easier to use.

    Args:
        cypher_query: Valid Cypher query (e.g., "MATCH (n:ThreatActor) RETURN n.name LIMIT 10")
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
            results = data.get("results", "")
            count = data.get("count", 0)
            truncated = data.get("truncated", False)

            if not results:
                return "Query executed successfully but returned no results."

            # Results are returned as a comma-separated string of JSON objects
            summary = f"Graph Query Results"
            if count > 0:
                summary += f" ({count} results"
                if truncated:
                    summary += ", truncated"
                summary += ")"
            summary += ":\n\n"

            # Format the results for better readability
            if results:
                # Split on ", {" to separate JSON objects, then clean up
                if results.startswith("[") and results.endswith("]"):
                    # If it's a JSON array, parse it
                    try:
                        import json as json_mod

                        parsed_results = json_mod.loads(results)
                        for i, item in enumerate(parsed_results[:10], 1):
                            summary += f"{i}. {json_mod.dumps(item, indent=2)}\n\n"
                        if len(parsed_results) > 10:
                            summary += (
                                f"... and {len(parsed_results) - 10} more results\n"
                            )
                    except:
                        summary += results
                else:
                    # Handle comma-separated JSON objects
                    parts = results.split(", {")
                    if len(parts) > 1:
                        # Reconstruct and format each JSON object
                        for i, part in enumerate(parts[:10], 1):
                            if i > 1:
                                part = "{" + part  # Add back the opening brace
                            summary += f"{i}. {part}\n\n"
                        if len(parts) > 10:
                            summary += f"... and {len(parts) - 10} more results\n"
                    else:
                        summary += results

            return summary
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error executing graph query: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def threat_intel_chat(question: str, ctx: Context) -> str:
    """Get comprehensive threat intelligence analysis using conversational AI

    This tool provides detailed, analytical responses to complex threat intelligence questions.
    It's designed for in-depth analysis, threat attribution, and strategic intelligence queries.

    Best for:
    - Analytical questions: "What are the capabilities of APT29?"
    - Attribution questions: "Which groups use Cobalt Strike?"
    - Trend analysis: "What are emerging ransomware tactics?"
    - Strategic questions: "How do Chinese APTs differ from Russian ones?"

    If you need specific data points, try search_threats or discover_recent_threats first.

    Args:
        question: Analytical question about threats, tactics, attribution, trends, etc.
    """
    try:
        logger.info(f"Processing analytical threat intelligence question: {question}")

        # Try the intelligent query first
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": question,
                "query_type": "natural_language",
                "max_results": 20,  # Increased for more comprehensive analysis
            },
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            answer = data.get("answer", "")
            cypher_query = data.get("cypher_query")
            graph_results = data.get("graph_results", [])
            confidence = data.get("confidence", 0)

            if answer and graph_results:
                summary = f"Threat Intelligence Analysis:\n\n{answer}"

                if confidence and confidence > 0.1:
                    summary += f"\n\nConfidence: {confidence:.1%}"

                if graph_results:
                    summary += "\n\nSupporting Evidence:"
                    for i, result_item in enumerate(graph_results[:5], 1):
                        summary += f"\n{i}. {result_item}"

                if cypher_query:
                    summary += f"\n\nGraph Query Used: {cypher_query}"

                return summary

        # If intelligent query didn't work well, provide helpful guidance
        logger.info(
            f"Intelligent query didn't provide good results, offering guidance for: {question}"
        )

        # Try to provide context-aware guidance
        guidance = _generate_analytical_guidance(question)

        # Try to get some basic data to support the guidance
        basic_data = await _get_contextual_data(question)

        response = f"Analysis Guidance for: '{question}'\n\n{guidance}"
        if basic_data:
            response += f"\n\nAvailable Data:\n{basic_data}"

        return response

    except Exception as e:
        logger.error(f"Error in threat intel chat: {e}")
        guidance = _generate_analytical_guidance(question)
        return f"Unable to process analytical query due to error: {str(e)}\n\nSuggested approach:\n{guidance}"


# Fallback search helper functions
async def _try_fallback_queries(query: str, limit: int) -> str:
    """Try direct Cypher queries for common search patterns"""
    query_lower = query.lower()
    fallback_queries = []

    # Pattern 1: Looking for threat actors
    if any(term in query_lower for term in ["actor", "apt", "group", "threat"]):
        fallback_queries.append(
            "MATCH (t:ThreatActor) RETURN t.name as name, t.aliases as aliases, t.country as country LIMIT "
            + str(limit)
        )

    # Pattern 2: Looking for malware
    if any(
        term in query_lower for term in ["malware", "ransomware", "trojan", "virus"]
    ):
        fallback_queries.append(
            "MATCH (m:Malware) RETURN m.name as name, m.family as family, m.type as type LIMIT "
            + str(limit)
        )

    # Pattern 3: Looking for campaigns
    if any(term in query_lower for term in ["campaign", "operation"]):
        fallback_queries.append(
            "MATCH (c:Campaign) RETURN c.name as name, c.description as description LIMIT "
            + str(limit)
        )

    # Pattern 4: Looking for indicators
    if any(
        term in query_lower for term in ["indicator", "ioc", "ip", "domain", "hash"]
    ):
        fallback_queries.append(
            "MATCH (i:Indicator) RETURN i.value as value, i.type as type, i.confidence as confidence LIMIT "
            + str(limit)
        )

    # Pattern 5: Country-based search
    for country in ["russia", "china", "north korea", "iran", "usa", "israel"]:
        if country in query_lower:
            fallback_queries.append(
                f"MATCH (actor:ThreatActor)-[:LOCATED_IN]->(country:Country) WHERE toLower(country.name) CONTAINS '{country}' RETURN actor.name as name, country.name as country LIMIT {limit}"
            )
            break

    # Try each fallback query
    for cypher_query in fallback_queries:
        try:
            response = await umbrix_client.client.post(
                f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
                json={"cypher_query": cypher_query},
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success" and result.get("data", {}).get(
                    "results"
                ):
                    return f"Found results using pattern matching:\n{result['data']['results']}"
        except Exception as e:
            logger.debug(f"Fallback query failed: {e}")
            continue

    return None


async def _try_keyword_search(query: str, limit: int) -> str:
    """Try keyword-based search across node properties"""
    keywords = query.lower().replace(",", " ").split()

    # Build a comprehensive keyword search query
    keyword_query = f"""
    MATCH (n)
    WHERE any(keyword IN {keywords} WHERE 
        toLower(n.name) CONTAINS keyword OR 
        toLower(n.title) CONTAINS keyword OR 
        toLower(n.description) CONTAINS keyword OR
        toLower(n.aliases) CONTAINS keyword
    )
    RETURN labels(n) as type, n.name as name, coalesce(n.description, n.title, '') as description
    LIMIT {limit}
    """

    try:
        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": keyword_query},
        )
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == "success" and result.get("data", {}).get(
                "results"
            ):
                return (
                    f"Found results using keyword search:\n{result['data']['results']}"
                )
    except Exception as e:
        logger.debug(f"Keyword search failed: {e}")

    return None


async def _get_basic_database_stats() -> str:
    """Get basic database statistics"""
    try:
        stats_query = """
        MATCH (n) 
        RETURN labels(n)[0] as node_type, count(n) as count 
        ORDER BY count DESC
        """

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": stats_query},
        )
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == "success":
                return f"Database contains: {result.get('data', {}).get('results', 'unknown data')}"
    except:
        pass
    return "Database status unknown"


def _generate_analytical_guidance(question: str) -> str:
    """Generate analytical guidance for threat intelligence questions"""
    question_lower = question.lower()

    guidance = ["💡 Analytical Approach:"]

    # Context-specific guidance
    if any(term in question_lower for term in ["actor", "group", "apt"]):
        guidance.extend(
            [
                "• Use get_threat_actor for detailed actor profiles",
                "• Try search_threats with specific actor names",
                "• Use threat_correlation for actor relationships",
            ]
        )
    elif any(term in question_lower for term in ["malware", "trojan", "ransomware"]):
        guidance.extend(
            [
                "• Use get_malware_details for family analysis",
                "• Try search_threats with malware names",
                "• Use threat_correlation for malware relationships",
            ]
        )
    elif any(term in question_lower for term in ["campaign", "operation"]):
        guidance.extend(
            [
                "• Use get_campaign_details for operation analysis",
                "• Try search_threats with campaign names",
                "• Use timeline_analysis for campaign progression",
            ]
        )
    elif any(
        term in question_lower for term in ["indicator", "ioc", "ip", "domain", "hash"]
    ):
        guidance.extend(
            [
                "• Use analyze_indicator for IOC details",
                "• Try indicator_reputation for threat scoring",
                "• Use threat_actor_attribution for attribution",
            ]
        )
    else:
        guidance.extend(
            [
                "• Use discover_recent_threats to see available data",
                "• Try search_threats with key terms from your question",
                "• Use execute_graph_query for custom analysis",
            ]
        )

    guidance.append(
        "\nFor immediate data exploration, try discover_recent_threats first."
    )
    return "\n".join(guidance)


async def _get_contextual_data(question: str) -> str:
    """Get contextual data to support analytical guidance"""
    try:
        # Get basic database stats to show what data is available
        stats_query = """
        CALL {
            MATCH (n:ThreatActor) RETURN 'Threat Actors' as type, count(n) as count
            UNION
            MATCH (n:Malware) RETURN 'Malware' as type, count(n) as count
            UNION
            MATCH (n:Campaign) RETURN 'Campaigns' as type, count(n) as count
            UNION
            MATCH (n:Indicator) RETURN 'Indicators' as type, count(n) as count
            UNION
            MATCH (n:Article) RETURN 'Articles' as type, count(n) as count
        }
        RETURN type, count
        ORDER BY count DESC
        """

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": stats_query},
        )
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == "success":
                return f"Database contains: {result.get('data', {}).get('results', 'unknown data')}"
    except:
        pass
    return "Database status unknown"


def _generate_search_suggestions(query: str) -> str:
    """Generate helpful search suggestions when no results found"""
    suggestions = []
    query_lower = query.lower()

    # Suggest related terms
    if "apt" in query_lower:
        suggestions.append(
            "• Try searching for specific APT numbers: 'APT1', 'APT29', 'APT28'"
        )
        suggestions.append(
            "• Try broader terms: 'advanced persistent threat' or 'state-sponsored'"
        )

    if any(
        malware_term in query_lower
        for malware_term in ["malware", "ransomware", "trojan"]
    ):
        suggestions.append(
            "• Try specific malware names: 'WannaCry', 'Emotet', 'Cobalt Strike'"
        )
        suggestions.append("• Try malware families: 'banking trojan', 'cryptominer'")

    if any(geo_term in query_lower for geo_term in ["russian", "chinese", "iranian"]):
        suggestions.append(
            "• Try country names: 'Russia', 'China', 'Iran', 'North Korea'"
        )
        suggestions.append("• Try 'threat actors from [country]'")

    # Always suggest recent data exploration
    suggestions.extend(
        [
            "• Use discover_recent_threats to see latest threat activity",
            "• Try execute_graph_query with: 'MATCH (n) RETURN labels(n), count(n)' to see available data types",
            "• Search for broader terms like 'threat actor', 'malware', 'campaign', or 'indicators'",
        ]
    )

    return "Try these alternatives:\n" + "\n".join(suggestions)


@mcp.tool()
async def get_malware_details(malware_name: str, ctx: Context) -> str:
    """Comprehensive malware analysis and family intelligence

    Provides detailed malware intelligence including:
    - Malware family classification and variants
    - Capabilities and attack vectors
    - Associated threat actors and campaigns
    - Infrastructure and distribution methods
    - Timeline of variants and evolution

    Use this when you know the specific malware name or family.
    For discovery, try search_threats with terms like 'ransomware' or 'banking trojan'.

    Args:
        malware_name: Malware name or family (WannaCry, Emotet, TrickBot, etc.)
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
    """Detailed threat campaign analysis and operation intelligence

    Provides comprehensive campaign intelligence including:
    - Campaign objectives and targeting strategy
    - Attribution to threat actors and sponsors
    - Timeline of activities and phases
    - Malware and tools used
    - Victims and geographic scope
    - Indicators and infrastructure

    Use this when you know the specific campaign or operation name.
    For discovery, try search_threats with terms like 'operation' or 'campaign'.

    Args:
        campaign_name: Campaign name or operation (SolarWinds, Operation Aurora, etc.)
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
async def find_threat_actors(ctx: Context, days_back: int = 90, limit: int = 15) -> str:
    """Find threat actors with recent activity and attribution information

    This tool finds threat actors that have been active recently or have strong attribution.
    Perfect for "who are the current threat actors?" or "what groups are active?"

    Args:
        days_back: Number of days to look back for activity (default: 90)
        limit: Maximum number of actors to return (default: 15)
    """
    try:
        logger.info(f"Finding threat actors from the last {days_back} days")

        # Use direct Cypher query to find threat actors with recent activity
        threat_actors_query = f"""
        MATCH (ta:ThreatActor)
        OPTIONAL MATCH (ta)-[:ATTRIBUTED_TO|USES|TARGETS]-(related)
        WHERE related.last_seen IS NOT NULL 
        AND datetime(related.last_seen) >= datetime() - duration({{days: {days_back}}})
        WITH ta, count(related) as recent_activity
        WHERE recent_activity > 0 OR ta.aliases IS NOT NULL
        RETURN ta.name, ta.aliases, ta.country, ta.description, recent_activity
        ORDER BY recent_activity DESC, ta.name ASC
        LIMIT {limit}
        """

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": threat_actors_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            results = data.get("results", "")
            count = data.get("count", 0)

            if count > 0:
                summary = f"🎭 Active Threat Actors (Last {days_back} Days)\n"
                summary += f"Found {count} threat actors with recent activity:\n\n"

                # Parse the results
                import json as json_mod

                try:
                    if results.startswith("[") and results.endswith("]"):
                        actors = json_mod.loads(results)
                        for i, actor in enumerate(actors, 1):
                            name = actor.get("ta.name", "Unknown")
                            aliases = actor.get("ta.aliases", "")
                            country = actor.get("ta.country", "")
                            description = actor.get("ta.description", "")
                            activity = actor.get("recent_activity", 0)

                            summary += f"{i}. {name}\n"
                            if aliases and aliases.strip():
                                summary += f"   🏷️  Aliases: {aliases}\n"
                            if country and country.strip():
                                summary += f"   🌍 Country: {country}\n"
                            if activity > 0:
                                summary += (
                                    f"   📊 Recent Activity: {activity} connections\n"
                                )
                            if (
                                description
                                and description.strip()
                                and len(description) < 100
                            ):
                                summary += f"   📝 {description[:97]}...\n"
                            summary += "\n"
                    else:
                        summary += results

                except Exception:
                    summary += results

                summary += "\n💡 For detailed profiles, use get_threat_actor tool with specific actor names."
                return summary
            else:
                # Try fallback query without date restrictions
                fallback_query = f"""
                MATCH (ta:ThreatActor)
                RETURN ta.name, ta.aliases, ta.country, ta.description
                ORDER BY ta.name ASC
                LIMIT {limit}
                """

                response = await umbrix_client.client.post(
                    f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
                    json={"cypher_query": fallback_query},
                )
                response.raise_for_status()
                fallback_result = response.json()

                if fallback_result.get("status") == "success":
                    fallback_data = fallback_result.get("data", {})
                    fallback_results = fallback_data.get("results", "")
                    fallback_count = fallback_data.get("count", 0)

                    if fallback_count > 0:
                        return f"🎭 Known Threat Actors (no recent activity in {days_back} days)\n\nFound {fallback_count} known threat actors:\n\n{fallback_results}\n\n💡 Use get_threat_actor tool for detailed profiles."

                return "No threat actors found in the database."
        else:
            return (
                f"Error finding threat actors: {result.get('error', 'Unknown error')}"
            )

    except Exception as e:
        logger.error(f"Error finding threat actors: {e}")
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
async def find_recent_indicators(
    ctx: Context,
    days_back: int = 30,
    indicator_types: list[str] = None,
    limit: int = 20,
) -> str:
    """Find recent indicators of compromise (IOCs) by type and timeframe

    This tool finds IOCs that have been recently discovered or updated.
    Perfect for "what are the latest IOCs?" or "show me recent malware hashes"

    Args:
        days_back: Number of days to look back (default: 30)
        indicator_types: Types to filter by (e.g., ['ipv4-addr', 'domain-name', 'file:hashes.MD5']) (optional)
        limit: Maximum number of indicators to return (default: 20)
    """
    try:
        logger.info(f"Finding recent indicators from the last {days_back} days")

        # Build type filter if specified
        type_filter = ""
        if indicator_types and len(indicator_types) > 0:
            type_list = "', '".join(indicator_types)
            type_filter = f"AND i.type IN ['{type_list}']"

        # Use direct Cypher query to find recent indicators
        indicators_query = f"""
        MATCH (i:Indicator)
        WHERE i.first_seen IS NOT NULL 
        AND datetime(i.first_seen) >= datetime() - duration({{days: {days_back}}})
        {type_filter}
        RETURN i.value, i.type, i.confidence, i.first_seen, i.threat_level
        ORDER BY datetime(i.first_seen) DESC
        LIMIT {limit}
        """

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": indicators_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            results = data.get("results", "")
            count = data.get("count", 0)

            if count > 0:
                type_str = f" ({', '.join(indicator_types)})" if indicator_types else ""
                summary = f"🔍 Recent Indicators{type_str} (Last {days_back} Days)\n"
                summary += f"Found {count} recent IOCs:\n\n"

                # Parse the results
                import json as json_mod

                try:
                    if results.startswith("[") and results.endswith("]"):
                        indicators = json_mod.loads(results)
                        for i, indicator in enumerate(indicators, 1):
                            value = indicator.get("i.value", "Unknown")
                            ioc_type = indicator.get("i.type", "Unknown")
                            confidence = indicator.get("i.confidence", "")
                            first_seen = indicator.get("i.first_seen", "")
                            threat_level = indicator.get("i.threat_level", "")

                            summary += f"{i}. {value}\n"
                            summary += f"   📝 Type: {ioc_type}\n"
                            if confidence:
                                summary += f"   📊 Confidence: {confidence}\n"
                            if threat_level:
                                summary += f"   ⚠️  Threat Level: {threat_level}\n"
                            if first_seen:
                                summary += f"   📅 First Seen: {first_seen[:10]}\n"
                            summary += "\n"
                    else:
                        summary += results

                except Exception:
                    summary += results

                summary += "\n💡 For detailed analysis, use analyze_indicator tool with specific IOCs."
                return summary
            else:
                # Try fallback query without date restrictions
                fallback_query = f"""
                MATCH (i:Indicator)
                WHERE 1=1 {type_filter}
                RETURN i.value, i.type, i.confidence, coalesce(i.first_seen, 'unknown') as first_seen
                ORDER BY i.value ASC
                LIMIT {limit}
                """

                response = await umbrix_client.client.post(
                    f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
                    json={"cypher_query": fallback_query},
                )
                response.raise_for_status()
                fallback_result = response.json()

                if fallback_result.get("status") == "success":
                    fallback_data = fallback_result.get("data", {})
                    fallback_results = fallback_data.get("results", "")
                    fallback_count = fallback_data.get("count", 0)

                    if fallback_count > 0:
                        type_str = (
                            f" of type {', '.join(indicator_types)}"
                            if indicator_types
                            else ""
                        )
                        return f"🔍 Known Indicators{type_str} (no recent activity in {days_back} days)\n\nFound {fallback_count} indicators:\n\n{fallback_results}\n\n💡 Use analyze_indicator for detailed analysis."

                return f"No indicators found{' of the specified types' if indicator_types else ''} in the database."
        else:
            return f"Error finding indicators: {result.get('error', 'Unknown error')}"

    except Exception as e:
        logger.error(f"Error finding recent indicators: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def timeline_analysis(
    entities: list[str],
    ctx: Context,
    time_range: dict = None,
    analysis_types: list[str] = None,
    max_events: int = 100,
) -> str:
    """Analyze threat activity over a time period

    Args:
        entities: List of entities to analyze (indicators, campaigns, threat actors, etc.)
        time_range: Time range with start_date and end_date in ISO 8601 format (optional, defaults to last 30 days)
        analysis_types: Types of analysis to perform (optional, defaults to ["indicator_timeline", "campaign_progression"])
        max_events: Maximum number of events to analyze (default: 100)
    """
    try:
        logger.info(f"Analyzing timeline for entities: {entities}")

        # Prepare request payload
        payload = {"entities": entities, "max_events": max_events}

        if time_range:
            payload["time_range"] = time_range

        if analysis_types:
            payload["analysis_types"] = analysis_types
        else:
            payload["analysis_types"] = ["indicator_timeline", "campaign_progression"]

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/timeline_analysis",
            json=payload,
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            timeline = data.get("timeline", [])
            patterns = data.get("patterns", [])
            correlations = data.get("correlations", [])
            statistics = data.get("statistics", {})
            insights = data.get("insights", [])

            # Format time range for display
            time_display = "Last 30 days"
            if time_range:
                start = time_range.get("start_date", "")[:10]  # Extract date part
                end = time_range.get("end_date", "")[:10]
                time_display = f"{start} to {end}"

            summary = f"Timeline Analysis: {', '.join(entities[:3])}{'...' if len(entities) > 3 else ''}\n"
            summary += f"Time Range: {time_display}\n\n"

            # Statistics
            if statistics:
                summary += "Statistics:\n"
                if statistics.get("total_events"):
                    summary += f"  Total Events: {statistics['total_events']}\n"
                if statistics.get("time_span"):
                    summary += f"  Time Span: {statistics['time_span']}\n"
                if statistics.get("most_active_period"):
                    summary += (
                        f"  Most Active Period: {statistics['most_active_period']}\n"
                    )
                summary += "\n"

            # Key timeline events
            if timeline:
                summary += f"Timeline Events (showing {min(len(timeline), 10)} of {len(timeline)}):\n"
                for event in timeline[:10]:
                    summary += f"• {event.get('timestamp', '')[:10]} - {event.get('description', '')}\n"
                    if event.get("severity"):
                        summary += f"  Severity: {event.get('severity')}\n"
                summary += "\n"

            # Patterns
            if patterns:
                summary += f"Temporal Patterns ({len(patterns)}):\n"
                for pattern in patterns[:3]:
                    summary += f"• {pattern.get('pattern_type', '')}: {pattern.get('description', '')}\n"
                if len(patterns) > 3:
                    summary += f"  ... and {len(patterns) - 3} more patterns\n"
                summary += "\n"

            # Key insights
            if insights:
                summary += f"Key Insights ({len(insights)}):\n"
                for insight in insights[:3]:
                    summary += f"• {insight.get('title', '')}\n"
                    summary += f"  {insight.get('description', '')}\n"
                if len(insights) > 3:
                    summary += f"  ... and {len(insights) - 3} more insights\n"

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
    """Check system health and verify threat intelligence platform status

    Provides comprehensive system status including:
    - Database connectivity and performance
    - Data collection agent status
    - API service health and response times
    - Data freshness and ingestion rates
    - Storage and memory utilization

    Use this tool when:
    - Other tools are returning errors or no data
    - You want to verify the platform is operational
    - Checking data availability before analysis
    - Troubleshooting connectivity issues

    No parameters required - returns full system status report.
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


@mcp.tool()
async def find_vulnerabilities(
    ctx: Context,
    severity_levels: list[str] = None,
    days_back: int = 90,
    limit: int = 15,
) -> str:
    """Find known vulnerabilities and CVEs in the threat intelligence database

    This tool finds vulnerabilities that threat actors are exploiting or targeting.
    Perfect for "what vulnerabilities are being exploited?" or "show me recent CVEs"

    Args:
        severity_levels: Filter by severity (e.g., ['critical', 'high']) (optional)
        days_back: Number of days to look back for recent activity (default: 90)
        limit: Maximum number of vulnerabilities to return (default: 15)
    """
    try:
        logger.info(f"Finding vulnerabilities from the last {days_back} days")

        # Build severity filter if specified
        severity_filter = ""
        if severity_levels and len(severity_levels) > 0:
            severity_list = "', '".join([s.lower() for s in severity_levels])
            severity_filter = f"AND toLower(v.severity) IN ['{severity_list}']"

        # Use direct Cypher query to find vulnerabilities
        vulnerabilities_query = f"""
        MATCH (v:Vulnerability)
        OPTIONAL MATCH (v)-[:EXPLOITS|TARGETS]-(related)
        WHERE (related.last_seen IS NOT NULL 
               AND datetime(related.last_seen) >= datetime() - duration({{days: {days_back}}})
              ) OR v.published_date IS NOT NULL
        {severity_filter}
        WITH v, count(related) as recent_activity
        RETURN v.cve_id, v.name, v.severity, v.cvss_score, v.description, recent_activity
        ORDER BY recent_activity DESC, v.cvss_score DESC, v.cve_id DESC
        LIMIT {limit}
        """

        response = await umbrix_client.client.post(
            f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": vulnerabilities_query},
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            data = result.get("data", {})
            results = data.get("results", "")
            count = data.get("count", 0)

            if count > 0:
                severity_str = (
                    f" ({', '.join(severity_levels)})" if severity_levels else ""
                )
                summary = f"🚨 Vulnerabilities{severity_str} (Last {days_back} Days)\n"
                summary += (
                    f"Found {count} vulnerabilities with activity or high impact:\n\n"
                )

                # Parse the results
                import json as json_mod

                try:
                    if results.startswith("[") and results.endswith("]"):
                        vulns = json_mod.loads(results)
                        for i, vuln in enumerate(vulns, 1):
                            cve_id = vuln.get("v.cve_id", "Unknown")
                            name = vuln.get("v.name", "")
                            severity = vuln.get("v.severity", "")
                            cvss_score = vuln.get("v.cvss_score", "")
                            description = vuln.get("v.description", "")
                            activity = vuln.get("recent_activity", 0)

                            summary += f"{i}. {cve_id}\n"
                            if name and name.strip():
                                summary += f"   📝 Name: {name}\n"
                            if severity:
                                summary += f"   ⚠️  Severity: {severity.upper()}\n"
                            if cvss_score:
                                summary += f"   📊 CVSS Score: {cvss_score}\n"
                            if activity > 0:
                                summary += f"   🎯 Recent Exploitation: {activity} references\n"
                            if description and len(description) < 150:
                                summary += f"   📄 {description[:147]}...\n"
                            summary += "\n"
                    else:
                        summary += results

                except Exception:
                    summary += results

                summary += "\n💡 For detailed vulnerability analysis, use search_threats with specific CVE IDs."
                return summary
            else:
                # Try fallback query without activity filter
                fallback_query = f"""
                MATCH (v:Vulnerability)
                WHERE 1=1 {severity_filter}
                RETURN v.cve_id, v.name, v.severity, v.cvss_score
                ORDER BY v.cvss_score DESC, v.cve_id DESC
                LIMIT {limit}
                """

                response = await umbrix_client.client.post(
                    f"{umbrix_client.base_url}/v1/tools/execute_graph_query",
                    json={"cypher_query": fallback_query},
                )
                response.raise_for_status()
                fallback_result = response.json()

                if fallback_result.get("status") == "success":
                    fallback_data = fallback_result.get("data", {})
                    fallback_results = fallback_data.get("results", "")
                    fallback_count = fallback_data.get("count", 0)

                    if fallback_count > 0:
                        severity_str = (
                            f" with {', '.join(severity_levels)} severity"
                            if severity_levels
                            else ""
                        )
                        return f"🚨 Known Vulnerabilities{severity_str} (no recent exploitation in {days_back} days)\n\nFound {fallback_count} vulnerabilities:\n\n{fallback_results}\n\n💡 Use search_threats with CVE IDs for more details."

                return f"No vulnerabilities found{' with specified severity levels' if severity_levels else ''} in the database."
        else:
            return (
                f"Error finding vulnerabilities: {result.get('error', 'Unknown error')}"
            )

    except Exception as e:
        logger.error(f"Error finding vulnerabilities: {e}")
        return f"Error: {str(e)}"


def main():
    """Run the enhanced Umbrix MCP server with improved LLM-friendly tools"""
    logger.info(
        "Starting enhanced Umbrix MCP server with optimized threat intelligence tools"
    )
    mcp.run()


if __name__ == "__main__":
    main()
