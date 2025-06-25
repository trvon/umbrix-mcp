"""Tests for Umbrix MCP Server"""

import pytest
from unittest.mock import AsyncMock, patch
from umbrix_mcp.server import UmbrixClient


@pytest.fixture
def mock_client():
    """Create a mock Umbrix client"""
    client = AsyncMock(spec=UmbrixClient)
    client.api_key = "test-key"
    client.base_url = "https://test.umbrix.dev/api"
    return client


@pytest.mark.asyncio
async def test_umbrix_client_initialization():
    """Test that UmbrixClient initializes correctly"""
    client = UmbrixClient("test-key", "https://test.api.com")
    assert client.api_key == "test-key"
    assert client.base_url == "https://test.api.com"
    assert "X-API-Key" in client.headers
    assert client.headers["X-API-Key"] == "test-key"
    await client.close()


@pytest.mark.asyncio
async def test_search_threats_tool():
    """Test search_threats tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "answer": "Found 2 threats related to APT28",
                    "graph_results": [
                        "APT28 - Russian cyber espionage group",
                        "Fancy Bear - Alias for APT28",
                    ],
                },
            }
        )

        from umbrix_mcp.server import search_threats
        from mcp.server.fastmcp import Context

        result = await search_threats("APT28", Context(), limit=10)

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/intelligent_query",
            json={"question": "Search for threats related to: APT28"},
        )

        # Verify response formatting
        assert "Threat Intelligence Search Results:" in result
        assert "Found 2 threats related to APT28" in result
        assert "APT28 - Russian cyber espionage group" in result


@pytest.mark.asyncio
async def test_analyze_indicator_tool():
    """Test analyze_indicator tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "indicator_info": {
                        "status": "malicious",
                        "risk_level": "high",
                        "first_seen": "2024-01-01",
                        "last_seen": "2024-01-15",
                    },
                    "threat_context": {
                        "description": "Known malicious domain used in phishing campaigns"
                    },
                },
            }
        )

        from umbrix_mcp.server import analyze_indicator
        from mcp.server.fastmcp import Context

        result = await analyze_indicator("evil.com", Context(), indicator_type="domain")

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/indicator_lookup",
            json={
                "indicator": "evil.com",
                "indicator_type": "domain",
                "include_context": True,
            },
        )

        # Verify response formatting
        assert "Indicator Analysis: evil.com" in result
        assert "Status: malicious" in result
        assert "Risk Level: high" in result


@pytest.mark.asyncio
async def test_get_threat_actor_tool():
    """Test get_threat_actor tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "actor_info": {
                        "name": "APT28",
                        "aliases": ["Fancy Bear", "Sofacy"],
                        "country": "Russia",
                        "description": "Russian cyber espionage group",
                    },
                    "infrastructure": ["185.220.101.45", "example-c2.com"],
                    "tactics": ["Spear phishing", "Credential harvesting"],
                },
            }
        )

        from umbrix_mcp.server import get_threat_actor
        from mcp.server.fastmcp import Context

        result = await get_threat_actor("APT28", Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/campaign_analysis",
            json={
                "campaign_or_actor": "APT28",
                "analysis_type": "threat_actor",
                "include_infrastructure": True,
                "include_tactics": True,
            },
        )

        # Verify response formatting
        assert "Threat Actor Analysis: APT28" in result
        assert "Name: APT28" in result
        assert "Aliases: Fancy Bear, Sofacy" in result


@pytest.mark.asyncio
async def test_graph_statistics_tool():
    """Test graph_statistics tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "total_nodes": 1000,
                    "source_nodes": 250,
                    "relationships": 3500,
                    "indicators": 150,
                },
            }
        )

        from umbrix_mcp.server import graph_statistics
        from mcp.server.fastmcp import Context

        result = await graph_statistics(Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/graph_statistics", json={}
        )

        # Verify response formatting
        assert "Graph Database Statistics:" in result
        assert "Total Nodes: 1000" in result
        assert "Source Nodes: 250" in result


def create_mock_response(response_data):
    """Helper to create a mock response that works with httpx"""

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return response_data

    return MockResponse()


@pytest.mark.asyncio
async def test_system_health_tool():
    """Test system_health tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "overall_status": "healthy",
                    "components": {
                        "database": {"status": "healthy"},
                        "kafka": {"status": "healthy"},
                        "neo4j": {"status": "healthy"},
                    },
                },
            }
        )

        from umbrix_mcp.server import system_health
        from mcp.server.fastmcp import Context

        result = await system_health(Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/system_health",
            json={"component": "all", "include_metrics": True},
        )

        # Verify response formatting
        assert "System Health Check: 🟢 HEALTHY" in result
        assert "Database: HEALTHY" in result
        assert "Kafka: HEALTHY" in result


@pytest.mark.asyncio
async def test_execute_graph_query_tool():
    """Test execute_graph_query tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "results": [
                        {"n.name": "APT28", "n.country": "Russia"},
                        {"n.name": "Lazarus", "n.country": "North Korea"},
                    ]
                },
            }
        )

        from umbrix_mcp.server import execute_graph_query
        from mcp.server.fastmcp import Context

        cypher_query = "MATCH (n:ThreatActor) RETURN n.name, n.country LIMIT 2"
        result = await execute_graph_query(cypher_query, Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/graph_query",
            json={"cypher_query": cypher_query},
        )

        # Verify response formatting
        assert "Graph Query Results (2 total" in result
        assert "APT28" in result


@pytest.mark.asyncio
async def test_threat_intel_chat_tool():
    """Test threat_intel_chat tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "answer": "APT28 is a Russian cyber espionage group known for sophisticated attacks.",
                    "confidence": 0.92,
                    "cypher_query": "MATCH (ta:ThreatActor {name: 'APT28'}) RETURN ta",
                    "graph_results": [{"ta.name": "APT28", "ta.country": "Russia"}],
                },
            }
        )

        from umbrix_mcp.server import threat_intel_chat
        from mcp.server.fastmcp import Context

        result = await threat_intel_chat("Tell me about APT28", Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/intelligent_query",
            json={"question": "Tell me about APT28"},
        )

        # Verify response formatting
        assert "Threat Intelligence Analysis:" in result
        assert "APT28 is a Russian cyber espionage group" in result
        assert "Confidence: 92.0%" in result


@pytest.mark.asyncio
async def test_quick_ioc_check_tool():
    """Test quick_ioc_check tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "indicator_info": {
                        "status": "malicious",
                        "risk_level": "high",
                        "confidence": 95,
                        "first_seen": "2024-01-01",
                    },
                    "threat_context": {
                        "description": "Known command and control server"
                    },
                },
            }
        )

        from umbrix_mcp.server import quick_ioc_check
        from mcp.server.fastmcp import Context

        result = await quick_ioc_check("185.220.101.45", Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/indicator_lookup",
            json={
                "indicator": "185.220.101.45",
                "indicator_type": "ip",
                "include_context": True,
                "quick_check": True,
            },
        )

        # Verify response formatting
        assert "IoC Quick Check Result: 🚨 MALICIOUS" in result
        assert "Indicator: 185.220.101.45" in result
        assert "Risk Level: High" in result


@pytest.mark.asyncio
async def test_visualize_threat_graph_tool():
    """Test visualize_threat_graph tool using backend tool execution"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "success": True,
                "data": {
                    "results": [
                        {
                            "n.name": "APT28",
                            "r.type": "OPERATES",
                            "m.name": "Malware_X",
                        },
                        {
                            "n.name": "Malware_X",
                            "r.type": "COMMUNICATES_WITH",
                            "m.name": "C2_Server",
                        },
                    ]
                },
            }
        )

        from umbrix_mcp.server import visualize_threat_graph
        from mcp.server.fastmcp import Context

        result = await visualize_threat_graph("APT28", Context())

        # Verify correct endpoint was called with generated cypher query
        mock_http_client.post.assert_called_once()
        call_args = mock_http_client.post.call_args
        assert f"{mock_client.base_url}/v1/tools/graph_query" in call_args[0]
        assert "cypher_query" in call_args[1]["json"]

        # Verify response formatting
        assert "Graph Visualization Results for: APT28" in result
        assert "Found 2 relationships:" in result


@pytest.mark.asyncio
async def test_tool_error_handling():
    """Test error handling when backend tool execution fails"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        # Setup mock client attributes
        mock_client.base_url = "https://test.api.com"

        # Setup mock HTTP client
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        mock_http_client.post.return_value = create_mock_response(
            {
                "success": False,
                "error": "Tool execution failed due to authentication error",
            }
        )

        from umbrix_mcp.server import graph_statistics
        from mcp.server.fastmcp import Context

        result = await graph_statistics(Context())

        # Verify error is properly handled
        assert "Error: Tool execution failed due to authentication error" in result
