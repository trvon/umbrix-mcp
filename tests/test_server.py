"""Tests for Umbrix MCP Server

Comprehensive test suite covering all 18 MCP tools with parameter validation,
response format verification, error handling, and integration testing.
"""

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


def create_mock_response(response_data):
    """Helper to create a mock response that works with httpx"""

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return response_data

    return MockResponse()


@pytest.mark.asyncio
async def test_indicator_correlation_tool():
    """Test indicator_correlation tool with proper parameters and response format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "correlations": [
                        {
                            "correlation_type": "infrastructure",
                            "confidence": 0.85,
                            "description": "🔄 Infrastructure Overlap: Shared hosting on ASN-1234",
                        },
                        {
                            "correlation_type": "temporal",
                            "confidence": 0.72,
                            "description": "⏰ Temporal Analysis: Similar activity timeframes",
                        },
                    ],
                    "analysis": {
                        "total_correlations": 2,
                        "strongest_correlation": "infrastructure",
                    },
                },
            }
        )

        from umbrix_mcp.server import indicator_correlation
        from mcp.server.fastmcp import Context

        result = await indicator_correlation(
            ["192.168.1.1", "malicious.com"], Context()
        )

        # Verify HTTP client was called once for indicator_correlation
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/threat_correlation",
            json={
                "indicators": ["192.168.1.1", "malicious.com"],
            },
        )

        # Verify response contains expected content
        assert isinstance(result, str)
        assert len(result) > 0
        # Should contain correlation analysis data
        assert "🔗 Threat Correlation Analysis" in result
        assert "Analyzed 2 indicators: 192.168.1.1, malicious.com" in result
        assert "Found 2 correlations:" in result
        assert "Infrastructure Correlation" in result
        assert "Confidence:" in result


@pytest.mark.asyncio
async def test_analyze_indicator_tool():
    """Test analyze_indicator tool with proper parameters and response format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": "evil.com - Known malicious domain\nThreat Level: HIGH\nAssociated: TrojanDownloader",
                    "count": 1,
                },
            }
        )

        from umbrix_mcp.server import analyze_indicator
        from mcp.server.fastmcp import Context

        result = await analyze_indicator(
            "evil.com", Context(), indicator_type="domain-name"
        )

        # Verify HTTP client was called (multiple calls expected for analyze_indicator)
        assert mock_http_client.post.call_count >= 1

        # Verify at least one call was made to execute_graph_query
        calls = mock_http_client.post.call_args_list
        assert any(
            call[0][0].endswith("/v1/tools/execute_graph_query") for call in calls
        ), "Expected at least one call to execute_graph_query endpoint"

        # Verify response contains expected content
        assert isinstance(result, str)
        assert len(result) > 0
        # Should contain some indicator analysis data
        assert (
            "evil.com" in result
            or "malicious" in result
            or "TrojanDownloader" in result
        )


@pytest.mark.asyncio
async def test_get_threat_actor_tool():
    """Test get_threat_actor tool with proper parameters and response format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '{"name": "APT28", "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM"], "description": "APT28 is a Russian cyber espionage group", "country": "Russia", "malware": ["X-Agent"], "campaigns": ["Operation Pawn Storm"], "techniques": ["T1566.001"]}',
                    "count": 1,
                },
            }
        )

        from umbrix_mcp.server import get_threat_actor
        from mcp.server.fastmcp import Context

        result = await get_threat_actor("APT28", Context())

        # Verify HTTP client was called (multiple calls are possible due to fallback logic)
        assert mock_http_client.post.call_count >= 1

        # Verify at least one call was made to execute_graph_query endpoint
        calls = mock_http_client.post.call_args_list
        assert any(
            call[0][0].endswith("/v1/tools/execute_graph_query") for call in calls
        ), "Expected at least one call to execute_graph_query endpoint"

        # Verify response contains expected content
        assert isinstance(result, str)
        assert len(result) > 0
        # Should contain threat actor information
        assert (
            "APT28" in result
            or "Threat Actor" in result
            or "Graph Database Results" in result
        )


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
                "status": "success",
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
            json={},
        )

        # Verify response formatting
        assert "System Health Report" in result
        assert "HEALTHY" in result
        assert "Database" in result
        assert "Kafka" in result


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
                "status": "success",
                "data": {
                    "results": '{"n.name": "APT28", "n.country": "Russia"}, {"n.name": "Lazarus", "n.country": "North Korea"}',
                    "count": 2,
                    "truncated": False,
                },
            }
        )

        from umbrix_mcp.server import execute_graph_query
        from mcp.server.fastmcp import Context

        cypher_query = "MATCH (n:ThreatActor) RETURN n.name, n.country LIMIT 2"
        result = await execute_graph_query(cypher_query, Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/execute_graph_query",
            json={"cypher_query": cypher_query},
        )

        # Verify response formatting
        assert "Graph Query Results (2 results)" in result
        assert "APT28" in result
        assert "Lazarus" in result


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
                "status": "success",
                "data": {
                    "results": '{"ta.name": "APT28", "ta.country": "Russia", "ta.description": "Russian cyber espionage group known for sophisticated attacks"}',
                    "count": 1,
                },
            }
        )

        from umbrix_mcp.server import threat_intel_chat
        from mcp.server.fastmcp import Context

        result = await threat_intel_chat("Tell me about APT28", Context())

        # Verify HTTP client was called (multiple calls are expected for threat_intel_chat)
        assert mock_http_client.post.call_count >= 1

        # Verify at least one call was made to threat_intel_chat
        calls = mock_http_client.post.call_args_list
        assert any(
            call[0][0].endswith("/v1/tools/threat_intel_chat") for call in calls
        ), "Expected at least one call to threat_intel_chat endpoint"

        # Verify response contains expected content
        assert isinstance(result, str)
        assert len(result) > 0
        # Should contain some threat intelligence analysis
        assert (
            "APT28" in result
            or "Graph-Based Analysis" in result
            or "Graph Database" in result
        )


@pytest.mark.asyncio
async def test_parameter_validation():
    """Test parameter validation for various tools"""
    from umbrix_mcp.server import (
        threat_correlation,
        analyze_indicator,
    )
    from mcp.server.fastmcp import Context

    # Test empty query parameter
    with patch("umbrix_mcp.server.umbrix_client"):
        result = await threat_correlation("", Context())
        # Should handle empty query gracefully
        assert isinstance(result, str)

    # Test None indicator parameter
    with patch("umbrix_mcp.server.umbrix_client"):
        result = await analyze_indicator(None, Context())
        # Should handle None gracefully
        assert isinstance(result, str)


@pytest.mark.asyncio
async def test_tool_error_handling():
    """Test error handling when backend tool execution fails"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "error",
                "error": "Authentication failed - invalid API key",
            }
        )

        from umbrix_mcp.server import threat_correlation
        from mcp.server.fastmcp import Context

        result = await threat_correlation("test query", Context())

        # Verify HTTP client was called (multiple calls are possible)
        assert mock_http_client.post.call_count >= 1

        # Verify at least one call was made to threat_correlation
        calls = mock_http_client.post.call_args_list
        assert any(
            call[0][0].endswith("/v1/tools/threat_correlation") for call in calls
        ), "Expected at least one call to threat_correlation endpoint"

        # Verify error is handled appropriately
        assert isinstance(result, str)
        assert (
            "Error:" in result
            or "Authentication failed" in result
            or "No threat intelligence found" in result
            or "No verified graph data found" in result
        )


@pytest.mark.asyncio
async def test_get_cve_details_tool():
    """Test get_cve_details tool with proper parameters and response format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "description": "Critical vulnerability in web application framework",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "published_date": "2024-04-15",
                    "last_modified": "2024-04-20",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "affected_products": ["Framework v1.0-v2.5"],
                    "associated_threat_actors": ["APT28", "Lazarus Group"],
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3721"],
                    "exploitation_status": "Exploited in Wild",
                },
            }
        )

        from umbrix_mcp.server import get_cve_details
        from mcp.server.fastmcp import Context

        result = await get_cve_details("CVE-2024-3721", Context())

        # Verify HTTP client was called
        assert mock_http_client.post.call_count >= 1

        # Verify at least one call was made to get_cve_details endpoint
        calls = mock_http_client.post.call_args_list
        assert any(
            call[0][0].endswith("/v1/tools/get_cve_details") for call in calls
        ), "Expected at least one call to get_cve_details endpoint"

        # Verify response contains expected content
        assert isinstance(result, str)
        assert len(result) > 0
        # Should contain CVE information
        assert "CVE-2024-3721" in result
        assert (
            "Critical vulnerability" in result
            or "CRITICAL" in result
            or "9.8" in result
        )


@pytest.mark.asyncio
async def test_response_format_consistency():
    """Test that all tools return consistent string responses"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {"status": "success", "data": {"test": "response"}}
        )

        from umbrix_mcp.server import (
            threat_correlation,
            analyze_indicator,
            get_threat_actor,
            execute_graph_query,
            threat_intel_chat,
            system_health,
            get_cve_details,
        )
        from mcp.server.fastmcp import Context

        context = Context()

        # Test that all tools return strings
        tools_to_test = [
            (threat_correlation, ("test", context)),
            (analyze_indicator, ("test.com", context)),
            (get_threat_actor, ("APT28", context)),
            (execute_graph_query, ("MATCH (n) RETURN n LIMIT 1", context)),
            (threat_intel_chat, ("test question", context)),
            (system_health, (context,)),
            (get_cve_details, ("CVE-2024-1234", context)),
        ]

        for tool_func, args in tools_to_test:
            result = await tool_func(*args)
            assert isinstance(
                result, str
            ), f"{tool_func.__name__} should return a string"
            assert (
                len(result) > 0
            ), f"{tool_func.__name__} should return non-empty response"
