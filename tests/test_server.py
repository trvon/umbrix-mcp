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

        # graph_statistics tool was removed - this test needs to be updated
        # Using system_health_check instead as a valid backend tool test
        from umbrix_mcp.server import system_health_check
        from mcp.server.fastmcp import Context

        result = await system_health_check(Context())

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/system_health", json={}
        )

        # Verify response formatting
        assert "System Health Report" in result
        assert "HEALTHY" in result


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

        from umbrix_mcp.server import system_health_check
        from mcp.server.fastmcp import Context

        result = await system_health_check(Context())

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


# Additional comprehensive tests for all 18 tools


@pytest.mark.asyncio
async def test_get_malware_details_tool():
    """Test get_malware_details tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '{"name": "Emotet", "aliases": ["Geodo", "Heodo"], "family": "Emotet", "type": "banking trojan", "description": "Emotet is a modular banking Trojan", "actors": ["TA542"], "campaigns": ["Emotet Campaign"], "techniques": ["T1566.001"]}',
                    "count": 1,
                },
            }
        )

        from umbrix_mcp.server import get_malware_details
        from mcp.server.fastmcp import Context

        result = await get_malware_details("Emotet", Context())

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
        # Should contain malware information
        assert (
            "Emotet" in result
            or "Malware Profile" in result
            or "Graph Database Results" in result
        )


@pytest.mark.asyncio
async def test_get_campaign_details_tool():
    """Test get_campaign_details tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '{"name": "SolarWinds Compromise", "aliases": ["SUNBURST", "UNC2452"], "description": "Supply chain attack via SolarWinds Orion", "objective": "Intelligence gathering", "actors": ["APT29"], "malware": ["SUNBURST"], "first_seen": "2020-03-01T00:00:00Z"}',
                    "count": 1,
                },
            }
        )

        from umbrix_mcp.server import get_campaign_details
        from mcp.server.fastmcp import Context

        result = await get_campaign_details("SolarWinds Compromise", Context())

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
        # Should contain campaign information
        assert (
            "SolarWinds" in result
            or "Campaign Profile" in result
            or "Graph Database Results" in result
        )


@pytest.mark.asyncio
async def test_get_attack_pattern_details_tool():
    """Test get_attack_pattern_details tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
                    "name": "Spearphishing Attachment",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1566.001"}
                    ],
                    "description": "Adversaries may send spearphishing emails with a malicious attachment",
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "initial-access",
                        }
                    ],
                    "x_mitre_platforms": ["Linux", "macOS", "Windows"],
                    "used_by_actors": [{"name": "APT28", "id": "intrusion-set-abc"}],
                },
            }
        )

        from umbrix_mcp.server import get_attack_pattern_details
        from mcp.server.fastmcp import Context

        result = await get_attack_pattern_details("T1566.001", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/get_attack_pattern_details",
            json={"attack_pattern_identifier": "T1566.001"},
        )

        assert "Attack Pattern Analysis: T1566.001" in result
        assert "MITRE ATT&CK ID: T1566.001" in result
        assert "Platforms: Linux, macOS, Windows" in result


@pytest.mark.asyncio
async def test_get_vulnerability_details_tool():
    """Test get_vulnerability_details tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "id": "vulnerability--f8533ce6-ea32-41c2-bd8e-5dfb8d8737ff",
                    "name": "CVE-2021-44228",
                    "cve_id": "CVE-2021-44228",
                    "description": "Apache Log4j2 JNDI features used in configuration",
                    "cvss_v3_score": 10.0,
                    "cvss_v3_severity": "CRITICAL",
                    "external_references": [
                        {
                            "source_name": "cve",
                            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
                        }
                    ],
                    "exploited_by_malware": [
                        {"name": "Log4Shell Scanner", "id": "malware-xyz"}
                    ],
                },
            }
        )

        from umbrix_mcp.server import get_vulnerability_details
        from mcp.server.fastmcp import Context

        result = await get_vulnerability_details("CVE-2021-44228", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/get_vulnerability_details",
            json={"vulnerability_identifier": "CVE-2021-44228"},
        )

        assert "Vulnerability Analysis: CVE-2021-44228" in result
        assert "CVSS v3 Score: 10.0 (CRITICAL)" in result
        assert "Exploited by Malware (1):" in result


@pytest.mark.asyncio
async def test_threat_correlation_tool():
    """Test threat_correlation tool"""
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
                            "description": "Shared C2 infrastructure",
                            "evidence": [
                                "Common IP ranges",
                                "Similar hosting providers",
                            ],
                        },
                        {
                            "correlation_type": "temporal",
                            "confidence": 0.95,
                            "description": "Coordinated activity patterns",
                            "evidence": ["Simultaneous campaigns"],
                        },
                    ]
                },
            }
        )

        from umbrix_mcp.server import indicator_correlation
        from mcp.server.fastmcp import Context

        result = await indicator_correlation(
            ["192.168.1.1", "malicious.com"], Context()
        )

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/threat_correlation",
            json={
                "indicators": ["192.168.1.1", "malicious.com"],
            },
        )

        assert "🔗 Threat Correlation Analysis" in result
        assert "Analyzed 2 indicators: 192.168.1.1, malicious.com" in result
        assert "Found 2 correlations:" in result
        assert "Confidence:" in result


@pytest.mark.asyncio
async def test_threat_correlation_tool():
    """Test threat_correlation tool with proper parameters and response format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "result": "APT28 - Russian cyber espionage group\nFancy Bear - Alias for APT28",
                },
            }
        )

        from umbrix_mcp.server import threat_correlation
        from mcp.server.fastmcp import Context

        result = await threat_correlation("APT28", Context(), limit=10)

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/threat_correlation",
            json={
                "query": "APT28",
                "limit": 10,
            },
        )

        assert isinstance(result, str)
        assert "APT28" in result or "Russian cyber espionage" in result


@pytest.mark.asyncio
async def test_indicator_reputation_tool():
    """Test indicator_reputation tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "reputation_score": 15,
                    "threat_level": "HIGH",
                    "classification": "malicious",
                    "first_seen": "2024-01-01T00:00:00Z",
                    "times_reported": 47,
                    "sources": [{"name": "VirusTotal", "confidence": 0.92}],
                    "associated_threats": [
                        {"type": "malware", "name": "TrojanDownloader"}
                    ],
                    "tags": ["botnet", "c2-server"],
                },
            }
        )

        from umbrix_mcp.server import indicator_reputation
        from mcp.server.fastmcp import Context

        result = await indicator_reputation("192.168.1.100", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/indicator_reputation",
            json={"indicators": ["192.168.1.100"]},
        )

        assert "Indicator Reputation: 192.168.1.100" in result
        assert "Reputation Score: 15/100" in result
        assert "Threat Level: HIGH" in result
        assert "Times Reported: 47" in result
        assert "Tags: botnet, c2-server" in result


@pytest.mark.asyncio
async def test_threat_actor_attribution_tool():
    """Test threat_actor_attribution tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "attributions": [
                        {
                            "actor_name": "APT28",
                            "confidence": 0.87,
                            "matching_indicators": 12,
                            "matching_ttps": ["T1566.001", "T1055", "T1003"],
                            "reasoning": "High overlap in infrastructure and TTPs",
                        },
                        {
                            "actor_name": "FIN7",
                            "confidence": 0.34,
                            "matching_indicators": 3,
                            "matching_ttps": ["T1566.001"],
                            "reasoning": "Limited overlap in spear-phishing techniques",
                        },
                    ]
                },
            }
        )

        from umbrix_mcp.server import threat_actor_attribution
        from mcp.server.fastmcp import Context

        indicators = ["192.168.1.1", "malicious.com", "abc123def456"]
        result = await threat_actor_attribution(indicators, Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/threat_actor_attribution",
            json={"indicators": indicators},
        )

        assert "Threat Actor Attribution Analysis" in result
        assert "Analyzed 3 indicators" in result
        assert "1. APT28" in result
        assert "Confidence: 87.0%" in result
        assert "Matching Indicators: 12" in result
        assert "High overlap in infrastructure" in result


@pytest.mark.asyncio
async def test_ioc_validation_tool():
    """Test ioc_validation tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "is_valid": True,
                    "normalized_value": "example.com",
                    "enrichment": {
                        "geolocation": "United States",
                        "asn": "AS12345",
                        "organization": "Example Corp",
                        "hosting_provider": "CloudFlare",
                        "reverse_dns": "example.com",
                    },
                    "context": "Domain appears legitimate but flagged for monitoring",
                },
            }
        )

        from umbrix_mcp.server import ioc_validation
        from mcp.server.fastmcp import Context

        result = await ioc_validation("example.com", "domain", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/ioc_validation",
            json={
                "indicators": ["example.com"],
                "validate_format": True,
                "enrich_context": True,
            },
        )

        assert "IoC Validation: example.com" in result
        assert "✓ Valid IoC" in result
        assert "Normalized: example.com" in result
        assert "Location: United States" in result
        assert "ASN: AS12345" in result


@pytest.mark.asyncio
async def test_network_analysis_tool():
    """Test network_analysis tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "total_ips": 256,
                    "known_malicious": 3,
                    "suspicious": 7,
                    "clean": 246,
                    "network_info": {
                        "asn": "AS12345",
                        "organization": "Example ISP",
                        "country": "United States",
                        "network_type": "residential",
                    },
                    "threats": [
                        {
                            "ip": "192.168.1.100",
                            "threat_type": "botnet",
                            "description": "Known botnet member",
                        },
                        {
                            "ip": "192.168.1.200",
                            "threat_type": "scanner",
                            "description": "Port scanning activity",
                        },
                    ],
                    "statistics": {
                        "most_common_threat": "botnet",
                        "last_activity": "2024-01-15T10:30:00Z",
                    },
                },
            }
        )

        from umbrix_mcp.server import network_analysis
        from mcp.server.fastmcp import Context

        result = await network_analysis("192.168.1.0/24", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/network_analysis",
            json={"targets": ["192.168.1.0/24"]},
        )

        assert "Network Analysis: 192.168.1.0/24" in result
        assert "Total IPs: 256" in result
        assert "Known Malicious: 3" in result
        assert "Organization: Example ISP" in result
        assert "Most Common Threat: botnet" in result


@pytest.mark.asyncio
async def test_timeline_analysis_tool():
    """Test timeline_analysis tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "timeline": [
                        {
                            "timestamp": "2024-01-15T10:00:00Z",
                            "event_type": "campaign_start",
                            "description": "New phishing campaign detected",
                            "entity": "APT28",
                            "severity": "high",
                        },
                        {
                            "timestamp": "2024-01-12T14:30:00Z",
                            "event_type": "malware_discovery",
                            "description": "New variant of Emotet discovered",
                            "entity": "Emotet",
                            "severity": "medium",
                        },
                    ],
                    "patterns": [],
                    "correlations": [],
                    "statistics": {
                        "total_events": 150,
                        "time_span": "30 days",
                        "most_active_period": "2024-01-10 (15 events)",
                    },
                    "insights": [],
                },
            }
        )

        from umbrix_mcp.server import timeline_analysis
        from mcp.server.fastmcp import Context

        result = await timeline_analysis(
            ["actors", "malware", "campaigns"],
            Context(),
            time_range={
                "start_date": "2024-01-01T00:00:00Z",
                "end_date": "2024-01-31T23:59:59Z",
            },
        )

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/timeline_analysis",
            json={
                "entities": ["actors", "malware", "campaigns"],
                "time_range": {
                    "start_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-31T23:59:59Z",
                },
                "analysis_types": ["indicator_timeline", "campaign_progression"],
                "max_events": 100,
            },
        )

        assert "Timeline Analysis:" in result
        assert "Time Range: 2024-01-01 to 2024-01-31" in result
        assert "Total Events: 150" in result
        assert "Most Active Period: 2024-01-10 (15 events)" in result
        assert "New phishing campaign detected" in result


@pytest.mark.asyncio
async def test_threat_hunting_query_builder_tool():
    """Test threat_hunting_query_builder tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "query": "index=security EventCode=4624 | stats count by src_ip | where count > 100",
                    "description": "Hunt for potential lateral movement via excessive successful logins",
                    "expected_results": "IP addresses with unusually high successful login counts",
                    "detection_logic": [
                        "Monitor successful login events (EventCode 4624)",
                        "Group by source IP address",
                        "Flag IPs with > 100 successful logins in timeframe",
                    ],
                    "related_techniques": ["T1021", "T1078", "T1550"],
                    "false_positives": [
                        "Jump servers and privileged workstations",
                        "Service accounts with automated processes",
                        "VPN concentrators during peak hours",
                    ],
                },
            }
        )

        from umbrix_mcp.server import threat_hunting_query_builder
        from mcp.server.fastmcp import Context

        parameters = {"timeframe": "24h", "threshold": 100}
        result = await threat_hunting_query_builder(
            "lateral_movement", parameters, Context()
        )

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/threat_hunting_query_builder",
            json={
                "hunt_objectives": ["lateral_movement"],
                "filters": parameters,
                "include_suggestions": True,
                "validate_syntax": True,
            },
        )

        assert "Threat Hunting Query: lateral_movement" in result
        assert "Generated Query:" in result
        assert "index=security EventCode=4624" in result
        assert "Detection Logic:" in result
        assert "Related MITRE Techniques:" in result
        assert "False Positive Considerations:" in result


@pytest.mark.asyncio
async def test_report_generation_tool():
    """Test report_generation tool"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "report": "# APT28 Threat Actor Profile\\n\\nAPT28 is a sophisticated threat actor...",
                    "generated_at": "2024-01-15T10:30:00Z",
                    "metadata": {
                        "sources_used": 15,
                        "confidence_level": "high",
                        "data_freshness": "current",
                    },
                },
            }
        )

        from umbrix_mcp.server import report_generation
        from mcp.server.fastmcp import Context

        result = await report_generation(
            "actor_profile", "APT28", "markdown", Context()
        )

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/report_generation",
            json={
                "report_type": "actor_profile",
                "entities": ["APT28"],
                "format": "markdown",
            },
        )

        assert "Report: Actor Profile" in result
        assert "Entity: APT28" in result
        assert "Format: markdown" in result
        assert "# APT28 Threat Actor Profile" in result
        assert "Sources: 15" in result
        assert "Confidence: high" in result


@pytest.mark.asyncio
async def test_report_generation_json_format():
    """Test report_generation tool with JSON format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "report": {
                        "actor_name": "APT28",
                        "sophistication": "expert",
                        "country": "Russia",
                    },
                    "generated_at": "2024-01-15T10:30:00Z",
                },
            }
        )

        from umbrix_mcp.server import report_generation
        from mcp.server.fastmcp import Context

        result = await report_generation("actor_profile", "APT28", "json", Context())

        assert "Report Generated:" in result
        assert '"actor_name": "APT28"' in result
        assert '"sophistication": "expert"' in result


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
async def test_http_exception_handling():
    """Test handling of HTTP exceptions"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        # Simulate HTTP exception
        import httpx

        mock_http_client.post.side_effect = httpx.ConnectTimeout("Connection timeout")

        from umbrix_mcp.server import threat_correlation
        from mcp.server.fastmcp import Context

        result = await threat_correlation("test query", Context())

        # Verify HTTP client was called (multiple calls are possible)
        assert mock_http_client.post.call_count >= 1

        # Verify exception is handled appropriately
        assert isinstance(result, str)
        assert (
            "Error:" in result
            or "Error in search:" in result
            or "Connection timeout" in result
            or "No verified graph data found" in result
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
async def test_discover_recent_threats_tool():
    """Test discover_recent_threats tool with predefined Cypher query"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "threats": [
                        {
                            "title": "New APT28 Campaign",
                            "type": "Article",
                            "timestamp": "2024-01-15T10:30:00Z",
                            "description": "Advanced phishing campaign targeting government entities",
                        },
                        {
                            "title": "Emotet Variant Discovered",
                            "type": "Article",
                            "timestamp": "2024-01-14T08:20:00Z",
                            "description": "New banking trojan variant with enhanced evasion capabilities",
                        },
                    ],
                    "count": 2,
                },
            }
        )

        from umbrix_mcp.server import discover_recent_threats
        from mcp.server.fastmcp import Context

        result = await discover_recent_threats(Context(), 30)

        # Verify correct endpoint was called
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/discover_recent_threats",
            json={"days_back": 30},
        )

        # Verify response formatting
        assert "🔍 Recent Threat Intelligence (Last 30 Days)" in result
        assert "Found 2 recent threats:" in result
        assert "New APT28 Campaign" in result
        assert "2024-01-15" in result
        assert "Emotet Variant Discovered" in result


@pytest.mark.asyncio
async def test_find_threat_actors_tool():
    """Test find_threat_actors tool with predefined Cypher query"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '[{"ta.name": "APT28", "ta.aliases": "Fancy Bear, Sofacy", "ta.country": "Russia", "ta.description": "Russian cyber espionage group", "recent_activity": 15}, {"ta.name": "Lazarus", "ta.aliases": "Hidden Cobra", "ta.country": "North Korea", "ta.description": "North Korean APT group", "recent_activity": 8}]',
                    "count": 2,
                },
            }
        )

        from umbrix_mcp.server import find_threat_actors
        from mcp.server.fastmcp import Context

        result = await find_threat_actors(Context(), 90, 15)

        # Verify correct endpoint and Cypher query format
        mock_http_client.post.assert_called_once()
        call_args = mock_http_client.post.call_args
        assert f"{mock_client.base_url}/v1/tools/execute_graph_query" in call_args[0]
        assert "cypher_query" in call_args[1]["json"]
        assert "MATCH (ta:ThreatActor)" in call_args[1]["json"]["cypher_query"]
        assert "duration({days: 90})" in call_args[1]["json"]["cypher_query"]
        assert "LIMIT 15" in call_args[1]["json"]["cypher_query"]

        # Verify response formatting
        assert "🎭 Active Threat Actors (Last 90 Days)" in result
        assert "Found 2 threat actors with recent activity:" in result
        assert "1. APT28" in result
        assert "🏷️  Aliases: Fancy Bear, Sofacy" in result
        assert "🌍 Country: Russia" in result
        assert "📊 Recent Activity: 15 connections" in result
        assert "2. Lazarus" in result
        assert "💡 For detailed profiles, use get_threat_actor tool" in result


@pytest.mark.asyncio
async def test_find_recent_indicators_tool():
    """Test find_recent_indicators tool with predefined Cypher query"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '[{"i.value": "malicious.com", "i.type": "domain-name", "i.confidence": "high", "i.first_seen": "2024-01-15T10:30:00Z", "i.threat_level": "HIGH"}, {"i.value": "192.168.1.100", "i.type": "ipv4-addr", "i.confidence": "medium", "i.first_seen": "2024-01-14T08:20:00Z", "i.threat_level": "MEDIUM"}]',
                    "count": 2,
                },
            }
        )

        from umbrix_mcp.server import find_recent_indicators
        from mcp.server.fastmcp import Context

        result = await find_recent_indicators(
            Context(), 30, ["domain-name", "ipv4-addr"], 20
        )

        # Verify correct endpoint and Cypher query format
        mock_http_client.post.assert_called_once()
        call_args = mock_http_client.post.call_args
        assert f"{mock_client.base_url}/v1/tools/execute_graph_query" in call_args[0]
        assert "cypher_query" in call_args[1]["json"]
        assert "MATCH (i:Indicator)" in call_args[1]["json"]["cypher_query"]
        assert "duration({days: 30})" in call_args[1]["json"]["cypher_query"]
        assert (
            "AND i.type IN ['domain-name', 'ipv4-addr']"
            in call_args[1]["json"]["cypher_query"]
        )
        assert "LIMIT 20" in call_args[1]["json"]["cypher_query"]

        # Verify response formatting
        assert "🔍 Recent Indicators (domain-name, ipv4-addr) (Last 30 Days)" in result
        assert "Found 2 recent IOCs:" in result
        assert "1. malicious.com" in result
        assert "📝 Type: domain-name" in result
        assert "📊 Confidence: high" in result
        assert "⚠️  Threat Level: HIGH" in result
        assert "📅 First Seen: 2024-01-15" in result
        assert "2. 192.168.1.100" in result
        assert "💡 For detailed analysis, use analyze_indicator tool" in result


@pytest.mark.asyncio
async def test_find_vulnerabilities_tool():
    """Test find_vulnerabilities tool with predefined Cypher query"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '[{"v.cve_id": "CVE-2021-44228", "v.name": "Log4Shell", "v.severity": "CRITICAL", "v.cvss_score": 10.0, "v.description": "Apache Log4j2 JNDI features vulnerability", "recent_activity": 25}, {"v.cve_id": "CVE-2023-23397", "v.name": "Outlook Elevation of Privilege", "v.severity": "CRITICAL", "v.cvss_score": 9.8, "v.description": "Microsoft Outlook elevation of privilege vulnerability", "recent_activity": 12}]',
                    "count": 2,
                },
            }
        )

        from umbrix_mcp.server import find_vulnerabilities
        from mcp.server.fastmcp import Context

        result = await find_vulnerabilities(Context(), ["critical", "high"], 90, 15)

        # Verify correct endpoint and Cypher query format
        mock_http_client.post.assert_called_once()
        call_args = mock_http_client.post.call_args
        assert f"{mock_client.base_url}/v1/tools/execute_graph_query" in call_args[0]
        assert "cypher_query" in call_args[1]["json"]
        assert "MATCH (v:Vulnerability)" in call_args[1]["json"]["cypher_query"]
        assert "duration({days: 90})" in call_args[1]["json"]["cypher_query"]
        assert (
            "AND toLower(v.severity) IN ['critical', 'high']"
            in call_args[1]["json"]["cypher_query"]
        )
        assert "LIMIT 15" in call_args[1]["json"]["cypher_query"]

        # Verify response formatting
        assert "🚨 Vulnerabilities (critical, high) (Last 90 Days)" in result
        assert "Found 2 vulnerabilities with activity or high impact:" in result
        assert "1. CVE-2021-44228" in result
        assert "📝 Name: Log4Shell" in result
        assert "⚠️  Severity: CRITICAL" in result
        assert "📊 CVSS Score: 10.0" in result
        assert "🎯 Recent Exploitation: 25 references" in result
        assert "2. CVE-2023-23397" in result
        assert (
            "💡 For detailed vulnerability analysis, use threat_correlation" in result
        )


@pytest.mark.asyncio
async def test_specialized_tools_fallback_behavior():
    """Test fallback behavior when no recent results found"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        # First call returns no results, second call (fallback) returns results
        mock_http_client.post.side_effect = [
            create_mock_response(
                {
                    "status": "success",
                    "data": {"results": "[]", "count": 0},
                }
            ),
            create_mock_response(
                {
                    "status": "success",
                    "data": {
                        "results": '[{"ta.name": "APT29", "ta.aliases": "Cozy Bear", "ta.country": "Russia", "ta.description": "Russian intelligence group"}]',
                        "count": 1,
                    },
                }
            ),
        ]

        from umbrix_mcp.server import find_threat_actors
        from mcp.server.fastmcp import Context

        result = await find_threat_actors(Context(), 30)

        # Should have made two calls (original + fallback)
        assert mock_http_client.post.call_count == 2

        # Verify fallback response
        assert "🎭 Known Threat Actors (no recent activity in 30 days)" in result
        assert "Found 1 known threat actors:" in result
        assert "APT29" in result


@pytest.mark.asyncio
async def test_specialized_tools_error_handling():
    """Test error handling in specialized tools"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "error",
                "error": "Database connection failed",
            }
        )

        from umbrix_mcp.server import (
            discover_recent_threats,
            find_threat_actors,
            find_recent_indicators,
            find_vulnerabilities,
        )
        from mcp.server.fastmcp import Context

        context = Context()

        # Test error handling for all specialized tools
        tools_to_test = [
            (discover_recent_threats, (context,)),
            (find_threat_actors, (context,)),
            (find_recent_indicators, (context,)),
            (find_vulnerabilities, (context,)),
        ]

        for tool_func, args in tools_to_test:
            result = await tool_func(*args)
            assert "Error" in result and "Database connection failed" in result


@pytest.mark.asyncio
async def test_specialized_tools_parameter_handling():
    """Test parameter handling in specialized tools"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "results": '[{"i.value": "test.com", "i.type": "domain"}]',
                    "count": 1,
                },
            }
        )

        from umbrix_mcp.server import find_recent_indicators, find_vulnerabilities
        from mcp.server.fastmcp import Context

        context = Context()

        # Test find_recent_indicators with different parameter combinations
        result = await find_recent_indicators(context, 7, None, 5)
        assert isinstance(result, str)

        # Verify the query doesn't include type filter when indicator_types is None
        call_args = mock_http_client.post.call_args
        assert "AND i.type IN" not in call_args[1]["json"]["cypher_query"]
        assert "duration({days: 7})" in call_args[1]["json"]["cypher_query"]
        assert "LIMIT 5" in call_args[1]["json"]["cypher_query"]

        # Test find_vulnerabilities with different parameter combinations
        result = await find_vulnerabilities(context, None, 180, 25)
        assert isinstance(result, str)

        # Verify the query doesn't include severity filter when severity_levels is None
        call_args = mock_http_client.post.call_args
        assert "AND toLower(v.severity) IN" not in call_args[1]["json"]["cypher_query"]
        assert "duration({days: 180})" in call_args[1]["json"]["cypher_query"]
        assert "LIMIT 25" in call_args[1]["json"]["cypher_query"]


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
            get_malware_details,
            system_health_check,
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
            (get_malware_details, ("Emotet", context)),
            (system_health_check, (context,)),
        ]

        for tool_func, args in tools_to_test:
            result = await tool_func(*args)
            assert isinstance(
                result, str
            ), f"{tool_func.__name__} should return a string"
            assert (
                len(result) > 0
            ), f"{tool_func.__name__} should return non-empty response"
