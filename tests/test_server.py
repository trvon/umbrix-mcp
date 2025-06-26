"""Tests for Umbrix MCP Server

Comprehensive test suite covering all 18 MCP tools with parameter validation,
response format verification, error handling, and integration testing.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
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
    """Test search_threats tool with proper parameters and response format"""
    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client
        mock_http_client.post.return_value = create_mock_response(
            {
                "status": "success",
                "data": {
                    "answer": "Found 2 threats related to APT28",
                    "graph_results": [
                        "APT28 - Russian cyber espionage group",
                        "Fancy Bear - Alias for APT28",
                    ],
                    "confidence": 0.92,
                },
            }
        )

        from umbrix_mcp.server import search_threats
        from mcp.server.fastmcp import Context

        result = await search_threats("APT28", Context(), limit=10)

        # Verify correct endpoint and parameters
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": "APT28",
                "query_type": "natural_language",
                "max_results": 10,
            },
        )

        # Verify response formatting
        assert "Threat Intelligence Search Results:" in result
        assert "Found 2 threats related to APT28" in result
        assert "Confidence: 92.0%" in result


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
                    "id": "indicator-123",
                    "name": "evil.com",
                    "value": "evil.com",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "indicator_types": ["malicious-activity"],
                    "description": "Known malicious domain used in phishing campaigns",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "associated_ttps": [{"name": "Phishing", "id": "T1566"}],
                    "associated_malware": [
                        {"name": "TrojanDownloader", "id": "malware-456"}
                    ],
                },
            }
        )

        from umbrix_mcp.server import analyze_indicator
        from mcp.server.fastmcp import Context

        result = await analyze_indicator(
            "evil.com", Context(), indicator_type="domain-name"
        )

        # Verify correct endpoint and parameters
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/get_indicator_details",
            json={
                "indicator_value": "evil.com",
                "indicator_type": "domain-name",
            },
        )

        # Verify response formatting
        assert "Indicator Analysis: evil.com" in result
        assert "ID: indicator-123" in result
        assert "Pattern: [domain-name:value = 'evil.com']" in result
        assert "Associated TTPs (1):" in result
        assert "Phishing" in result


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
                    "id": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c",
                    "name": "APT28",
                    "labels": ["intrusion-set"],
                    "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM"],
                    "first_seen": "2007-01-01T00:00:00Z",
                    "description": "APT28 is a threat group that has been attributed to Russia's Main Intelligence Directorate of the Russian General Staff by a July 2018 U.S. Department of Justice indictment.",
                    "sophistication": "expert",
                    "resource_level": "government",
                    "primary_motivation": "organizational-gain",
                    "goals": ["Intelligence gathering", "Credential theft"],
                    "common_tactics": [{"name": "Spear Phishing", "id": "T1566.001"}],
                    "associated_malware": [{"name": "X-Agent", "id": "malware-123"}],
                    "attributed_indicators": 147,
                },
            }
        )

        from umbrix_mcp.server import get_threat_actor
        from mcp.server.fastmcp import Context

        result = await get_threat_actor("APT28", Context())

        # Verify correct endpoint and parameters
        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/get_threat_actor_summary",
            json={
                "actor_name": "APT28",
            },
        )

        # Verify response formatting
        assert "Threat Actor Analysis: APT28" in result
        assert "Name: APT28" in result
        assert "Aliases: Fancy Bear, Sofacy, STRONTIUM" in result
        assert "Sophistication: expert" in result
        assert "Resource Level: government" in result
        assert "Primary Motivation: organizational-gain" in result
        assert "Associated Malware (1):" in result
        assert "Attributed Indicators: 147" in result


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
            f"{mock_client.base_url}/v1/tools/execute_graph_query",
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
                "status": "success",
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
            f"{mock_client.base_url}/v1/tools/intelligent_graph_query",
            json={
                "query": "Tell me about APT28",
                "query_type": "natural_language",
                "max_results": 10,
            },
        )

        # Verify response formatting
        assert "Threat Intelligence Analysis:" in result
        assert "APT28 is a Russian cyber espionage group" in result
        assert "Confidence: 92.0%" in result


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
                    "id": "malware--162af3d1-a4df-4a0f-88e5-8c5b8c8c8c8c",
                    "name": "Emotet",
                    "labels": ["trojan", "backdoor"],
                    "aliases": ["Geodo", "Heodo"],
                    "malware_types": ["trojan", "backdoor"],
                    "is_family": True,
                    "description": "Emotet is a modular banking Trojan",
                    "capabilities": ["credential-theft", "lateral-movement"],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "initial-access",
                        }
                    ],
                    "associated_actors": [{"name": "TA542", "id": "intrusion-set-123"}],
                },
            }
        )

        from umbrix_mcp.server import get_malware_details
        from mcp.server.fastmcp import Context

        result = await get_malware_details("Emotet", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/get_malware_details",
            json={"malware_name": "Emotet"},
        )

        assert "Malware Analysis: Emotet" in result
        assert "Labels: trojan, backdoor" in result
        assert "Capabilities (2):" in result
        assert "credential-theft" in result


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
                    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "name": "SolarWinds Compromise",
                    "aliases": ["SUNBURST", "UNC2452"],
                    "first_seen": "2020-03-01T00:00:00Z",
                    "description": "Supply chain attack via SolarWinds Orion",
                    "objective": "Intelligence gathering",
                    "attributed_to_actors": [
                        {"name": "APT29", "id": "intrusion-set-456"}
                    ],
                    "uses_malware": [{"name": "SUNBURST", "id": "malware-789"}],
                },
            }
        )

        from umbrix_mcp.server import get_campaign_details
        from mcp.server.fastmcp import Context

        result = await get_campaign_details("SolarWinds Compromise", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/get_campaign_details",
            json={"campaign_name": "SolarWinds Compromise"},
        )

        assert "Campaign Analysis: SolarWinds Compromise" in result
        assert "Aliases: SUNBURST, UNC2452" in result
        assert "Objective: Intelligence gathering" in result


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
            json={"pattern_name": "T1566.001"},
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
            json={"vulnerability_name": "CVE-2021-44228"},
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
                            "name": "APT29",
                            "id": "intrusion-set-def",
                            "relationship_type": "similar-tactics",
                            "confidence": 0.85,
                            "first_seen": "2020-01-15T00:00:00Z",
                        },
                        {
                            "name": "Cozy Bear",
                            "id": "intrusion-set-ghi",
                            "relationship_type": "alias",
                            "confidence": 0.95,
                        },
                    ]
                },
            }
        )

        from umbrix_mcp.server import threat_correlation
        from mcp.server.fastmcp import Context

        result = await threat_correlation("actor", "APT28", "related_actors", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/threat_correlation",
            json={
                "entity_type": "actor",
                "entity_name": "APT28",
                "correlation_type": "related_actors",
            },
        )

        assert "Threat Correlation Analysis" in result
        assert "Entity: APT28 (actor)" in result
        assert "Found 2 correlations:" in result
        assert "Confidence: 0.85" in result


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
            json={"indicator": "192.168.1.100"},
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
                "ioc": "example.com",
                "ioc_type": "domain",
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
            json={"network": "192.168.1.0/24"},
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
                    "total_events": 150,
                    "summary": {
                        "most_active_actors": ["APT28", "Lazarus", "FIN7"],
                        "new_malware": 5,
                        "major_campaigns": 3,
                        "peak_activity_date": "2024-01-10",
                    },
                    "events": [
                        {
                            "date": "2024-01-15",
                            "event_type": "campaign_start",
                            "description": "New phishing campaign detected",
                            "entities": ["APT28", "Phishing Campaign 2024-01"],
                            "severity": "high",
                        },
                        {
                            "date": "2024-01-12",
                            "event_type": "malware_discovery",
                            "description": "New variant of Emotet discovered",
                            "entities": ["Emotet", "TA542"],
                            "severity": "medium",
                        },
                    ],
                },
            }
        )

        from umbrix_mcp.server import timeline_analysis
        from mcp.server.fastmcp import Context

        result = await timeline_analysis("2024-01-01", "2024-01-31", "all", Context())

        mock_http_client.post.assert_called_once_with(
            f"{mock_client.base_url}/v1/tools/timeline_analysis",
            json={
                "start_date": "2024-01-01",
                "end_date": "2024-01-31",
                "entity_filter": "all",
            },
        )

        assert "Timeline Analysis: 2024-01-01 to 2024-01-31" in result
        assert "Total Events: 150" in result
        assert "Most Active Actors: APT28, Lazarus, FIN7" in result
        assert "Peak Activity: 2024-01-10" in result
        assert "2024-01-15 - campaign_start:" in result


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
                "hunt_type": "lateral_movement",
                "parameters": parameters,
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
                "entity_name": "APT28",
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

        from umbrix_mcp.server import search_threats
        from mcp.server.fastmcp import Context

        result = await search_threats("test query", Context())

        assert "Error: Authentication failed - invalid API key" in result


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

        from umbrix_mcp.server import search_threats
        from mcp.server.fastmcp import Context

        result = await search_threats("test query", Context())

        assert "Error:" in result
        assert "Connection timeout" in result


@pytest.mark.asyncio
async def test_parameter_validation():
    """Test parameter validation for various tools"""
    from umbrix_mcp.server import (
        search_threats,
        analyze_indicator,
        get_threat_actor,
        threat_correlation,
        timeline_analysis,
    )
    from mcp.server.fastmcp import Context

    # Test empty query parameter
    with patch("umbrix_mcp.server.umbrix_client"):
        result = await search_threats("", Context())
        # Should handle empty query gracefully
        assert isinstance(result, str)

    # Test None indicator parameter
    with patch("umbrix_mcp.server.umbrix_client"):
        result = await analyze_indicator(None, Context())
        # Should handle None gracefully
        assert isinstance(result, str)


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
            search_threats,
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
            (search_threats, ("test", context)),
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
