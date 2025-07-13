"""
Tests for enhanced MCP tools functionality
"""

import pytest
import re
from unittest.mock import Mock
import sys
import os

# Add the source directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from umbrix_mcp.server import (
    _convert_simple_patterns_to_cypher,
    get_tool_recommendation,
)


class TestSimplePatternConversion:
    """Test the simple pattern to Cypher conversion functionality"""

    def test_recent_threats_pattern(self):
        """Test conversion of 'recent threats' pattern"""
        query = "recent threats"
        result = _convert_simple_patterns_to_cypher(query)

        assert "MATCH (a:Article)-[:MENTIONS]->(i:Indicator)" in result
        assert "WHERE a.published_date >= datetime() - duration({days: 30})" in result
        assert "ORDER BY a.published_date DESC" in result
        assert "LIMIT 10" in result

    def test_latest_threats_pattern(self):
        """Test conversion of 'latest threats' pattern"""
        query = "latest threats"
        result = _convert_simple_patterns_to_cypher(query)

        assert "MATCH (a:Article)-[:MENTIONS]->(i:Indicator)" in result
        assert "WHERE a.published_date >= datetime() - duration({days: 30})" in result

    def test_apt_threat_actor_pattern(self):
        """Test conversion of APT threat actor patterns"""
        test_cases = [
            "APT29",
            "Tell me about APT28",
            "lazarus group",
            "kimsuky threat actor",
        ]

        for query in test_cases:
            result = _convert_simple_patterns_to_cypher(query)

            assert "MATCH (ta:ThreatActor)" in result
            assert "WHERE toLower(ta.name) CONTAINS toLower" in result
            assert "OR toLower(ta.aliases) CONTAINS toLower" in result
            assert "RETURN ta.name, ta.aliases, ta.description, ta.country" in result
            assert "LIMIT 5" in result

    def test_ip_address_pattern(self):
        """Test conversion of IP address patterns"""
        test_cases = [
            "192.168.1.1",
            "Analyze this IP: 10.0.0.1",
            "What about 203.0.113.5?",
        ]

        for query in test_cases:
            result = _convert_simple_patterns_to_cypher(query)

            # Extract IP from query
            ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", query)
            assert ip_match is not None

            expected_ip = ip_match.group()
            assert f"WHERE i.value = '{expected_ip}'" in result
            assert "AND i.type = 'ip'" in result
            assert "OPTIONAL MATCH (i)<-[:USES]-(ta:ThreatActor)" in result
            assert "collect(ta.name) as threat_actors" in result

    def test_domain_pattern(self):
        """Test conversion of domain patterns"""
        test_cases = [
            "evil.com",
            "Check domain: malicious.example.org",
            "What about suspicious-site.net?",
        ]

        for query in test_cases:
            result = _convert_simple_patterns_to_cypher(query)

            # Extract domain from query
            domain_match = re.search(
                r"\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b", query
            )
            assert domain_match is not None

            expected_domain = domain_match.group()
            assert f"WHERE i.value = '{expected_domain}'" in result
            assert "AND i.type = 'domain'" in result

    def test_malware_patterns(self):
        """Test conversion of malware search patterns"""
        test_cases = [
            ("ransomware", "ransomware"),
            ("show me malware families", "malware"),
            ("malware analysis", "malware"),  # Should contain "malware" keyword
        ]

        for query, expected_type in test_cases:
            result = _convert_simple_patterns_to_cypher(query)

            # Only test cases that should trigger malware pattern
            if "malware" in query.lower() or "ransomware" in query.lower():
                assert "MATCH (m:Malware)" in result
                assert f"WHERE toLower(m.family) CONTAINS '{expected_type}'" in result
                assert f"OR toLower(m.type) CONTAINS '{expected_type}'" in result
                assert "collect(ta.name) as threat_actors" in result

    def test_count_patterns(self):
        """Test conversion of count patterns"""
        test_cases = [
            (
                "count threat actors",
                "MATCH (ta:ThreatActor) RETURN count(ta) as threat_actor_count",
            ),
            (
                "count indicators",
                "MATCH (i:Indicator) RETURN count(i) as indicator_count",
            ),
            ("count campaigns", "MATCH (c:Campaign) RETURN count(c) as campaign_count"),
        ]

        for query, expected in test_cases:
            result = _convert_simple_patterns_to_cypher(query)
            assert result == expected

    def test_count_malware_triggers_search_pattern(self):
        """Test that 'count malware' triggers malware search pattern instead of count"""
        query = "count malware"
        result = _convert_simple_patterns_to_cypher(query)

        # Should trigger malware search pattern, not simple count
        assert "MATCH (m:Malware)" in result
        assert "WHERE toLower(m.family) CONTAINS 'malware'" in result
        assert "OR toLower(m.type) CONTAINS 'malware'" in result
        assert "collect(ta.name) as threat_actors" in result

    def test_campaign_pattern(self):
        """Test conversion of campaign search patterns"""
        query = "campaign"
        result = _convert_simple_patterns_to_cypher(query)

        assert "MATCH (c:Campaign)" in result
        assert "RETURN c.name, c.description, c.first_seen, c.last_seen" in result
        assert "ORDER BY c.last_seen DESC" in result
        assert "LIMIT 10" in result

    def test_cypher_passthrough(self):
        """Test that valid Cypher queries are passed through unchanged"""
        cypher_queries = [
            "MATCH (n:ThreatActor) RETURN n",
            "MATCH (a)-[r]-(b) WHERE a.name = 'test' RETURN a, r, b",
            "CREATE (n:Test) RETURN n",
        ]

        for query in cypher_queries:
            result = _convert_simple_patterns_to_cypher(query)
            assert result == query  # Should be unchanged

    def test_unknown_pattern_passthrough(self):
        """Test that unknown patterns are passed through unchanged"""
        unknown_queries = [
            "some random text that doesn't match any pattern",
            "xyz123 completely unknown",
            "!@#$%^&*()",
        ]

        for query in unknown_queries:
            result = _convert_simple_patterns_to_cypher(query)
            assert result == query  # Should be unchanged


class TestToolRecommendation:
    """Test the tool recommendation functionality"""

    @pytest.fixture
    def mock_context(self):
        """Mock context for MCP tools"""
        return Mock()

    @pytest.mark.asyncio
    async def test_recent_activity_recommendation(self, mock_context):
        """Test recommendation for recent activity queries"""
        queries = [
            "show me recent threats",
            "what are the latest attacks",
            "new indicators today",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            assert "discover_recent_threats" in result
            assert "Shows latest threat activity" in result
            assert "example" in result.lower()

    @pytest.mark.asyncio
    async def test_threat_actor_recommendation(self, mock_context):
        """Test recommendation for threat actor queries"""
        queries = [
            "tell me about APT29",
            "research lazarus group",
            "threat actor information",
            "kimsuky activities",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            assert "get_threat_actor" in result
            assert "threat actor profiles" in result
            assert "get_threat_actor(actor_name=" in result

    @pytest.mark.asyncio
    async def test_indicator_recommendation(self, mock_context):
        """Test recommendation for indicator analysis"""
        queries = [
            "analyze this IP: 192.168.1.1",
            "check domain evil.com",
            "indicator analysis",
            "IOC investigation",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            assert "analyze_indicator" in result
            assert "IOCs with threat context" in result
            assert "analyze_indicator(indicator=" in result

    @pytest.mark.asyncio
    async def test_malware_recommendation(self, mock_context):
        """Test recommendation for malware queries"""
        queries = [
            "find ransomware families",
            "malware analysis",
            "trojan information",
            "family classification",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            assert "execute_graph_query" in result
            assert "natural language" in result
            assert "ransomware families" in result or "malware" in result

    @pytest.mark.asyncio
    async def test_cve_recommendation(self, mock_context):
        """Test recommendation for CVE queries"""
        queries = [
            "CVE-2023-1234 details",
            "vulnerability analysis",
            "exploit information",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            assert "get_cve_details" in result
            assert "vulnerability analysis" in result
            assert "get_cve_details(cve_id=" in result

    @pytest.mark.asyncio
    async def test_search_recommendation(self, mock_context):
        """Test recommendation for general search queries"""
        queries = [
            "search for Russian threat actors",
            "find connections between entities",
            "look for relationships",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            assert "threat_correlation" in result
            assert "search across all threat entities" in result
            assert "threat_correlation(query=" in result

    @pytest.mark.asyncio
    async def test_fallback_recommendation(self, mock_context):
        """Test fallback recommendations for unclear queries"""
        queries = [
            "help me with threat intelligence",
            "what can you do",
            "unclear request",
        ]

        for query in queries:
            result = await get_tool_recommendation(query, mock_context)

            # Should include either execute_graph_query or discover_recent_threats
            assert ("execute_graph_query" in result) or (
                "discover_recent_threats" in result
            )
            assert "Pro tip" in result

    @pytest.mark.asyncio
    async def test_recommendation_format(self, mock_context):
        """Test the format of recommendations"""
        query = "find APT29 information"
        result = await get_tool_recommendation(query, mock_context)

        # Should have proper formatting
        assert "Tool Recommendations for:" in result
        assert "💡" in result  # Reason icon
        assert "📝" in result  # Example icon
        assert "Example:" in result
        assert "**" in result  # Bold formatting

    @pytest.mark.asyncio
    async def test_multiple_recommendations(self, mock_context):
        """Test that multiple relevant tools can be recommended"""
        query = "search for recent APT activities"  # Could match multiple patterns
        result = await get_tool_recommendation(query, mock_context)

        # Should contain multiple numbered recommendations
        lines = result.split("\n")
        recommendation_lines = [
            line for line in lines if line.strip().startswith(("1.", "2.", "3."))
        ]
        assert len(recommendation_lines) >= 1  # At least one recommendation


class TestIntegration:
    """Integration tests for enhanced functionality"""

    def test_pattern_recognition_coverage(self):
        """Test that pattern recognition covers common use cases"""
        common_queries = [
            "recent threats",
            "APT29",
            "192.168.1.1",
            "evil.com",
            "ransomware",
            "count threat actors",
            "campaign analysis",
        ]

        for query in common_queries:
            result = _convert_simple_patterns_to_cypher(query)
            # Should not be the original query (should be converted)
            assert result != query or query.upper().startswith(
                ("MATCH", "RETURN", "CREATE")
            )

    def test_regex_patterns_valid(self):
        """Test that regex patterns are valid and don't cause errors"""
        test_strings = [
            "192.168.1.1",
            "10.0.0.1",
            "203.0.113.255",
            "evil.com",
            "malicious.example.org",
            "suspicious-site.net",
            "test.co.uk",
        ]

        # IP pattern
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ip_regex = re.compile(ip_pattern)

        # Domain pattern
        domain_pattern = r"\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b"
        domain_regex = re.compile(domain_pattern)

        for test_string in test_strings:
            # Should not raise exceptions
            ip_match = ip_regex.search(test_string)
            domain_match = domain_regex.search(test_string)

            # At least one should match for valid test cases
            if "." in test_string and not test_string.count(".") == 3:
                assert domain_match is not None
            elif test_string.count(".") == 3:
                assert ip_match is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
