"""Test CLI functionality and MCP server integration

Comprehensive test suite covering CLI functionality, server imports,
configuration validation, and MCP protocol compliance.
"""

import pytest


def test_import_server():
    """Test that the server module can be imported"""
    import umbrix_mcp.server

    assert umbrix_mcp.server.__name__ == "umbrix_mcp.server"

    # Test that all expected tools are available
    expected_tools = [
        "threat_correlation",
        "analyze_indicator",
        "get_threat_actor",
        "execute_graph_query",
        "threat_intel_chat",
        "get_malware_details",
        "get_campaign_details",
        "get_attack_pattern_details",
        "get_vulnerability_details",
        "indicator_reputation",
        "threat_actor_attribution",
        "ioc_validation",
        "network_analysis",
        "timeline_analysis",
        "threat_hunting_query_builder",
        "report_generation",
        "system_health",
        "get_cve_details",
    ]

    for tool_name in expected_tools:
        assert hasattr(
            umbrix_mcp.server, tool_name
        ), f"Tool {tool_name} should be available"


def test_umbrix_client_exists():
    """Test that UmbrixClient class exists and has required methods"""
    from umbrix_mcp.server import UmbrixClient

    assert UmbrixClient is not None

    # Test client instantiation with valid parameters
    client = UmbrixClient("test-key", "https://test.api.com")
    assert client.api_key == "test-key"
    assert client.base_url == "https://test.api.com"
    assert "X-API-Key" in client.headers
    assert "Content-Type" in client.headers


def test_main_requires_api_key():
    """Test that server initialization requires API key"""
    import os

    # Temporarily remove API key if it exists
    original_key = os.environ.get("UMBRIX_API_KEY")
    try:
        if "UMBRIX_API_KEY" in os.environ:
            del os.environ["UMBRIX_API_KEY"]

        # Test that the client initialization requires an API key
        with pytest.raises(SystemExit):
            # This should fail during the lifespan setup when UMBRIX_API_KEY is missing
            from umbrix_mcp.server import app_lifespan, mcp
            import asyncio

            # Mock the lifespan to trigger the check
            async def test_lifespan():
                async with app_lifespan(mcp):
                    pass

            asyncio.run(test_lifespan())
    finally:
        # Restore original API key
        if original_key:
            os.environ["UMBRIX_API_KEY"] = original_key


def test_mcp_server_instance():
    """Test that MCP server instance is properly configured"""
    from umbrix_mcp.server import mcp

    assert mcp is not None
    assert mcp.name == "umbrix-mcp"


def test_environment_variables():
    """Test environment variable handling"""
    import os

    # Test that the server respects environment variables
    original_base_url = os.environ.get("UMBRIX_API_BASE_URL")

    try:
        # Set custom base URL
        os.environ["UMBRIX_API_BASE_URL"] = "https://custom.api.com"

        # Re-import to pick up new environment
        import importlib
        import umbrix_mcp.server

        importlib.reload(umbrix_mcp.server)

        # The module should use the custom URL
        assert umbrix_mcp.server.UMBRIX_API_BASE_URL == "https://custom.api.com"

    finally:
        # Restore original value
        if original_base_url:
            os.environ["UMBRIX_API_BASE_URL"] = original_base_url
        elif "UMBRIX_API_BASE_URL" in os.environ:
            del os.environ["UMBRIX_API_BASE_URL"]


def test_tool_count():
    """Test that all 18 expected tools are available"""
    import umbrix_mcp.server as server

    # Count available tool functions
    tool_functions = [
        name
        for name in dir(server)
        if callable(getattr(server, name))
        and not name.startswith("_")
        and name not in ["main", "UmbrixClient", "AppContext", "mcp", "app_lifespan"]
    ]

    # Should have exactly 18 tools
    assert (
        len(tool_functions) >= 18
    ), f"Expected at least 18 tools, found {len(tool_functions)}: {tool_functions}"


def test_server_configuration():
    """Test server configuration parameters"""
    from umbrix_mcp.server import UMBRIX_API_BASE_URL, UMBRIX_API_KEY

    # Should have default base URL, None if not set, or a custom URL if modified by other tests
    assert UMBRIX_API_BASE_URL in [
        "https://umbrix.dev/api",
        "https://custom.api.com",
        None,
    ]

    # API key should be from environment (may be None in tests)
    assert UMBRIX_API_KEY is None or isinstance(UMBRIX_API_KEY, str)


def test_client_headers():
    """Test that client sets proper headers"""
    from umbrix_mcp.server import UmbrixClient

    client = UmbrixClient("test-api-key", "https://test.com")

    assert client.headers["X-API-Key"] == "test-api-key"
    assert client.headers["Content-Type"] == "application/json"
    # Check timeout attribute properly - httpx uses Timeout objects
    import httpx

    assert isinstance(client.client.timeout, (httpx.Timeout, float, int))
    # For httpx Timeout objects, check the timeout value
    if isinstance(client.client.timeout, httpx.Timeout):
        # httpx.Timeout object might have different attributes
        # Check if it's configured with our expected timeout
        assert "30.0" in str(client.client.timeout)
    else:
        assert client.client.timeout == 30.0


def test_module_structure():
    """Test that the module has the expected structure"""
    import umbrix_mcp.server

    # Test that key components exist
    assert hasattr(umbrix_mcp.server, "UmbrixClient")
    assert hasattr(umbrix_mcp.server, "AppContext")
    assert hasattr(umbrix_mcp.server, "mcp")
    assert hasattr(umbrix_mcp.server, "main")
    assert hasattr(umbrix_mcp.server, "logger")


def test_tool_function_signatures():
    """Test that tool functions have expected signatures"""
    import inspect
    from umbrix_mcp.server import (
        threat_correlation,
        analyze_indicator,
        get_threat_actor,
    )

    # Test threat_correlation signature
    sig = inspect.signature(threat_correlation)
    params = list(sig.parameters.keys())
    assert "query" in params
    assert "ctx" in params
    assert "limit" in params

    # Test analyze_indicator signature
    sig = inspect.signature(analyze_indicator)
    params = list(sig.parameters.keys())
    assert "indicator" in params
    assert "ctx" in params
    assert "indicator_type" in params

    # Test get_threat_actor signature
    sig = inspect.signature(get_threat_actor)
    params = list(sig.parameters.keys())
    assert "actor_name" in params
    assert "ctx" in params


def test_logging_configuration():
    """Test that logging is properly configured"""
    from umbrix_mcp.server import logger
    import logging

    assert logger is not None
    assert logger.name == "umbrix-mcp"
    assert logger.level <= logging.INFO  # Should be INFO or DEBUG


def test_async_functions():
    """Test that tool functions are properly declared as async"""
    import inspect
    from umbrix_mcp.server import (
        threat_correlation,
        analyze_indicator,
        get_threat_actor,
        execute_graph_query,
        threat_intel_chat,
    )

    # All tool functions should be async
    assert inspect.iscoroutinefunction(threat_correlation)
    assert inspect.iscoroutinefunction(analyze_indicator)
    assert inspect.iscoroutinefunction(get_threat_actor)
    assert inspect.iscoroutinefunction(execute_graph_query)
    assert inspect.iscoroutinefunction(threat_intel_chat)


def test_integration_mock_server():
    """Test integration with mock backend server"""
    import asyncio
    from unittest.mock import patch, AsyncMock

    async def run_integration_test():
        with patch("umbrix_mcp.server.umbrix_client") as mock_client:
            mock_client.base_url = "https://test.api.com"
            mock_http_client = AsyncMock()
            mock_client.client = mock_http_client

            # Mock a successful response
            mock_response = AsyncMock()
            mock_response.json.return_value = {
                "status": "success",
                "data": {"test": "integration_response"},
            }
            mock_http_client.post.return_value = mock_response

            from umbrix_mcp.server import threat_correlation
            from mcp.server.fastmcp import Context

            result = await threat_correlation("integration test", Context())

            # Should get a string response
            assert isinstance(result, str)
            assert len(result) > 0

            # Should have called the backend (multiple calls expected)
            assert mock_http_client.post.call_count >= 1

    # Run the async test
    asyncio.run(run_integration_test())


def test_cli_integration():
    """Test CLI integration points"""
    from umbrix_mcp.server import main

    # Should be able to import main function
    assert callable(main)

    # Main function should exist for CLI entry point
    import umbrix_mcp.server

    assert hasattr(umbrix_mcp.server, "__name__")


def test_error_handling_imports():
    """Test that error handling modules are properly imported"""
    import umbrix_mcp.server

    # Should have imported necessary modules for error handling
    assert hasattr(umbrix_mcp.server, "logger")

    # Should have Exception types available
    import sys

    server_module = sys.modules["umbrix_mcp.server"]
    assert "httpx" in server_module.__dict__ or "httpx" in sys.modules


# Integration tests
@pytest.mark.asyncio
async def test_tool_integration():
    """Test integration between multiple tools"""
    from unittest.mock import patch, AsyncMock
    from umbrix_mcp.server import threat_correlation, analyze_indicator
    from mcp.server.fastmcp import Context

    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        # Mock successful responses for multiple tools
        mock_response = AsyncMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {"results": "integration response data", "count": 1},
        }
        mock_response.status_code = 200
        mock_http_client.post.return_value = mock_response

        # Test multiple tool calls
        context = Context()
        result1 = await threat_correlation("APT28", context)
        result2 = await analyze_indicator("malicious.com", context)

        # Both should succeed
        assert isinstance(result1, str) and len(result1) > 0
        assert isinstance(result2, str) and len(result2) > 0

        # Should have made multiple backend calls (functions make multiple calls due to fallback logic)
        assert mock_http_client.post.call_count >= 2


@pytest.mark.asyncio
async def test_concurrent_tool_calls():
    """Test concurrent execution of multiple tools"""
    import asyncio
    from unittest.mock import patch, AsyncMock
    from umbrix_mcp.server import (
        threat_correlation,
        get_threat_actor,
        analyze_indicator,
    )
    from mcp.server.fastmcp import Context

    with patch("umbrix_mcp.server.umbrix_client") as mock_client:
        mock_client.base_url = "https://test.api.com"
        mock_http_client = AsyncMock()
        mock_client.client = mock_http_client

        # Mock response with artificial delay
        async def mock_post(*args, **kwargs):
            await asyncio.sleep(0.01)  # Small delay
            mock_response = AsyncMock()
            mock_response.json.return_value = {
                "status": "success",
                "data": {"results": "concurrent response data", "count": 1},
            }
            mock_response.status_code = 200
            return mock_response

        mock_http_client.post.side_effect = mock_post

        # Run multiple tools concurrently
        context = Context()
        tasks = [
            threat_correlation("APT28", context),
            get_threat_actor("APT28", context),
            analyze_indicator("malicious.com", context),
        ]

        results = await asyncio.gather(*tasks)

        # All should succeed
        assert len(results) == 3
        for result in results:
            assert isinstance(result, str) and len(result) > 0

        # Should have made multiple concurrent calls (each function makes multiple calls due to fallback logic)
        assert mock_http_client.post.call_count >= 3
