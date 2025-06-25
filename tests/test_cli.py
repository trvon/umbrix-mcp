"""Test CLI functionality"""

import pytest


def test_import_server():
    """Test that the server module can be imported"""
    import umbrix_mcp.server
    assert umbrix_mcp.server.__name__ == "umbrix_mcp.server"


def test_umbrix_client_exists():
    """Test that UmbrixClient class exists"""
    from umbrix_mcp.server import UmbrixClient
    assert UmbrixClient is not None


def test_main_requires_api_key():
    """Test that server initialization requires API key"""
    import os
    
    # Temporarily remove API key if it exists
    original_key = os.environ.get('UMBRIX_API_KEY')
    try:
        if 'UMBRIX_API_KEY' in os.environ:
            del os.environ['UMBRIX_API_KEY']
        
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
            os.environ['UMBRIX_API_KEY'] = original_key