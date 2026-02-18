# tests/unit/test_mcp_tools/test_mcp_scaffold.py
from unittest.mock import MagicMock

def test_initialize_sets_client():
    from hexstrike_mcp_tools import get_client, initialize
    mock_client = MagicMock()
    initialize(mock_client)
    assert get_client() is mock_client

def test_client_import():
    from hexstrike_mcp_tools.client import HexStrikeClient
    assert callable(HexStrikeClient)

def test_get_client_raises_before_init():
    # Reset the module state
    import hexstrike_mcp_tools
    hexstrike_mcp_tools._client = None
    try:
        hexstrike_mcp_tools.get_client()
        assert False, "Should have raised RuntimeError"
    except RuntimeError:
        pass
