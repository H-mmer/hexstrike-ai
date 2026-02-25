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


def test_system_tools_importable():
    """system.py should import without error and register MCP tools."""
    from unittest.mock import MagicMock
    import hexstrike_mcp_tools
    hexstrike_mcp_tools.initialize(MagicMock())
    import hexstrike_mcp_tools.system  # triggers @mcp.tool() registrations
    assert True  # If we get here, import succeeded


def test_execute_command_calls_api():
    from unittest.mock import MagicMock
    import hexstrike_mcp_tools
    import hexstrike_mcp_tools.system as sys_mod

    mock_client = MagicMock()
    mock_client.safe_post.return_value = {"success": True, "output": "hello"}
    hexstrike_mcp_tools.initialize(mock_client)

    # Call the underlying function (not via MCP protocol, just directly)
    result = sys_mod.execute_command.__wrapped__("echo hello") if hasattr(sys_mod.execute_command, '__wrapped__') else sys_mod.execute_command("echo hello")
    mock_client.safe_post.assert_called_once()
    call_args = mock_client.safe_post.call_args
    assert call_args[0][0] == "api/command"


def test_all_mcp_tool_modules_importable():
    """All hexstrike_mcp_tools submodules should import without error."""
    import hexstrike_mcp_tools
    from hexstrike_mcp_tools import initialize
    from unittest.mock import MagicMock
    initialize(MagicMock())

    import hexstrike_mcp_tools.network
    import hexstrike_mcp_tools.web
    import hexstrike_mcp_tools.cloud
    import hexstrike_mcp_tools.binary
    import hexstrike_mcp_tools.mobile
    import hexstrike_mcp_tools.api_security
    import hexstrike_mcp_tools.wireless
    import hexstrike_mcp_tools.osint
    import hexstrike_mcp_tools.workflows
    import hexstrike_mcp_tools.system
