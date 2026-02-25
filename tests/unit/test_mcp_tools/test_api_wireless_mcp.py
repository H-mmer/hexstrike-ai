"""Unit tests for hexstrike_mcp_tools/api_security.py and wireless.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True, "output": "test"}
    initialize(mock)
    return mock


# ---------------------------------------------------------------------------
# API Security MCP tools
# ---------------------------------------------------------------------------

def test_api_discover_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.api_security as m
    result = m.api_discover("http://example.com")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "discover" in path


def test_api_fuzz_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.api_security as m
    result = m.api_fuzz("http://example.com")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "fuzz" in path


def test_api_auth_test_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.api_security as m
    result = m.api_auth_test("http://example.com")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "auth" in path


def test_api_monitoring_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.api_security as m
    result = m.api_monitoring("http://example.com")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "monitoring" in path


# ---------------------------------------------------------------------------
# Wireless MCP tools
# ---------------------------------------------------------------------------

def test_wifi_attack_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.wireless as m
    result = m.wifi_attack("wlan0")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "wifi" in path


def test_bluetooth_scan_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.wireless as m
    result = m.bluetooth_scan()
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "bluetooth" in path


def test_rf_analysis_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.wireless as m
    result = m.rf_analysis()
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "rf" in path
