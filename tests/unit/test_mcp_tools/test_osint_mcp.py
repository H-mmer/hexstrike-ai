"""Unit tests for hexstrike_mcp_tools/osint.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True, "output": "test"}
    initialize(mock)
    return mock


def test_osint_passive_recon_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.osint as m
    result = m.osint_passive_recon("example.com")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called_once()
    path = mock.safe_post.call_args[0][0]
    assert "passive-recon" in path or "osint" in path


def test_osint_threat_intel_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.osint as m
    result = m.osint_threat_intel("8.8.8.8")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called_once()
    path = mock.safe_post.call_args[0][0]
    assert "threat-intel" in path or "osint" in path


def test_osint_social_recon_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.osint as m
    result = m.osint_social_recon(username="testuser")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called_once()
    path = mock.safe_post.call_args[0][0]
    assert "social-recon" in path or "osint" in path


def test_osint_breach_check_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.osint as m
    result = m.osint_breach_check("test@example.com")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called_once()
    path = mock.safe_post.call_args[0][0]
    assert "breach-check" in path or "osint" in path


def test_osint_shodan_search_mcp():
    mock = _mock_client()
    import hexstrike_mcp_tools.osint as m
    result = m.osint_shodan_search("nginx port:443")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called_once()
    path = mock.safe_post.call_args[0][0]
    assert "shodan" in path or "osint" in path
