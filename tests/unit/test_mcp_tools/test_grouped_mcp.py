# tests/unit/test_mcp_tools/test_grouped_mcp.py
"""Tests for grouped MCP tool endpoints."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize


def setup_mock():
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)
    return mock


def test_network_scan_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import network_scan
    network_scan("nmap", "10.0.0.1")
    m.safe_post.assert_called()
    assert "nmap" in m.safe_post.call_args[0][0]


def test_network_scan_unknown_tool():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import network_scan
    result = network_scan("nonexistent_tool", "10.0.0.1")
    assert "error" in result


def test_web_scan_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import web_scan
    web_scan("gobuster", "http://example.com")
    m.safe_post.assert_called()


def test_cloud_assess_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import cloud_assess
    cloud_assess("trivy", params={"target": "nginx:latest"})
    m.safe_post.assert_called()


def test_system_admin_get():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import system_admin
    system_admin("health")
    m.safe_get.assert_called()


def test_list_available_tools():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import list_available_tools
    result = list_available_tools()
    assert isinstance(result, dict)
    assert "network_scan" in result


def test_binary_analyze_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import binary_analyze
    binary_analyze("checksec", params={"binary": "/tmp/test"})
    m.safe_post.assert_called()


def test_network_scan_zmap_maps_target_network():
    """Verify zmap uses target_network param instead of target."""
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import network_scan
    network_scan("zmap", "10.0.0.0/24", params={"port": "80"})
    call_params = m.safe_post.call_args[0][1]
    assert "target_network" in call_params, f"Expected target_network, got: {call_params}"
    assert "target" not in call_params, "zmap should NOT have 'target' param"


def test_intelligence_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import intelligence
    intelligence("analyze-target", params={"target": "example.com"})
    m.safe_post.assert_called()


def test_osint_gather_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import osint_gather
    osint_gather("passive-recon", params={"domain": "example.com"})
    m.safe_post.assert_called()


def test_mobile_test_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import mobile_test
    mobile_test("apk-analyze", params={"apk_path": "/tmp/test.apk"})
    m.safe_post.assert_called()


def test_wireless_test_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import wireless_test
    wireless_test("wifi-attack", params={"interface": "wlan0"})
    m.safe_post.assert_called()


def test_api_test_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import api_test
    api_test("api-discover", params={"base_url": "http://api.example.com"})
    m.safe_post.assert_called()
