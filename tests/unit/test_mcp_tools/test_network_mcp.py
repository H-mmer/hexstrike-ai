# tests/unit/test_mcp_tools/test_network_mcp.py
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize

def setup_mock_client():
    mock_client = MagicMock()
    mock_client.safe_post.return_value = {"success": True, "output": "result"}
    mock_client.safe_get.return_value = {"success": True, "output": "result"}
    initialize(mock_client)
    return mock_client

def test_network_tools_importable():
    setup_mock_client()
    import hexstrike_mcp_tools.network
    assert True

def test_nmap_scan_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.network as net
    result = net.nmap_scan("127.0.0.1")
    mock_client.safe_post.assert_called()
    call_args = mock_client.safe_post.call_args
    assert "nmap" in call_args[0][0]

def test_rustscan_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.network as net
    result = net.rustscan("127.0.0.1")
    mock_client.safe_post.assert_called()

def test_amass_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.network as net
    result = net.amass_enum("example.com")
    mock_client.safe_post.assert_called()

def test_naabu_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.network as net
    result = net.naabu_port_scan("127.0.0.1")
    mock_client.safe_post.assert_called()
