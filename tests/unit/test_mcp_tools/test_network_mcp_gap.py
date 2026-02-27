# tests/unit/test_mcp_tools/test_network_mcp_gap.py
"""Tests for new network MCP tool wrappers (Phase 5b, Task 19)."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize


def setup_mock():
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)
    return mock


def test_nmap_advanced_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import nmap_advanced_scan
    nmap_advanced_scan("10.0.0.1")
    m.safe_post.assert_called()
    assert "api/tools/nmap-advanced" in m.safe_post.call_args[0][0]


def test_fierce_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import fierce_scan
    fierce_scan("example.com")
    assert "api/tools/fierce" in m.safe_post.call_args[0][0]


def test_autorecon_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import autorecon_scan
    autorecon_scan("10.0.0.1")
    assert "api/tools/autorecon" in m.safe_post.call_args[0][0]


def test_nbtscan_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import nbtscan_scan
    nbtscan_scan("10.0.0.0/24")
    assert "api/tools/nbtscan" in m.safe_post.call_args[0][0]


def test_scapy_probe():
    m = setup_mock()
    from hexstrike_mcp_tools.network import scapy_probe
    scapy_probe("10.0.0.1")
    assert "api/tools/network/scapy" in m.safe_post.call_args[0][0]


def test_ipv6_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import ipv6_scan
    ipv6_scan("::1")
    assert "api/tools/network/ipv6-toolkit" in m.safe_post.call_args[0][0]


def test_udp_proto_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import udp_proto_scan
    udp_proto_scan("10.0.0.1")
    assert "api/tools/network/udp-proto-scanner" in m.safe_post.call_args[0][0]


def test_cisco_torch_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import cisco_torch_scan
    cisco_torch_scan("10.0.0.1")
    assert "api/tools/network/cisco-torch" in m.safe_post.call_args[0][0]


def test_enum4linux_ng_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import enum4linux_ng_scan
    enum4linux_ng_scan("10.0.0.1")
    assert "api/tools/enum4linux-ng" in m.safe_post.call_args[0][0]
