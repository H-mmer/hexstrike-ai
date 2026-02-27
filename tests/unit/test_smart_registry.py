# tests/unit/test_smart_registry.py
"""Tests for SmartToolRegistry."""
import pytest
from hexstrike_mcp_tools.registry import SmartToolRegistry


@pytest.fixture
def registry():
    r = SmartToolRegistry()
    r.register("network_scan", "nmap", "api/tools/nmap", method="POST",
               description="Network scanner")
    r.register("network_scan", "rustscan", "api/tools/rustscan", method="POST",
               description="Fast port scanner")
    r.register("system_admin", "health", "health", method="GET",
               description="Health check")
    return r


def test_register_and_list_category(registry):
    tools = registry.list_tools("network_scan")
    assert "nmap" in tools
    assert "rustscan" in tools
    assert len(tools) == 2


def test_list_all_categories(registry):
    all_tools = registry.list_tools()
    assert "network_scan" in all_tools
    assert "system_admin" in all_tools


def test_get_route(registry):
    route_info = registry.get_route("network_scan", "nmap")
    assert route_info["route"] == "api/tools/nmap"
    assert route_info["method"] == "POST"


def test_get_route_unknown_tool(registry):
    with pytest.raises(KeyError):
        registry.get_route("network_scan", "nonexistent")


def test_get_route_unknown_category(registry):
    with pytest.raises(KeyError):
        registry.get_route("nonexistent", "nmap")


def test_list_categories(registry):
    cats = registry.list_categories()
    assert "network_scan" in cats
    assert "system_admin" in cats


def test_tool_count(registry):
    assert registry.tool_count() == 3


def test_register_duplicate_overwrites(registry):
    registry.register("network_scan", "nmap", "api/tools/nmap-v2", method="POST",
                      description="Updated nmap")
    route_info = registry.get_route("network_scan", "nmap")
    assert route_info["route"] == "api/tools/nmap-v2"
