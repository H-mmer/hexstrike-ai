# tests/unit/test_tool_definitions.py
"""Tests for tool_definitions — registry population."""
from hexstrike_mcp_tools.tool_definitions import build_registry


def test_registry_has_all_categories():
    r = build_registry()
    expected = [
        "network_scan", "network_recon", "network_enum", "network_advanced",
        "web_scan", "web_vuln_test", "web_specialized",
        "cloud_assess", "cloud_container",
        "binary_analyze", "binary_forensics",
        "mobile_test", "api_test", "wireless_test", "osint_gather",
        "intelligence", "ctf", "bugbounty",
        "async_scan", "browser_stealth", "system_admin",
    ]
    cats = r.list_categories()
    for cat in expected:
        assert cat in cats, f"Missing category: {cat}"


def test_registry_tool_count():
    r = build_registry()
    assert r.tool_count() >= 114, f"Expected >=114 tools, got {r.tool_count()}"


def test_exact_route_mappings():
    """Validate specific (category, tool, route, method) tuples to catch param drift."""
    r = build_registry()
    spot_checks = [
        ("network_scan", "zmap", "api/tools/network/zmap", "POST"),
        ("network_recon", "httpx", "api/tools/httpx", "POST"),
        ("network_enum", "smbmap", "api/tools/smbmap", "POST"),
        ("web_vuln_test", "sqlmap", "api/tools/sqlmap", "POST"),
        ("system_admin", "health", "health", "GET"),
        ("system_admin", "telemetry", "api/telemetry", "GET"),
        ("browser_stealth", "navigate", "/api/browser/navigate", "POST"),
        ("mobile_test", "apk-analyze", "api/tools/mobile/apk-analyze", "POST"),
    ]
    for cat, tool, expected_route, expected_method in spot_checks:
        info = r.get_route(cat, tool)
        assert info["route"] == expected_route, f"{cat}/{tool}: route={info['route']}, expected={expected_route}"
        assert info["method"] == expected_method, f"{cat}/{tool}: method={info['method']}, expected={expected_method}"


def test_network_scan_has_expected_tools():
    r = build_registry()
    tools = r.list_tools("network_scan")
    for name in ["nmap", "rustscan", "masscan", "naabu", "zmap", "nmap-advanced"]:
        assert name in tools, f"Missing network_scan tool: {name}"


def test_web_scan_has_expected_tools():
    r = build_registry()
    tools = r.list_tools("web_scan")
    for name in ["gobuster", "nuclei", "nikto", "ffuf", "feroxbuster", "dirsearch", "wfuzz", "katana"]:
        assert name in tools, f"Missing web_scan tool: {name}"


def test_system_admin_has_expected_tools():
    r = build_registry()
    tools = r.list_tools("system_admin")
    for name in ["health", "command", "cache-stats", "cache-clear", "telemetry", "processes"]:
        assert name in tools, f"Missing system_admin tool: {name}"


def test_every_tool_has_route():
    r = build_registry()
    all_tools = r.list_tools()
    for cat, tools in all_tools.items():
        for tool_name in tools:
            info = r.get_route(cat, tool_name)
            assert "route" in info, f"{cat}/{tool_name} missing route"
            assert info["route"], f"{cat}/{tool_name} has empty route"
