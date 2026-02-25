# hexstrike_mcp_tools/api_security.py
"""MCP tool registrations for API security tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def api_discover(base_url: str, schema_url: str = "") -> Dict[str, Any]:
    """API endpoint discovery and schema analysis (Swagger, GraphQL introspection, kiterunner)."""
    return get_client().safe_post("api/tools/api/discover", {"base_url": base_url, "schema_url": schema_url})


@mcp.tool()
def api_fuzz(base_url: str, wordlist: str = "") -> Dict[str, Any]:
    """API endpoint fuzzing using rest-attacker."""
    return get_client().safe_post("api/tools/api/fuzz", {"base_url": base_url, "wordlist": wordlist})


@mcp.tool()
def api_auth_test(base_url: str, jwt_token: str = "") -> Dict[str, Any]:
    """API authentication vulnerability testing — JWT, OAuth, API keys."""
    return get_client().safe_post("api/tools/api/auth-test", {"base_url": base_url, "jwt_token": jwt_token})


@mcp.tool()
def api_monitoring(base_url: str) -> Dict[str, Any]:
    """API security monitoring and rate-limit testing."""
    return get_client().safe_post("api/tools/api/monitoring", {"base_url": base_url})
