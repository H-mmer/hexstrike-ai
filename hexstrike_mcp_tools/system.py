# hexstrike_mcp_tools/system.py
"""MCP tool registrations for system/infrastructure tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def check_server_health() -> Dict[str, Any]:
    """Check HexStrike server health and available tools."""
    return get_client().safe_get("health")


@mcp.tool()
def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """Execute a shell command via the HexStrike server."""
    return get_client().safe_post("api/command", {"command": command, "use_cache": use_cache})


@mcp.tool()
def get_cache_stats() -> Dict[str, Any]:
    """Get server cache performance statistics."""
    return get_client().safe_get("api/cache/stats")


@mcp.tool()
def list_processes() -> Dict[str, Any]:
    """List all running tool processes on the server."""
    return get_client().safe_get("api/processes/list")


@mcp.tool()
def get_telemetry() -> Dict[str, Any]:
    """Get server telemetry — uptime, request count, error count."""
    return get_client().safe_get("api/telemetry")


@mcp.tool()
def clear_cache() -> Dict[str, Any]:
    """Clear all entries from the server cache."""
    return get_client().safe_post("api/cache/clear", {})
