# hexstrike_mcp_tools/__init__.py
"""HexStrike MCP tool registration modules."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hexstrike-ai-mcp")

_client = None


def initialize(client) -> None:
    """Set the HexStrike API client for all tool modules."""
    global _client
    _client = client


def get_client():
    """Get the initialized client. Raises RuntimeError if not yet initialized."""
    if _client is None:
        raise RuntimeError("Call hexstrike_mcp_tools.initialize(client) before using tools.")
    return _client
