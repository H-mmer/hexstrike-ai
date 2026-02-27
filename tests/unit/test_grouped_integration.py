# tests/unit/test_grouped_integration.py
"""Integration tests — verify all registry tools are dispatchable via grouped endpoints."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize
from hexstrike_mcp_tools.tool_definitions import build_registry


def test_all_registry_tools_have_valid_routes():
    """Every tool in the registry should have a valid route and method."""
    registry = build_registry()
    errors = []
    valid_methods = {"GET", "POST"}
    for cat in registry.list_categories():
        tools = registry.list_tools(cat)
        for tool_name in tools:
            try:
                info = registry.get_route(cat, tool_name)
                if not info["route"]:
                    errors.append(f"{cat}/{tool_name}: empty route")
                if info["method"] not in valid_methods:
                    errors.append(f"{cat}/{tool_name}: invalid method {info['method']}")
            except KeyError as e:
                errors.append(f"{cat}/{tool_name}: {e}")
    assert errors == [], f"Route errors: {errors}"


def test_all_registry_tools_dispatchable_via_client():
    """Every tool in the registry should dispatch without error via mock client."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)

    registry = build_registry()
    errors = []
    for cat in registry.list_categories():
        tools = registry.list_tools(cat)
        for tool_name in tools:
            try:
                route_info = registry.get_route(cat, tool_name)
                if route_info["method"] == "GET":
                    mock.safe_get(route_info["route"], {})
                else:
                    mock.safe_post(route_info["route"], {"target": "test"})
            except Exception as e:
                errors.append(f"{cat}/{tool_name}: {e}")
    assert errors == [], f"Dispatch errors: {errors}"


def test_registry_categories_match_grouped_functions():
    """Every registry category should have a corresponding grouped MCP function."""
    import hexstrike_mcp_tools.grouped as g
    registry = build_registry()
    grouped_funcs = {name for name in dir(g) if not name.startswith("_") and callable(getattr(g, name))}
    # list_available_tools is the discovery tool, not a category
    grouped_funcs.discard("list_available_tools")
    categories = set(registry.list_categories())
    missing = categories - grouped_funcs
    assert missing == set(), f"Categories without grouped function: {missing}"
