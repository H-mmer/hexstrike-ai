# tests/unit/test_mcp_tools/test_system_mcp_gap.py
"""Tests for new system + workflow MCP tool wrappers (Phase 5b, Task 20)."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize


def setup_mock():
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)
    return mock


def test_get_telemetry():
    m = setup_mock()
    from hexstrike_mcp_tools.system import get_telemetry
    get_telemetry()
    m.safe_get.assert_called()
    assert "api/telemetry" in m.safe_get.call_args[0][0]


def test_clear_cache():
    m = setup_mock()
    from hexstrike_mcp_tools.system import clear_cache
    clear_cache()
    m.safe_post.assert_called()
    assert "api/cache/clear" in m.safe_post.call_args[0][0]


def test_optimize_tool_parameters():
    m = setup_mock()
    from hexstrike_mcp_tools.workflows import optimize_tool_parameters
    optimize_tool_parameters("10.0.0.1", "nmap")
    m.safe_post.assert_called()
    assert "api/intelligence/optimize-parameters" in m.safe_post.call_args[0][0]
