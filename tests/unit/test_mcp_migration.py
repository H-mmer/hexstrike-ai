# tests/unit/test_mcp_migration.py
"""Verify MCP migration: only grouped.py registers @mcp.tool() decorators."""
import ast
import pathlib

MCP_DIR = pathlib.Path("hexstrike_mcp_tools")
ALLOWED_FILES = {"grouped.py"}


def test_no_mcp_tool_decorators_in_old_modules():
    """Old MCP modules must NOT have @mcp.tool() decorators."""
    violations = []
    for py_file in MCP_DIR.glob("*.py"):
        if py_file.name in ALLOWED_FILES or py_file.name.startswith("_"):
            continue
        if py_file.name in ("registry.py", "tool_definitions.py", "client.py"):
            continue
        source = py_file.read_text()
        if "@mcp.tool()" in source:
            violations.append(py_file.name)
    assert violations == [], f"@mcp.tool() found in old modules: {violations}"


def test_grouped_has_mcp_tools():
    """grouped.py must register MCP tools."""
    source = (MCP_DIR / "grouped.py").read_text()
    count = source.count("@mcp.tool()")
    assert count >= 22, f"Expected >=22 @mcp.tool() in grouped.py, found {count}"


def test_launcher_imports_grouped():
    """hexstrike_mcp.py must import grouped module."""
    source = pathlib.Path("hexstrike_mcp.py").read_text()
    assert "hexstrike_mcp_tools.grouped" in source
