"""Unit tests for hexstrike_mcp_tools/binary.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    initialize(mock)
    return mock


def test_binary_tools_importable():
    _mock_client()
    import hexstrike_mcp_tools.binary  # noqa: F401
    assert True


def test_gdb_debug_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.gdb_debug("/tmp/test_binary", commands="info functions")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "gdb" in path


def test_binwalk_scan_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.binwalk_scan("/tmp/firmware.bin")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "binwalk" in path


def test_yara_malware_scan_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.yara_malware_scan("/tmp/sample.exe", rules="/tmp/rules.yar")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "yara" in path


def test_floss_string_extract_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.floss_string_extract("/tmp/malware.exe")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "floss" in path


def test_rizin_analyze_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.rizin_analyze("/tmp/test_binary")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "rizin" in path


def test_ghidra_analyze_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.ghidra_analyze("/tmp/test_binary")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "ghidra" in path


def test_volatility3_memory_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.volatility3_memory("/tmp/memory.raw", "windows.pslist")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "volatility" in path


def test_forensics_analyze_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.binary as b
    b.forensics_analyze("/tmp/disk.img")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "forensics" in path
