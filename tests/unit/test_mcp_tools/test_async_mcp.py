# tests/unit/test_mcp_tools/test_async_mcp.py
"""Tests for hexstrike_mcp_tools.async_tools — async scan wrappers."""
from unittest.mock import MagicMock, patch
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def setup_mock_client():
    mock_client = MagicMock()
    mock_client.safe_post.return_value = {"success": True, "task_id": "abc-123"}
    mock_client.server_url = "http://127.0.0.1:8888"
    initialize(mock_client)
    return mock_client


# --- Importability tests ---

def test_mcp_async_nmap_module_importable():
    from hexstrike_mcp_tools import async_tools
    assert hasattr(async_tools, 'nmap_scan_async')


def test_mcp_async_nuclei_module_importable():
    from hexstrike_mcp_tools import async_tools
    assert hasattr(async_tools, 'nuclei_scan_async')


def test_mcp_get_task_status_importable():
    from hexstrike_mcp_tools import async_tools
    assert hasattr(async_tools, 'get_task_status')


def test_mcp_gobuster_async_importable():
    from hexstrike_mcp_tools import async_tools
    assert hasattr(async_tools, 'gobuster_async')


# --- Functional tests ---

def test_nmap_scan_async_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    result = at.nmap_scan_async("127.0.0.1")
    mock_client.safe_post.assert_called()
    call_args = mock_client.safe_post.call_args
    assert "nmap" in call_args[0][0]
    assert "async" in call_args[0][0]


def test_nmap_scan_async_passes_scan_type():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    at.nmap_scan_async("10.0.0.1", scan_type="-sC -sV")
    call_data = mock_client.safe_post.call_args[0][1]
    assert call_data["target"] == "10.0.0.1"
    assert call_data["scan_type"] == "-sC -sV"


def test_nuclei_scan_async_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    result = at.nuclei_scan_async("http://example.com")
    mock_client.safe_post.assert_called()
    call_args = mock_client.safe_post.call_args
    assert "nuclei" in call_args[0][0]
    assert "async" in call_args[0][0]


def test_nuclei_scan_async_passes_templates():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    at.nuclei_scan_async("http://example.com", templates="cves/")
    call_data = mock_client.safe_post.call_args[0][1]
    assert call_data["templates"] == "cves/"


def test_gobuster_async_calls_api():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    result = at.gobuster_async("http://example.com")
    mock_client.safe_post.assert_called()
    call_args = mock_client.safe_post.call_args
    assert "gobuster" in call_args[0][0]
    assert "async" in call_args[0][0]


def test_get_task_status_calls_get():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    with patch("hexstrike_mcp_tools.async_tools.requests") as mock_requests:
        mock_resp = MagicMock()
        mock_resp.text = '{"status": "running", "task_id": "abc-123"}'
        mock_requests.get.return_value = mock_resp
        result = at.get_task_status("abc-123")
        mock_requests.get.assert_called_once_with(
            "http://127.0.0.1:8888/api/tasks/abc-123", timeout=10
        )
        assert "running" in result


def test_get_task_status_handles_error():
    mock_client = setup_mock_client()
    import hexstrike_mcp_tools.async_tools as at
    with patch("hexstrike_mcp_tools.async_tools.requests") as mock_requests:
        mock_requests.get.side_effect = Exception("Connection refused")
        result = at.get_task_status("bad-id")
        assert "Connection refused" in result
