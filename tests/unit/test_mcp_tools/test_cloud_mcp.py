"""Unit tests for hexstrike_mcp_tools/cloud.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    initialize(mock)
    return mock


def test_cloud_tools_importable():
    _mock_client()
    import hexstrike_mcp_tools.cloud  # noqa: F401
    assert True


def test_trivy_scan_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.cloud as c
    c.trivy_scan("nginx:latest")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "trivy" in path


def test_prowler_scan_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.cloud as c
    c.prowler_scan(provider="aws")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "prowler" in path


def test_kubescape_assessment_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.cloud as c
    c.kubescape_assessment()
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "kubescape" in path


def test_container_escape_check_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.cloud as c
    c.container_escape_check()
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "container-escape" in path


def test_kubernetes_rbac_audit_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.cloud as c
    c.kubernetes_rbac_audit()
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "rbac-audit" in path
