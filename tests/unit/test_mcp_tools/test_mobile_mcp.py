"""Unit tests for hexstrike_mcp_tools/mobile.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True, "output": "test"}
    initialize(mock)
    return mock


def test_mobile_tools_importable():
    _mock_client()
    import hexstrike_mcp_tools.mobile  # noqa: F401
    assert True


def test_apk_analyze_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.mobile as m
    result = m.apk_analyze("/tmp/test.apk")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "apk" in path


def test_ios_analyze_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.mobile as m
    result = m.ios_analyze("/tmp/test.ipa")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "ios" in path


def test_drozer_android_audit_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.mobile as m
    result = m.drozer_android_audit("com.example.app")
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "drozer" in path


def test_mobile_traffic_intercept_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.mobile as m
    result = m.mobile_traffic_intercept()
    assert result == {"success": True, "output": "test"}
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "mitm" in path


def test_mobile_traffic_intercept_custom_port():
    mock = _mock_client()
    import hexstrike_mcp_tools.mobile as m
    m.mobile_traffic_intercept(listen_port=9090)
    mock.safe_post.assert_called()
    payload = mock.safe_post.call_args[0][1]
    assert payload.get("listen_port") == 9090
