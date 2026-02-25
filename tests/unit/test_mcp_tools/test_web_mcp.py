"""Unit tests for hexstrike_mcp_tools/web.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    initialize(mock)
    return mock


def test_web_tools_importable():
    _mock_client()
    import hexstrike_mcp_tools.web  # noqa: F401
    assert True


def test_gobuster_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.gobuster_scan("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "gobuster" in path


def test_nuclei_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.nuclei_scan("http://example.com", severity="high,critical")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "nuclei" in path


def test_sqlmap_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.sqlmap_scan("http://example.com/page?id=1")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "sqlmap" in path


def test_ffuf_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.ffuf_fuzz("http://example.com/FUZZ")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "ffuf" in path


def test_nikto_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.nikto_scan("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "nikto" in path


def test_wpscan_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.wpscan("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "wpscan" in path


def test_dalfox_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.dalfox_xss("http://example.com?q=test")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "dalfox" in path


def test_feroxbuster_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.feroxbuster_scan("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "feroxbuster" in path


def test_dirsearch_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.dirsearch("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "dirsearch" in path


def test_katana_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.katana_crawl("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "katana" in path


def test_web_js_analysis_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.web_js_analysis("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "js-analysis" in path


def test_web_injection_test_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.web_injection_test("http://example.com", inject_type="ssti")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "injection" in path


def test_web_cms_scan_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.web_cms_scan("http://example.com", cms="wordpress")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "cms-scan" in path


def test_web_auth_test_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.web_auth_test("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "auth-test" in path


def test_web_cdn_bypass_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.web_cdn_bypass("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "cdn-bypass" in path


def test_wfuzz_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.wfuzz("http://example.com/FUZZ")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "wfuzz" in path


def test_arjun_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.arjun_params("http://example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "arjun" in path


def test_paramspider_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.web as w
    w.paramspider("example.com")
    mock.safe_post.assert_called()
    path = mock.safe_post.call_args[0][0]
    assert "paramspider" in path
