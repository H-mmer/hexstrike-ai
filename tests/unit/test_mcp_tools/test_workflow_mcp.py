"""Unit tests for hexstrike_mcp_tools/workflows.py MCP tool registrations."""
from unittest.mock import MagicMock
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize


def _mock_client():
    """Set up and return a mock client with safe_post."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    initialize(mock)
    return mock


# ---------------------------------------------------------------------------
# Import tests
# ---------------------------------------------------------------------------

def test_workflows_importable():
    _mock_client()
    import hexstrike_mcp_tools.workflows  # noqa: F401
    assert True


# ---------------------------------------------------------------------------
# Intelligence tools
# ---------------------------------------------------------------------------

def test_analyze_target_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.analyze_target("example.com")
    mock.safe_post.assert_called()
    assert "intelligence" in mock.safe_post.call_args[0][0]


def test_select_optimal_tools_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.select_optimal_tools("example.com", objective="quick")
    mock.safe_post.assert_called()
    assert "select-tools" in mock.safe_post.call_args[0][0]


def test_create_attack_chain_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.create_attack_chain("example.com")
    mock.safe_post.assert_called()
    assert "attack-chain" in mock.safe_post.call_args[0][0]


def test_technology_detection_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.technology_detection("example.com")
    mock.safe_post.assert_called()
    assert "technology-detection" in mock.safe_post.call_args[0][0]


# ---------------------------------------------------------------------------
# CTF tools
# ---------------------------------------------------------------------------

def test_ctf_create_workflow_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ctf_create_workflow("test-challenge", category="web")
    mock.safe_post.assert_called()
    assert "ctf" in mock.safe_post.call_args[0][0]


def test_ctf_auto_solve_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ctf_auto_solve("test-challenge", category="crypto")
    mock.safe_post.assert_called()
    assert "auto-solve" in mock.safe_post.call_args[0][0]


def test_ctf_suggest_tools_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ctf_suggest_tools("base64 encoded string", category="crypto")
    mock.safe_post.assert_called()
    assert "suggest-tools" in mock.safe_post.call_args[0][0]


def test_ctf_crypto_solver_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ctf_crypto_solver("aGVsbG8=", cipher_type="unknown")
    mock.safe_post.assert_called()
    assert "cryptography" in mock.safe_post.call_args[0][0]


def test_ctf_forensics_analyzer_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ctf_forensics_analyzer("/tmp/test.bin")
    mock.safe_post.assert_called()
    assert "forensics" in mock.safe_post.call_args[0][0]


def test_ctf_binary_analyzer_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ctf_binary_analyzer("/tmp/test_binary")
    mock.safe_post.assert_called()
    assert "binary" in mock.safe_post.call_args[0][0]


# ---------------------------------------------------------------------------
# BugBounty tools
# ---------------------------------------------------------------------------

def test_bugbounty_recon_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.bugbounty_recon("example.com")
    mock.safe_post.assert_called()
    assert "reconnaissance" in mock.safe_post.call_args[0][0]


def test_bugbounty_vuln_hunt_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.bugbounty_vuln_hunt("example.com", priority_vulns="rce,xss")
    mock.safe_post.assert_called()
    assert "vulnerability-hunting" in mock.safe_post.call_args[0][0]


def test_bugbounty_osint_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.bugbounty_osint("example.com")
    mock.safe_post.assert_called()
    assert "osint" in mock.safe_post.call_args[0][0]


def test_bugbounty_comprehensive_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.bugbounty_comprehensive("example.com")
    mock.safe_post.assert_called()
    assert "comprehensive" in mock.safe_post.call_args[0][0]


# ---------------------------------------------------------------------------
# CVE / Vuln-intel tools
# ---------------------------------------------------------------------------

def test_cve_monitor_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.cve_monitor(hours=48, severity_filter="CRITICAL")
    mock.safe_post.assert_called()
    assert "cve-monitor" in mock.safe_post.call_args[0][0]


def test_cve_exploit_generate_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.cve_exploit_generate("CVE-2021-44228")
    mock.safe_post.assert_called()
    assert "exploit-generate" in mock.safe_post.call_args[0][0]


def test_threat_intelligence_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.threat_intelligence("CVE-2021-44228,192.168.1.1")
    mock.safe_post.assert_called()
    assert "threat-feeds" in mock.safe_post.call_args[0][0]


# ---------------------------------------------------------------------------
# AI payload tools
# ---------------------------------------------------------------------------

def test_ai_generate_payload_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ai_generate_payload(attack_type="xss")
    mock.safe_post.assert_called()
    assert "generate_payload" in mock.safe_post.call_args[0][0]


def test_ai_advanced_payload_calls_api():
    mock = _mock_client()
    import hexstrike_mcp_tools.workflows as w
    w.ai_advanced_payload("sqli", evasion_level="advanced")
    mock.safe_post.assert_called()
    assert "advanced-payload" in mock.safe_post.call_args[0][0]
