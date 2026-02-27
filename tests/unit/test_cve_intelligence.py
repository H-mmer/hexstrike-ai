# tests/unit/test_cve_intelligence.py
"""Tests for CVEIntelligenceManager (Phase 5b, Task 25)."""
import pytest
from unittest.mock import patch, MagicMock
from agents.cve_intelligence import CVEIntelligenceManager


@pytest.fixture
def cve_mgr():
    return CVEIntelligenceManager()


def test_init_empty_caches(cve_mgr):
    assert cve_mgr.cve_cache == {}
    assert cve_mgr.vulnerability_db == {}
    assert cve_mgr.threat_intelligence == {}


def test_create_banner(cve_mgr):
    banner = cve_mgr.create_banner()
    assert isinstance(banner, str)
    assert len(banner) > 0


def test_render_progress_bar(cve_mgr):
    bar = cve_mgr.render_progress_bar(0.5, label="Scanning")
    assert isinstance(bar, str)
    assert "50.0%" in bar


def test_render_vulnerability_card(cve_mgr):
    vuln = {
        "severity": "high",
        "title": "SQL Injection",
        "url": "http://example.com",
        "description": "SQL injection in login",
        "cvss_score": 8.5,
    }
    card = cve_mgr.render_vulnerability_card(vuln)
    assert isinstance(card, str)
    assert "SQL Injection" in card


@patch("agents.cve_intelligence.requests.get")
def test_fetch_latest_cves_success(mock_get, cve_mgr):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test vuln"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "published": "2024-01-01T00:00:00.000",
                }
            }
        ]
    }
    mock_get.return_value = mock_resp
    result = cve_mgr.fetch_latest_cves(hours=24, severity_filter="CRITICAL")
    assert isinstance(result, (dict, list))


@patch("agents.cve_intelligence.requests.get")
def test_fetch_latest_cves_network_error(mock_get, cve_mgr):
    mock_get.side_effect = Exception("Network error")
    result = cve_mgr.fetch_latest_cves(hours=24)
    assert isinstance(result, (dict, list))


def test_create_summary_report(cve_mgr):
    results = {
        "vulnerabilities": [
            {"severity": "critical", "title": "RCE"},
            {"severity": "high", "title": "SQLi"},
        ]
    }
    report = cve_mgr.create_summary_report(results)
    assert isinstance(report, str)
