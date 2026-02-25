"""Tests for OSINT tools — passive_recon, social_intel, threat_intel."""
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Task 15 — passive_recon.py
# ---------------------------------------------------------------------------

def test_shodan_search_returns_dict():
    from tools.osint.passive_recon import shodan_search
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='{"ip_str": "1.2.3.4"}', returncode=0)
        result = shodan_search("nginx", api_key="test_key")
    assert isinstance(result, dict)
    assert 'success' in result or 'error' in result or 'results' in result or 'output' in result


def test_whois_lookup_returns_dict():
    from tools.osint.passive_recon import whois_lookup
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='Domain: example.com\n', returncode=0)
        result = whois_lookup("example.com")
    assert isinstance(result, dict)


def test_the_harvester_returns_dict():
    from tools.osint.passive_recon import the_harvester
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='[*] Emails found: 3\n', returncode=0)
        result = the_harvester("example.com")
    assert isinstance(result, dict)


def test_dnsdumpster_recon_returns_dict():
    from tools.osint.passive_recon import dnsdumpster_recon
    with patch('tools.osint.passive_recon.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=True, text='example.com,1.2.3.4\n')
        result = dnsdumpster_recon("example.com")
    assert isinstance(result, dict)


def test_censys_search_returns_dict():
    from tools.osint.passive_recon import censys_search
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='results...', returncode=0)
        result = censys_search("nginx")
    assert isinstance(result, dict)


def test_shodan_search_tool_not_found():
    from tools.osint.passive_recon import shodan_search
    with patch('tools.osint.passive_recon.shutil.which', return_value=None):
        result = shodan_search("nginx")
    assert result['success'] is False
    assert 'error' in result


def test_whois_lookup_tool_not_found():
    from tools.osint.passive_recon import whois_lookup
    with patch('tools.osint.passive_recon.shutil.which', return_value=None):
        result = whois_lookup("example.com")
    assert result['success'] is False
    assert 'error' in result


def test_shodan_search_timeout():
    from tools.osint.passive_recon import shodan_search
    import subprocess
    with patch('tools.osint.passive_recon.shutil.which', return_value='/usr/bin/shodan'):
        with patch('tools.osint.passive_recon.subprocess.run', side_effect=subprocess.TimeoutExpired('shodan', 120)):
            result = shodan_search("nginx")
    assert result['success'] is False
    assert 'timed out' in result['error'].lower() or 'timeout' in result['error'].lower()


def test_whois_lookup_timeout():
    from tools.osint.passive_recon import whois_lookup
    import subprocess
    with patch('tools.osint.passive_recon.shutil.which', return_value='/usr/bin/whois'):
        with patch('tools.osint.passive_recon.subprocess.run', side_effect=subprocess.TimeoutExpired('whois', 30)):
            result = whois_lookup("example.com")
    assert result['success'] is False


def test_the_harvester_tool_not_found():
    from tools.osint.passive_recon import the_harvester
    with patch('tools.osint.passive_recon.shutil.which', return_value=None):
        result = the_harvester("example.com")
    assert result['success'] is False
    assert 'error' in result


def test_censys_search_tool_not_found():
    from tools.osint.passive_recon import censys_search
    with patch('tools.osint.passive_recon.shutil.which', return_value=None):
        result = censys_search("nginx")
    assert result['success'] is False
    assert 'error' in result


def test_dnsdumpster_recon_request_failure():
    from tools.osint.passive_recon import dnsdumpster_recon
    with patch('tools.osint.passive_recon.requests.get', side_effect=Exception("connection error")):
        result = dnsdumpster_recon("example.com")
    assert result['success'] is False
    assert 'error' in result


def test_shodan_search_success_fields():
    from tools.osint.passive_recon import shodan_search
    with patch('tools.osint.passive_recon.shutil.which', return_value='/usr/bin/shodan'):
        with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='1.2.3.4\t80\tGoogle\n', returncode=0)
            result = shodan_search("nginx")
    assert result['success'] is True
    assert 'output' in result
    assert result['query'] == 'nginx'


def test_dnsdumpster_recon_success_fields():
    from tools.osint.passive_recon import dnsdumpster_recon
    with patch('tools.osint.passive_recon.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=True, text='sub.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n')
        result = dnsdumpster_recon("example.com")
    assert result['success'] is True
    assert 'hosts' in result
    assert result['count'] == 2


# ---------------------------------------------------------------------------
# Task 16 — social_intel.py
# ---------------------------------------------------------------------------

def test_sherlock_search():
    from tools.osint.social_intel import sherlock_search
    with patch('tools.osint.social_intel.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='[+] Twitter: Found\n[+] GitHub: Found\n', returncode=0)
        result = sherlock_search("testuser")
    assert isinstance(result, dict)


def test_holehe_check():
    from tools.osint.social_intel import holehe_check
    with patch('tools.osint.social_intel.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='[+] gmail.com: registered\n', returncode=0)
        result = holehe_check("test@example.com")
    assert isinstance(result, dict)


def test_breach_lookup():
    from tools.osint.social_intel import breach_lookup
    with patch('tools.osint.social_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(status_code=404)
        result = breach_lookup("test@example.com")
    assert isinstance(result, dict)
    assert result.get('breached') is False


def test_sherlock_search_tool_not_found():
    from tools.osint.social_intel import sherlock_search
    with patch('tools.osint.social_intel.shutil.which', return_value=None):
        result = sherlock_search("testuser")
    assert result['success'] is False
    assert 'error' in result


def test_holehe_check_tool_not_found():
    from tools.osint.social_intel import holehe_check
    with patch('tools.osint.social_intel.shutil.which', return_value=None):
        result = holehe_check("test@example.com")
    assert result['success'] is False
    assert 'error' in result


def test_sherlock_search_found_results():
    from tools.osint.social_intel import sherlock_search
    with patch('tools.osint.social_intel.shutil.which', return_value='/usr/bin/sherlock'):
        with patch('tools.osint.social_intel.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='[+] Twitter: https://twitter.com/testuser\n[+] GitHub: https://github.com/testuser\n',
                returncode=0
            )
            result = sherlock_search("testuser")
    assert result['success'] is True
    assert result['count'] == 2
    assert result['username'] == 'testuser'


def test_holehe_check_registered():
    from tools.osint.social_intel import holehe_check
    with patch('tools.osint.social_intel.shutil.which', return_value='/usr/bin/holehe'):
        with patch('tools.osint.social_intel.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout='[+] gmail.com: registered\n[+] twitter.com: registered\n',
                returncode=0
            )
            result = holehe_check("test@example.com")
    assert result['success'] is True
    assert result['count'] == 2
    assert result['email'] == 'test@example.com'


def test_breach_lookup_breached():
    from tools.osint.social_intel import breach_lookup
    with patch('tools.osint.social_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [{"Name": "Adobe"}, {"Name": "LinkedIn"}]
        )
        result = breach_lookup("test@example.com")
    assert result['success'] is True
    assert result['breached'] is True
    assert result['count'] == 2


def test_breach_lookup_api_error():
    from tools.osint.social_intel import breach_lookup
    with patch('tools.osint.social_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(status_code=429)
        result = breach_lookup("test@example.com")
    assert result['success'] is False


def test_breach_lookup_exception():
    from tools.osint.social_intel import breach_lookup
    with patch('tools.osint.social_intel.requests.get', side_effect=Exception("timeout")):
        result = breach_lookup("test@example.com")
    assert result['success'] is False
    assert 'error' in result


def test_linkedin_recon_returns_dict():
    from tools.osint.social_intel import linkedin_recon
    result = linkedin_recon("Google")
    assert isinstance(result, dict)
    assert result['success'] is True
    assert 'company' in result


# ---------------------------------------------------------------------------
# Task 16 — threat_intel.py
# ---------------------------------------------------------------------------

def test_virustotal_lookup():
    from tools.osint.threat_intel import virustotal_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}
        )
        result = virustotal_lookup("8.8.8.8", api_key="test")
    assert isinstance(result, dict)


def test_otx_lookup():
    from tools.osint.threat_intel import otx_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=True, json=lambda: {"pulse_info": {"count": 2}, "reputation": 0})
        result = otx_lookup("8.8.8.8")
    assert isinstance(result, dict)


def test_urlscan_lookup():
    from tools.osint.threat_intel import urlscan_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=True, json=lambda: {"results": []})
        result = urlscan_lookup("example.com")
    assert isinstance(result, dict)


def test_virustotal_missing_api_key():
    from tools.osint.threat_intel import virustotal_lookup
    result = virustotal_lookup("8.8.8.8")  # no api_key
    assert result['success'] is False
    assert 'error' in result


def test_virustotal_lookup_success_fields():
    from tools.osint.threat_intel import virustotal_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 68}}}}
        )
        result = virustotal_lookup("8.8.8.8", api_key="test_key")
    assert result['success'] is True
    assert result['malicious'] == 2
    assert result['clean'] == 68
    assert result['ioc'] == '8.8.8.8'


def test_virustotal_lookup_domain():
    from tools.osint.threat_intel import virustotal_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 75}}}}
        )
        result = virustotal_lookup("example.com", api_key="test_key")
    assert result['success'] is True


def test_virustotal_lookup_hash():
    from tools.osint.threat_intel import virustotal_lookup
    md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 65}}}}
        )
        result = virustotal_lookup(md5_hash, api_key="test_key")
    assert result['success'] is True


def test_virustotal_api_error():
    from tools.osint.threat_intel import virustotal_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=False, status_code=403)
        result = virustotal_lookup("8.8.8.8", api_key="bad_key")
    assert result['success'] is False


def test_otx_lookup_success_fields():
    from tools.osint.threat_intel import otx_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"pulse_info": {"count": 5}, "reputation": -1}
        )
        result = otx_lookup("1.2.3.4")
    assert result['success'] is True
    assert result['pulse_count'] == 5
    assert result['reputation'] == -1
    assert result['ioc'] == '1.2.3.4'


def test_otx_lookup_api_error():
    from tools.osint.threat_intel import otx_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=False, status_code=401)
        result = otx_lookup("1.2.3.4")
    assert result['success'] is False


def test_otx_lookup_exception():
    from tools.osint.threat_intel import otx_lookup
    with patch('tools.osint.threat_intel.requests.get', side_effect=Exception("network error")):
        result = otx_lookup("1.2.3.4")
    assert result['success'] is False
    assert 'error' in result


def test_urlscan_lookup_success_fields():
    from tools.osint.threat_intel import urlscan_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"results": [{"_id": "abc"}, {"_id": "def"}, {"_id": "ghi"}, {"_id": "jkl"}]}
        )
        result = urlscan_lookup("example.com")
    assert result['success'] is True
    assert result['scan_count'] == 4
    assert result['target'] == 'example.com'
    assert len(result['recent_scans']) <= 3


def test_urlscan_lookup_api_error():
    from tools.osint.threat_intel import urlscan_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=False, status_code=429)
        result = urlscan_lookup("example.com")
    assert result['success'] is False


def test_urlscan_lookup_exception():
    from tools.osint.threat_intel import urlscan_lookup
    with patch('tools.osint.threat_intel.requests.get', side_effect=Exception("dns error")):
        result = urlscan_lookup("example.com")
    assert result['success'] is False
    assert 'error' in result


def test_shodan_cve_lookup_tool_not_found():
    from tools.osint.threat_intel import shodan_cve_lookup
    with patch('tools.osint.threat_intel.shutil.which', return_value=None):
        result = shodan_cve_lookup("1.2.3.4")
    assert result['success'] is False
    assert 'error' in result


def test_shodan_cve_lookup_success():
    from tools.osint.threat_intel import shodan_cve_lookup
    with patch('tools.osint.threat_intel.shutil.which', return_value='/usr/bin/shodan'):
        with patch('tools.osint.threat_intel.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout='IP: 1.2.3.4\nPorts: 80, 443\n', returncode=0)
            result = shodan_cve_lookup("1.2.3.4")
    assert result['success'] is True
    assert result['ip'] == '1.2.3.4'
