"""Unit tests for the OSINT and intelligence gathering routes Blueprint."""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.osint import osint_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(osint_bp)
    a.config['TESTING'] = True
    return a


def test_osint_blueprint_registers(app):
    assert 'osint' in app.blueprints


def test_passive_recon_route(app):
    with patch('tools.osint.passive_recon.the_harvester') as mock_th, \
         patch('tools.osint.passive_recon.whois_lookup') as mock_wh, \
         patch('tools.osint.passive_recon.dnsdumpster_recon') as mock_dns:
        mock_th.return_value = {'success': True, 'emails': [], 'hosts': []}
        mock_wh.return_value = {'success': True, 'output': ''}
        mock_dns.return_value = {'success': True, 'hosts': []}
        resp = app.test_client().post('/api/osint/passive-recon',
                                      json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_passive_recon_missing_domain(app):
    resp = app.test_client().post('/api/osint/passive-recon', json={})
    assert resp.status_code == 400


def test_threat_intel_route(app):
    with patch('tools.osint.threat_intel.urlscan_lookup') as mock_us, \
         patch('tools.osint.threat_intel.otx_lookup') as mock_otx:
        mock_us.return_value = {'success': True, 'results': []}
        mock_otx.return_value = {'success': True, 'pulse_count': 0}
        resp = app.test_client().post('/api/osint/threat-intel',
                                      json={'ioc': '8.8.8.8'})
    assert resp.status_code == 200


def test_threat_intel_missing_ioc(app):
    resp = app.test_client().post('/api/osint/threat-intel', json={})
    assert resp.status_code == 400


def test_social_recon_route_with_username(app):
    with patch('tools.osint.social_intel.sherlock_search') as mock_sh:
        mock_sh.return_value = {'success': True, 'found_on': []}
        resp = app.test_client().post('/api/osint/social-recon',
                                      json={'username': 'testuser'})
    assert resp.status_code == 200


def test_breach_check_route(app):
    with patch('tools.osint.social_intel.breach_lookup') as mock_bl:
        mock_bl.return_value = {'success': True, 'breached': False}
        resp = app.test_client().post('/api/osint/breach-check',
                                      json={'email': 'test@example.com'})
    assert resp.status_code == 200


def test_breach_check_missing_email(app):
    resp = app.test_client().post('/api/osint/breach-check', json={})
    assert resp.status_code == 400


def test_shodan_route(app):
    with patch('tools.osint.passive_recon.shodan_search') as mock_sh:
        mock_sh.return_value = {'success': True, 'output': ''}
        resp = app.test_client().post('/api/osint/shodan',
                                      json={'query': 'nginx'})
    assert resp.status_code == 200


def test_cve_lookup_route(app):
    with patch('tools.osint.threat_intel.shodan_cve_lookup') as mock_cve:
        mock_cve.return_value = {'success': True, 'output': ''}
        resp = app.test_client().post('/api/osint/ioc-cve',
                                      json={'ip': '8.8.8.8'})
    assert resp.status_code == 200
