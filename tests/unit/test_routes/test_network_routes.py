"""Tests for core/routes/network.py — network and recon tool Blueprint."""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.network import network_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(network_bp)
    a.config['TESTING'] = True
    return a


# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------

def test_network_blueprint_registers():
    a = Flask(__name__)
    a.register_blueprint(network_bp)
    assert 'network' in a.blueprints


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

def test_nmap_route_missing_target(app):
    resp = app.test_client().post('/api/tools/nmap', json={})
    assert resp.status_code == 400


def test_nmap_route_with_target(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='scan result', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/nmap'):
            resp = app.test_client().post('/api/tools/nmap', json={'target': '127.0.0.1'})
    assert resp.status_code in (200, 503)
    data = resp.get_json()
    assert 'success' in data


def test_nmap_route_tool_not_installed(app):
    with patch('core.routes.network.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/nmap', json={'target': '127.0.0.1'})
    assert resp.status_code in (200, 503)
    data = resp.get_json()
    assert data['success'] is False


# ---------------------------------------------------------------------------
# rustscan
# ---------------------------------------------------------------------------

def test_rustscan_route_missing_target(app):
    resp = app.test_client().post('/api/tools/rustscan', json={})
    assert resp.status_code == 400


def test_rustscan_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/rustscan'):
            resp = app.test_client().post('/api/tools/rustscan', json={'target': '127.0.0.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# masscan
# ---------------------------------------------------------------------------

def test_masscan_route_missing_target(app):
    resp = app.test_client().post('/api/tools/masscan', json={})
    assert resp.status_code == 400


def test_masscan_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='open 80/tcp', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/masscan'):
            resp = app.test_client().post('/api/tools/masscan', json={'target': '192.168.1.0/24'})
    assert resp.status_code in (200, 503)
    data = resp.get_json()
    assert 'success' in data


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------

def test_amass_route_missing_domain(app):
    resp = app.test_client().post('/api/tools/amass', json={})
    assert resp.status_code == 400


def test_amass_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/amass'):
            resp = app.test_client().post('/api/tools/amass', json={'domain': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

def test_subfinder_route_missing_domain(app):
    resp = app.test_client().post('/api/tools/subfinder', json={})
    assert resp.status_code == 400


def test_subfinder_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='sub.example.com\n', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/subfinder'):
            resp = app.test_client().post('/api/tools/subfinder', json={'domain': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------

def test_httpx_route_missing_target(app):
    resp = app.test_client().post('/api/tools/httpx', json={})
    assert resp.status_code == 400


def test_httpx_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='https://example.com [200]', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/httpx'):
            resp = app.test_client().post('/api/tools/httpx', json={'target': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# waybackurls
# ---------------------------------------------------------------------------

def test_waybackurls_route_missing_domain(app):
    resp = app.test_client().post('/api/tools/waybackurls', json={})
    assert resp.status_code == 400


def test_waybackurls_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='https://example.com/old\n', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/waybackurls'):
            resp = app.test_client().post('/api/tools/waybackurls', json={'domain': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# dnsenum
# ---------------------------------------------------------------------------

def test_dnsenum_route_missing_domain(app):
    resp = app.test_client().post('/api/tools/dnsenum', json={})
    assert resp.status_code == 400


def test_dnsenum_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='ns1.example.com', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/dnsenum'):
            resp = app.test_client().post('/api/tools/dnsenum', json={'domain': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# enum4linux
# ---------------------------------------------------------------------------

def test_enum4linux_route_missing_target(app):
    resp = app.test_client().post('/api/tools/enum4linux', json={})
    assert resp.status_code == 400


def test_enum4linux_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='Domain Name: WORKGROUP', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/enum4linux'):
            resp = app.test_client().post('/api/tools/enum4linux', json={'target': '192.168.1.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# smbmap
# ---------------------------------------------------------------------------

def test_smbmap_route_missing_host(app):
    resp = app.test_client().post('/api/tools/smbmap', json={})
    assert resp.status_code == 400


def test_smbmap_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='ADMIN$ NO ACCESS', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/smbmap'):
            resp = app.test_client().post('/api/tools/smbmap', json={'host': '192.168.1.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# nmap-advanced
# ---------------------------------------------------------------------------

def test_nmap_advanced_route_missing_target(app):
    resp = app.test_client().post('/api/tools/nmap-advanced', json={})
    assert resp.status_code == 400


def test_nmap_advanced_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='scan result', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/nmap'):
            resp = app.test_client().post('/api/tools/nmap-advanced', json={'target': '127.0.0.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# netexec
# ---------------------------------------------------------------------------

def test_netexec_route_missing_target(app):
    resp = app.test_client().post('/api/tools/netexec', json={})
    assert resp.status_code == 400


def test_netexec_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='SMB 192.168.1.1 445', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/nxc'):
            resp = app.test_client().post('/api/tools/netexec', json={'target': '192.168.1.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# autorecon
# ---------------------------------------------------------------------------

def test_autorecon_route_missing_target(app):
    resp = app.test_client().post('/api/tools/autorecon', json={})
    assert resp.status_code == 400


def test_autorecon_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/autorecon'):
            resp = app.test_client().post('/api/tools/autorecon', json={'target': '10.10.10.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# fierce
# ---------------------------------------------------------------------------

def test_fierce_route_missing_domain(app):
    resp = app.test_client().post('/api/tools/fierce', json={})
    assert resp.status_code == 400


def test_fierce_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='Found: mail.example.com', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/fierce'):
            resp = app.test_client().post('/api/tools/fierce', json={'domain': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# wafw00f
# ---------------------------------------------------------------------------

def test_wafw00f_route_missing_target(app):
    resp = app.test_client().post('/api/tools/wafw00f', json={})
    assert resp.status_code == 400


def test_wafw00f_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='No WAF detected', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/wafw00f'):
            resp = app.test_client().post('/api/tools/wafw00f', json={'target': 'https://example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# gau
# ---------------------------------------------------------------------------

def test_gau_route_missing_domain(app):
    resp = app.test_client().post('/api/tools/gau', json={})
    assert resp.status_code == 400


def test_gau_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='https://example.com/page\n', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/gau'):
            resp = app.test_client().post('/api/tools/gau', json={'domain': 'example.com'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# nbtscan
# ---------------------------------------------------------------------------

def test_nbtscan_route_missing_target(app):
    resp = app.test_client().post('/api/tools/nbtscan', json={})
    assert resp.status_code == 400


def test_nbtscan_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='192.168.1.1\tWORKGROUP', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/nbtscan'):
            resp = app.test_client().post('/api/tools/nbtscan', json={'target': '192.168.1.0/24'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# enum4linux-ng
# ---------------------------------------------------------------------------

def test_enum4linux_ng_route_missing_target(app):
    resp = app.test_client().post('/api/tools/enum4linux-ng', json={})
    assert resp.status_code == 400


def test_enum4linux_ng_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='Users: administrator', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/enum4linux-ng'):
            resp = app.test_client().post('/api/tools/enum4linux-ng', json={'target': '192.168.1.1'})
    assert resp.status_code in (200, 503)


# ---------------------------------------------------------------------------
# timeout handling
# ---------------------------------------------------------------------------

def test_nmap_timeout_handled(app):
    import subprocess as sp
    with patch('core.routes.network.subprocess.run', side_effect=sp.TimeoutExpired(cmd='nmap', timeout=60)):
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/nmap'):
            resp = app.test_client().post('/api/tools/nmap', json={'target': '127.0.0.1'})
    data = resp.get_json()
    assert data['success'] is False
    assert 'timed out' in data.get('error', '').lower()


# Phase 3 advanced network tests
def test_scapy_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/network/scapy',
                                      json={'target': '127.0.0.1', 'packet_type': 'icmp'})
    assert resp.status_code == 200


def test_naabu_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='80\n443\n', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/network/naabu',
                                      json={'target': '127.0.0.1'})
    assert resp.status_code == 200


def test_zmap_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='192.168.1.1\n', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/zmap'):
            resp = app.test_client().post('/api/tools/network/zmap',
                                          json={'target_network': '192.168.1.0/24'})
    assert resp.status_code == 200


def test_zmap_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/zmap', json={})
    assert resp.status_code == 400


def test_naabu_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/naabu', json={})
    assert resp.status_code == 400


def test_scapy_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/scapy', json={})
    assert resp.status_code == 400


def test_snmp_check_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='System info\n', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/network/snmp-check',
                                      json={'target': '192.168.1.1'})
    assert resp.status_code == 200


def test_snmp_check_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/snmp-check', json={})
    assert resp.status_code == 400


def test_ipv6_toolkit_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/alive6'):
            resp = app.test_client().post('/api/tools/network/ipv6-toolkit',
                                          json={'target': '::1'})
    assert resp.status_code == 200


def test_ipv6_toolkit_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/ipv6-toolkit', json={})
    assert resp.status_code == 400


def test_udp_proto_scanner_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='53 open\n', stderr='', returncode=0)
        with patch('core.routes.network.shutil.which', return_value='/usr/bin/udp-proto-scanner'):
            resp = app.test_client().post('/api/tools/network/udp-proto-scanner',
                                          json={'target': '192.168.1.1'})
    assert resp.status_code == 200


def test_udp_proto_scanner_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/udp-proto-scanner', json={})
    assert resp.status_code == 400


def test_cisco_torch_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='Cisco device found\n', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/network/cisco-torch',
                                      json={'target': '192.168.1.1'})
    assert resp.status_code == 200


def test_cisco_torch_route_missing_target(app):
    resp = app.test_client().post('/api/tools/network/cisco-torch', json={})
    assert resp.status_code == 400
