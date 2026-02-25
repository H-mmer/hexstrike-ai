"""Unit tests for the web security tool routes Blueprint."""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.web import web_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(web_bp)
    a.config['TESTING'] = True
    return a


# ---------------------------------------------------------------------------
# gobuster
# ---------------------------------------------------------------------------

def test_gobuster_route_missing_target(app):
    resp = app.test_client().post('/api/tools/gobuster', json={})
    assert resp.status_code == 400


def test_gobuster_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/gobuster',
                                      json={'target': 'http://example.com'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------

def test_nuclei_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/nuclei',
                                      json={'target': 'http://example.com'})
    assert resp.status_code == 200


def test_nuclei_route_missing_target(app):
    resp = app.test_client().post('/api/tools/nuclei', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# nikto
# ---------------------------------------------------------------------------

def test_nikto_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/nikto',
                                      json={'target': 'http://example.com'})
    assert resp.status_code == 200


def test_nikto_route_missing_target(app):
    resp = app.test_client().post('/api/tools/nikto', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# sqlmap
# ---------------------------------------------------------------------------

def test_sqlmap_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/sqlmap',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


def test_sqlmap_route_missing_url(app):
    resp = app.test_client().post('/api/tools/sqlmap', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------

def test_ffuf_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/ffuf',
                                      json={'url': 'http://example.com/FUZZ'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# feroxbuster
# ---------------------------------------------------------------------------

def test_feroxbuster_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/feroxbuster',
                                      json={'target': 'http://example.com'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# wpscan
# ---------------------------------------------------------------------------

def test_wpscan_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/wpscan',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# dalfox
# ---------------------------------------------------------------------------

def test_dalfox_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/dalfox',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# dirsearch
# ---------------------------------------------------------------------------

def test_dirsearch_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/dirsearch',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# katana
# ---------------------------------------------------------------------------

def test_katana_route_exists(app):
    with patch('core.routes.web.shutil.which', return_value='/usr/bin/katana'), \
         patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/katana',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# wfuzz
# ---------------------------------------------------------------------------

def test_wfuzz_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/wfuzz',
                                      json={'url': 'http://example.com/FUZZ'})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Phase 3 — js-analysis
# ---------------------------------------------------------------------------

def test_js_analysis_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/web/js-analysis',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


def test_js_analysis_route_missing_url(app):
    resp = app.test_client().post('/api/tools/web/js-analysis', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Phase 3 — injection
# ---------------------------------------------------------------------------

def test_injection_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/web/injection',
                                      json={'url': 'http://example.com', 'type': 'nosql'})
    assert resp.status_code == 200


def test_injection_route_missing_url(app):
    resp = app.test_client().post('/api/tools/web/injection', json={'type': 'nosql'})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Phase 3 — cms-scan
# ---------------------------------------------------------------------------

def test_cms_scan_route_exists(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/web/cms-scan',
                                      json={'url': 'http://example.com', 'cms': 'wordpress'})
    assert resp.status_code == 200


def test_cms_scan_route_missing_url(app):
    resp = app.test_client().post('/api/tools/web/cms-scan', json={'cms': 'joomla'})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Phase 3 — auth-test
# ---------------------------------------------------------------------------

def test_auth_test_route_exists(app):
    with patch('core.routes.web.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            text='<form></form>',
            headers={},
            cookies={}
        )
        resp = app.test_client().post('/api/tools/web/auth-test',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200


def test_auth_test_route_missing_url(app):
    resp = app.test_client().post('/api/tools/web/auth-test', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Phase 3 — cdn-bypass
# ---------------------------------------------------------------------------

def test_cdn_bypass_route_exists(app):
    with patch('core.routes.web.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            text='',
            headers={}
        )
        with patch('core.routes.web.socket.gethostbyname', side_effect=OSError):
            resp = app.test_client().post('/api/tools/web/cdn-bypass',
                                          json={'url': 'http://example.com'})
    assert resp.status_code == 200


def test_cdn_bypass_route_missing_url(app):
    resp = app.test_client().post('/api/tools/web/cdn-bypass', json={})
    assert resp.status_code == 400
