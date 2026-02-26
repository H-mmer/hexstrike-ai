"""Unit tests for the cloud security tool routes Blueprint."""
import sys
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.cloud import cloud_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(cloud_bp)
    a.config['TESTING'] = True
    return a


# ---------------------------------------------------------------------------
# trivy
# ---------------------------------------------------------------------------

def test_trivy_route_missing_target(app):
    resp = app.test_client().post('/api/tools/trivy', json={})
    assert resp.status_code == 400


def test_trivy_route_exists(app):
    with patch('core.routes.cloud.subprocess.run') as mock_run, \
         patch('core.routes.cloud.shutil.which', return_value='/usr/bin/trivy'):
        mock_run.return_value = MagicMock(stdout='{}', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/trivy',
                                      json={'target': 'nginx:latest'})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_trivy_route_tool_missing(app):
    with patch('core.routes.cloud.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/trivy',
                                      json={'target': 'nginx:latest'})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# prowler
# ---------------------------------------------------------------------------

def test_prowler_route_exists(app):
    with patch('core.routes.cloud.subprocess.run') as mock_run, \
         patch('core.routes.cloud.shutil.which', return_value='/usr/bin/prowler'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/prowler', json={})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_prowler_route_tool_missing(app):
    with patch('core.routes.cloud.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/prowler', json={})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Phase 3: kubescape (fallback subprocess path)
# ---------------------------------------------------------------------------

def test_cloud_kubescape_route_exists(app):
    with patch.dict(sys.modules, {'tools.cloud.cloud_native': None}), \
         patch('core.routes.cloud.subprocess.run') as mock_run, \
         patch('core.routes.cloud.shutil.which', return_value='/usr/bin/kubescape'):
        mock_run.return_value = MagicMock(stdout='{}', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/cloud/kubescape', json={})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_cloud_kubescape_route_tool_missing(app):
    with patch.dict(sys.modules, {'tools.cloud.cloud_native': None}), \
         patch('core.routes.cloud.shutil.which', return_value=None):
        resp = app.test_client().post('/api/tools/cloud/kubescape', json={})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Phase 3: container-escape (fallback subprocess path)
# ---------------------------------------------------------------------------

def test_cloud_container_escape_route_exists(app):
    with patch.dict(sys.modules, {'tools.cloud.container_escape': None}), \
         patch('core.routes.cloud.subprocess.run') as mock_run, \
         patch('core.routes.cloud.shutil.which', return_value='/usr/bin/amicontained'):
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/cloud/container-escape', json={})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()


def test_cloud_rbac_audit_route_exists(app):
    with patch.dict(sys.modules, {'tools.cloud.cloud_native': None}), \
         patch('core.routes.cloud.subprocess.run') as mock_run, \
         patch('core.routes.cloud.shutil.which', return_value='/usr/bin/kubectl'):
        mock_run.return_value = MagicMock(stdout='{}', stderr='', returncode=0)
        resp = app.test_client().post('/api/tools/cloud/rbac-audit', json={})
    assert resp.status_code == 200
    assert 'success' in resp.get_json()
