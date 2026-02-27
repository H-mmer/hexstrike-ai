"""Unit tests for the API security tool routes Blueprint."""
import sys
import types
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.api_security import api_security_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(api_security_bp)
    a.config['TESTING'] = True
    return a


def _make_mock_module(**funcs):
    """Create a mock module with the given function names returning mock results."""
    mod = types.ModuleType('mock_module')
    for name, return_value in funcs.items():
        setattr(mod, name, MagicMock(return_value=return_value))
    return mod


def test_api_security_blueprint_registers(app):
    assert 'api_security' in app.blueprints


def test_api_discover_route(app):
    mock_mod = _make_mock_module(
        kiterunner_scan={'success': True, 'endpoints_found': 3},
        swagger_scanner={'success': True, 'docs_found': 1},
        graphql_cop_scan={'success': True, 'introspection_enabled': True},
    )
    with patch.dict(sys.modules, {'tools.api.api_discovery': mock_mod}):
        resp = app.test_client().post('/api/tools/api/discover',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'results' in data


def test_api_fuzz_route(app):
    mock_mod = _make_mock_module(
        rest_attacker={'success': True, 'findings': []},
    )
    with patch.dict(sys.modules, {'tools.api.api_fuzzing': mock_mod}):
        resp = app.test_client().post('/api/tools/api/fuzz',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_api_auth_test_route(app):
    mock_mod = _make_mock_module(
        jwt_hack={'success': True, 'decoded_payload': {}},
        oauth_scanner={'success': True, 'findings': []},
        api_key_brute={'success': True, 'valid_keys': []},
    )
    with patch.dict(sys.modules, {'tools.api.api_auth': mock_mod}):
        resp = app.test_client().post('/api/tools/api/auth-test',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'results' in data


def test_api_monitoring_route(app):
    mock_mod = _make_mock_module(
        rate_limit_tester={'success': True, 'rate_limit_detected': False},
    )
    with patch.dict(sys.modules, {'tools.api.api_monitoring': mock_mod}):
        resp = app.test_client().post('/api/tools/api/monitoring',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_api_discover_missing_param(app):
    resp = app.test_client().post('/api/tools/api/discover', json={})
    assert resp.status_code == 400


def test_api_fuzz_missing_param(app):
    resp = app.test_client().post('/api/tools/api/fuzz', json={})
    assert resp.status_code == 400


def test_api_auth_test_missing_param(app):
    resp = app.test_client().post('/api/tools/api/auth-test', json={})
    assert resp.status_code == 400


def test_api_monitoring_missing_param(app):
    resp = app.test_client().post('/api/tools/api/monitoring', json={})
    assert resp.status_code == 400


def test_api_auth_test_with_jwt(app):
    mock_mod = _make_mock_module(
        jwt_hack={'success': True, 'decoded_payload': {}},
        oauth_scanner={'success': True},
        api_key_brute={'success': True},
    )
    with patch.dict(sys.modules, {'tools.api.api_auth': mock_mod}):
        resp = app.test_client().post('/api/tools/api/auth-test',
                                      json={'base_url': 'http://example.com',
                                            'jwt_token': 'eyJhbGciOiJub25lIn0.e30.'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    mock_mod.jwt_hack.assert_called_once()


# ---------------------------------------------------------------------------
# Module import failure tests (503 when tool module not available)
# ---------------------------------------------------------------------------

def test_api_discover_module_unavailable(app):
    with patch.dict(sys.modules, {'tools.api.api_discovery': None}):
        resp = app.test_client().post('/api/tools/api/discover',
                                      json={'base_url': 'http://example.com'})
    assert resp.status_code == 503


def test_api_fuzz_module_unavailable(app):
    with patch.dict(sys.modules, {'tools.api.api_fuzzing': None}):
        resp = app.test_client().post('/api/tools/api/fuzz',
                                      json={'base_url': 'http://example.com'})
    assert resp.status_code == 503


def test_api_monitoring_module_unavailable(app):
    with patch.dict(sys.modules, {'tools.api.api_monitoring': None}):
        resp = app.test_client().post('/api/tools/api/monitoring',
                                      json={'base_url': 'http://example.com'})
    assert resp.status_code == 503
