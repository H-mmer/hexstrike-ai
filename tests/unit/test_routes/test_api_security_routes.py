"""Unit tests for the API security tool routes Blueprint."""
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


def test_api_security_blueprint_registers(app):
    assert 'api_security' in app.blueprints


def test_api_discover_route(app):
    with patch('core.routes.api_security.kiterunner_scan') as mock_kr, \
         patch('core.routes.api_security.swagger_scanner') as mock_sw, \
         patch('core.routes.api_security.graphql_cop_scan') as mock_gql:
        mock_kr.return_value = {'success': True, 'endpoints_found': 3}
        mock_sw.return_value = {'success': True, 'docs_found': 1}
        mock_gql.return_value = {'success': True, 'introspection_enabled': True}
        resp = app.test_client().post('/api/tools/api/discover',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'results' in data


def test_api_fuzz_route(app):
    with patch('core.routes.api_security.rest_attacker') as mock_fuzz:
        mock_fuzz.return_value = {'success': True, 'findings': []}
        resp = app.test_client().post('/api/tools/api/fuzz',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_api_auth_test_route(app):
    with patch('core.routes.api_security.jwt_hack') as mock_jwt, \
         patch('core.routes.api_security.oauth_scanner') as mock_oauth, \
         patch('core.routes.api_security.api_key_brute') as mock_key:
        mock_jwt.return_value = {'success': True, 'decoded_payload': {}}
        mock_oauth.return_value = {'success': True, 'findings': []}
        mock_key.return_value = {'success': True, 'valid_keys': []}
        resp = app.test_client().post('/api/tools/api/auth-test',
                                     json={'base_url': 'http://example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'results' in data


def test_api_monitoring_route(app):
    with patch('core.routes.api_security.rate_limit_tester') as mock_rl:
        mock_rl.return_value = {'success': True, 'rate_limit_detected': False}
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
    with patch('core.routes.api_security.jwt_hack') as mock_jwt, \
         patch('core.routes.api_security.oauth_scanner') as mock_oauth, \
         patch('core.routes.api_security.api_key_brute') as mock_apk:
        mock_jwt.return_value = {'success': True, 'decoded_payload': {}}
        mock_oauth.return_value = {'success': True}
        mock_apk.return_value = {'success': True}
        resp = app.test_client().post('/api/tools/api/auth-test',
                                      json={'base_url': 'http://example.com',
                                            'jwt_token': 'eyJhbGciOiJub25lIn0.e30.'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    mock_jwt.assert_called_once()
