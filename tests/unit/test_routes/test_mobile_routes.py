"""Unit tests for the mobile security tool routes Blueprint."""
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.mobile import mobile_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(mobile_bp)
    a.config['TESTING'] = True
    return a


def test_mobile_blueprint_registers(app):
    assert 'mobile' in app.blueprints


def test_apk_analyze_route(app):
    with patch('core.routes.mobile.apktool_decompile') as mock_apk, \
         patch('core.routes.mobile.jadx_decompile') as mock_jadx, \
         patch('core.routes.mobile.androguard_analyze') as mock_ag:
        mock_apk.return_value = {'success': True, 'output': 'decompiled'}
        mock_jadx.return_value = {'success': True, 'output': 'jadx'}
        mock_ag.return_value = {'success': True, 'output': 'ag'}
        resp = app.test_client().post('/api/tools/mobile/apk-analyze',
                                      json={'apk_path': '/tmp/test.apk'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_ios_analyze_route(app):
    with patch('core.routes.mobile.ipa_analyzer') as mock_ios, \
         patch('core.routes.mobile.class_dump') as mock_cd:
        mock_ios.return_value = {'success': True, 'info': {}}
        mock_cd.return_value = {'success': True, 'output': ''}
        resp = app.test_client().post('/api/tools/mobile/ios-analyze',
                                      json={'ipa_path': '/tmp/test.ipa'})
    assert resp.status_code == 200


def test_mobile_drozer_route(app):
    with patch('core.routes.mobile.drozer_scan') as mock_dz:
        mock_dz.return_value = {'vulnerabilities': [], 'success': True}
        resp = app.test_client().post('/api/tools/mobile/drozer',
                                      json={'package': 'com.example.app'})
    assert resp.status_code == 200


def test_mobile_mitm_route(app):
    with patch('core.routes.mobile.setup_mitmproxy_mobile') as mock_mitm:
        mock_mitm.return_value = {'traffic': [], 'success': True}
        resp = app.test_client().post('/api/tools/mobile/mitm',
                                      json={'interface': 'wlan0'})
    assert resp.status_code == 200


def test_apk_analyze_missing_param(app):
    resp = app.test_client().post('/api/tools/mobile/apk-analyze', json={})
    assert resp.status_code == 400


def test_ios_analyze_missing_param(app):
    resp = app.test_client().post('/api/tools/mobile/ios-analyze', json={})
    assert resp.status_code == 400


def test_drozer_missing_param(app):
    resp = app.test_client().post('/api/tools/mobile/drozer', json={})
    assert resp.status_code == 400
