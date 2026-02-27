"""Unit tests for the mobile security tool routes Blueprint."""
import sys
import types
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


def _make_mock_module(**funcs):
    """Create a mock module with the given function names returning mock results."""
    mod = types.ModuleType('mock_module')
    for name, return_value in funcs.items():
        setattr(mod, name, MagicMock(return_value=return_value))
    return mod


def test_mobile_blueprint_registers(app):
    assert 'mobile' in app.blueprints


def test_apk_analyze_route(app):
    mock_mod = _make_mock_module(
        apktool_decompile={'success': True, 'output': 'decompiled'},
        jadx_decompile={'success': True, 'output': 'jadx'},
        androguard_analyze={'success': True, 'output': 'ag'},
    )
    with patch.dict(sys.modules, {'tools.mobile.apk_tools': mock_mod}):
        resp = app.test_client().post('/api/tools/mobile/apk-analyze',
                                      json={'apk_path': '/tmp/test.apk'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_ios_analyze_route(app):
    mock_mod = _make_mock_module(
        ipa_analyzer={'success': True, 'info': {}},
        class_dump={'success': True, 'output': ''},
    )
    with patch.dict(sys.modules, {'tools.mobile.ios_tools': mock_mod}):
        resp = app.test_client().post('/api/tools/mobile/ios-analyze',
                                      json={'ipa_path': '/tmp/test.ipa'})
    assert resp.status_code == 200


def test_mobile_drozer_route(app):
    mock_mod = _make_mock_module(
        drozer_scan={'vulnerabilities': [], 'success': True},
    )
    with patch.dict(sys.modules, {'tools.mobile.mobile_exploit': mock_mod}):
        resp = app.test_client().post('/api/tools/mobile/drozer',
                                      json={'package': 'com.example.app'})
    assert resp.status_code == 200


def test_mobile_mitm_route(app):
    mock_mod = _make_mock_module(
        setup_mitmproxy_mobile={'traffic': [], 'success': True},
    )
    with patch.dict(sys.modules, {'tools.mobile.mobile_network': mock_mod}):
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


# ---------------------------------------------------------------------------
# Module import failure tests (503 when tool module not available)
# ---------------------------------------------------------------------------

def test_apk_analyze_module_unavailable(app):
    with patch.dict(sys.modules, {'tools.mobile.apk_tools': None}):
        resp = app.test_client().post('/api/tools/mobile/apk-analyze',
                                      json={'apk_path': '/tmp/test.apk'})
    assert resp.status_code == 503


def test_ios_analyze_module_unavailable(app):
    with patch.dict(sys.modules, {'tools.mobile.ios_tools': None}):
        resp = app.test_client().post('/api/tools/mobile/ios-analyze',
                                      json={'ipa_path': '/tmp/test.ipa'})
    assert resp.status_code == 503


def test_mitm_module_unavailable(app):
    with patch.dict(sys.modules, {'tools.mobile.mobile_network': None}):
        resp = app.test_client().post('/api/tools/mobile/mitm',
                                      json={'interface': 'wlan0'})
    assert resp.status_code == 503
