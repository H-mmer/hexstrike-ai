"""Unit tests for the wireless security tool routes Blueprint."""
import sys
import types
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.wireless import wireless_bp


@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(wireless_bp)
    a.config['TESTING'] = True
    return a


def _make_mock_module(**funcs):
    """Create a mock module with the given function names returning mock results."""
    mod = types.ModuleType('mock_module')
    for name, return_value in funcs.items():
        setattr(mod, name, MagicMock(return_value=return_value))
    return mod


def test_wireless_blueprint_registers(app):
    assert 'wireless' in app.blueprints


def test_wifi_attack_route(app):
    mock_mod = _make_mock_module(
        wifite2_attack={'success': True, 'pid': 1234},
    )
    with patch.dict(sys.modules, {'tools.wireless.wifi_tools': mock_mod}):
        resp = app.test_client().post('/api/tools/wireless/wifi-attack',
                                     json={'interface': 'wlan0'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_bluetooth_scan_route(app):
    mock_mod = _make_mock_module(
        bluez_scan={'success': True, 'devices': []},
        blueborne_scanner={'success': True, 'vulnerabilities': []},
    )
    with patch.dict(sys.modules, {'tools.wireless.bluetooth_tools': mock_mod}):
        resp = app.test_client().post('/api/tools/wireless/bluetooth-scan',
                                     json={'interface': 'hci0'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_rf_route(app):
    mock_mod = _make_mock_module(
        rtl_sdr_scan={'success': True, 'pid': 5678},
        hackrf_sweep={'success': True},
    )
    with patch.dict(sys.modules, {'tools.wireless.rf_tools': mock_mod}):
        resp = app.test_client().post('/api/tools/wireless/rf', json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_wifi_attack_missing_interface(app):
    resp = app.test_client().post('/api/tools/wireless/wifi-attack', json={})
    assert resp.status_code == 400
