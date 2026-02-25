"""Unit tests for the wireless security tool routes Blueprint."""
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


def test_wireless_blueprint_registers(app):
    assert 'wireless' in app.blueprints


def test_wifi_attack_route(app):
    with patch('core.routes.wireless.wifite2_attack') as mock_wifi:
        mock_wifi.return_value = {'success': True, 'pid': 1234}
        resp = app.test_client().post('/api/tools/wireless/wifi-attack',
                                     json={'interface': 'wlan0'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_bluetooth_scan_route(app):
    with patch('core.routes.wireless.bluez_scan') as mock_bt, \
         patch('core.routes.wireless.blueborne_scanner') as mock_bb:
        mock_bt.return_value = {'success': True, 'devices': []}
        mock_bb.return_value = {'success': True, 'vulnerabilities': []}
        resp = app.test_client().post('/api/tools/wireless/bluetooth-scan',
                                     json={'interface': 'hci0'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_rf_route(app):
    with patch('core.routes.wireless.rtl_sdr_scan') as mock_rtl:
        mock_rtl.return_value = {'success': True, 'pid': 5678}
        resp = app.test_client().post('/api/tools/wireless/rf', json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_wifi_attack_missing_interface(app):
    resp = app.test_client().post('/api/tools/wireless/wifi-attack', json={})
    assert resp.status_code == 400
