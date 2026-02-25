# tests/unit/test_routes/test_system_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.system import system_bp

def test_system_blueprint_registers():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    assert 'system' in app.blueprints

def test_health_route_exists():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    app.config['TESTING'] = True
    client = app.test_client()
    with patch('core.routes.system.shutil') as mock_shutil:
        mock_shutil.which.return_value = '/usr/bin/nmap'
        resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'status' in data

def test_health_route_missing_tools():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    app.config['TESTING'] = True
    client = app.test_client()
    with patch('core.routes.system.shutil') as mock_shutil:
        mock_shutil.which.return_value = None  # All tools missing
        resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'status' in data
    # When tools are missing, all_essential_tools_available should be False
    assert data.get('all_essential_tools_available') is False


def test_telemetry_route_exists():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    app.config['TESTING'] = True
    client = app.test_client()
    resp = client.get('/api/telemetry')
    assert resp.status_code == 200
