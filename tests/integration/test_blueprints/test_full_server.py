"""Integration tests verifying all blueprints are registered in create_app()."""
import pytest
from core.server import create_app


def test_all_blueprints_registered():
    app = create_app()
    registered = set(app.blueprints.keys())
    expected = {'system', 'network', 'web', 'cloud', 'binary',
                'ctf', 'bugbounty', 'intelligence', 'mobile',
                'api_security', 'wireless', 'osint'}
    assert expected.issubset(registered), f"Missing blueprints: {expected - registered}"


def test_health_endpoint_responds():
    app = create_app()
    app.config['TESTING'] = True
    resp = app.test_client().get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] in ('operational', 'healthy')


def test_hexstrike_server_is_thin():
    with open('hexstrike_server.py') as f:
        lines = [l for l in f.readlines() if l.strip() and not l.strip().startswith('#')]
    assert len(lines) < 100, f"hexstrike_server.py is {len(lines)} non-blank lines — expected < 100"
