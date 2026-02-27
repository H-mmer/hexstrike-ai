"""Integration tests for the system Blueprint routes."""
import pytest
from unittest.mock import patch, MagicMock
from core.server import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


@pytest.fixture(autouse=True)
def clear_cache():
    """Reset cache state before each test."""
    from managers.cache_manager import cache
    cache.clear()
    yield


# ---------------------------------------------------------------------------
# Cache routes
# ---------------------------------------------------------------------------

def test_cache_stats_route(client):
    resp = client.get('/api/cache/stats')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'stats' in data


def test_cache_stats_contains_expected_keys(client):
    resp = client.get('/api/cache/stats')
    stats = resp.get_json()['stats']
    # DiskTieredCache exposes tiered metrics instead of old HexStrikeCache keys
    for key in ('hits', 'misses', 'hit_rate', 'mem_size_mb', 'disk_size_mb',
                'mem_item_count', 'disk_item_count'):
        assert key in stats, f"Missing key: {key}"


def test_cache_clear_route(client):
    resp = client.post('/api/cache/clear')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True


def test_cache_clear_resets_stats(client):
    # After a clear, stats should reflect an empty cache
    client.post('/api/cache/clear')
    resp = client.get('/api/cache/stats')
    stats = resp.get_json()['stats']
    assert stats['mem_item_count'] == 0
    assert stats['disk_item_count'] == 0


# ---------------------------------------------------------------------------
# Process list route
# ---------------------------------------------------------------------------

def test_process_list_route(client):
    resp = client.get('/api/processes/list')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'processes' in data


def test_process_list_returns_dict(client):
    resp = client.get('/api/processes/list')
    assert isinstance(resp.get_json()['processes'], dict)


# ---------------------------------------------------------------------------
# Command route
# ---------------------------------------------------------------------------

def test_command_route_echo(client):
    with patch('core.routes.system.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            stdout='test output', stderr='', returncode=0
        )
        resp = client.post('/api/command', json={'command': 'echo test'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['output'] == 'test output'


def test_command_route_missing_command(client):
    resp = client.post('/api/command', json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False


def test_command_route_no_body(client):
    resp = client.post('/api/command', data='not-json', content_type='text/plain')
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
