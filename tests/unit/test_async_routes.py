# tests/unit/test_async_routes.py
"""Tests for async route variants — each tool returns HTTP 202 with a task_id."""
import pytest
from unittest.mock import patch
from core.server import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


@pytest.fixture(autouse=True)
def _fresh_task_store():
    """Clear the module-level task_store between tests so state doesn't leak."""
    from core.task_store import task_store
    with task_store._lock:
        task_store._tasks.clear()
    yield


# ---------------------------------------------------------------------------
# Network async routes
# ---------------------------------------------------------------------------

def test_nmap_async_returns_task_id(client):
    resp = client.post('/api/network/nmap/async', json={"target": "127.0.0.1"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_nmap_async_requires_target(client):
    resp = client.post('/api/network/nmap/async', json={})
    assert resp.status_code == 400


def test_rustscan_async_returns_task_id(client):
    resp = client.post('/api/network/rustscan/async', json={"target": "127.0.0.1"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_masscan_async_returns_task_id(client):
    resp = client.post('/api/network/masscan/async', json={"target": "127.0.0.1"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_amass_async_returns_task_id(client):
    resp = client.post('/api/network/amass/async', json={"domain": "example.com"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_amass_async_requires_domain(client):
    resp = client.post('/api/network/amass/async', json={})
    assert resp.status_code == 400


def test_subfinder_async_returns_task_id(client):
    resp = client.post('/api/network/subfinder/async', json={"domain": "example.com"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_subfinder_async_requires_domain(client):
    resp = client.post('/api/network/subfinder/async', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Web async routes
# ---------------------------------------------------------------------------

def test_nuclei_async_returns_task_id(client):
    resp = client.post('/api/web/nuclei/async', json={"target": "http://example.com"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_nuclei_async_requires_target(client):
    resp = client.post('/api/web/nuclei/async', json={})
    assert resp.status_code == 400


def test_gobuster_async_returns_task_id(client):
    resp = client.post('/api/web/gobuster/async', json={"target": "http://example.com"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_gobuster_async_requires_target(client):
    resp = client.post('/api/web/gobuster/async', json={})
    assert resp.status_code == 400


def test_feroxbuster_async_returns_task_id(client):
    resp = client.post('/api/web/feroxbuster/async', json={"target": "http://example.com"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
    assert data["status"] == "pending"


def test_feroxbuster_async_requires_target(client):
    resp = client.post('/api/web/feroxbuster/async', json={})
    assert resp.status_code == 400
