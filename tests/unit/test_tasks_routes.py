# tests/unit/test_tasks_routes.py
"""Tests for core/routes/tasks.py — task status/result polling endpoints."""
import pytest
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


def test_get_task_status_pending(client):
    from core.task_store import task_store
    task_id = task_store.create("nmap -sV example.com")
    resp = client.get(f'/api/tasks/{task_id}')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["task_id"] == task_id
    assert data["status"] == "pending"


def test_get_task_done_includes_result(client):
    from core.task_store import task_store
    task_id = task_store.create("test")
    task_store.set_done(task_id, {"output": "finished"})
    resp = client.get(f'/api/tasks/{task_id}')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "done"
    assert data["result"] == {"output": "finished"}


def test_get_unknown_task_returns_404(client):
    resp = client.get('/api/tasks/does_not_exist_xyz')
    assert resp.status_code == 404
