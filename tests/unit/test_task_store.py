# tests/unit/test_task_store.py
"""Tests for core.task_store — async scan polling foundation."""
import time
import threading


def test_create_returns_unique_ids():
    from core.task_store import TaskStore
    ts = TaskStore()
    id1 = ts.create("cmd1")
    id2 = ts.create("cmd2")
    assert id1 != id2


def test_status_is_pending_after_create():
    from core.task_store import TaskStore
    ts = TaskStore()
    task_id = ts.create("cmd")
    task = ts.get(task_id)
    assert task["status"] == "pending"
    assert task["result"] is None


def test_update_status_to_running():
    from core.task_store import TaskStore
    ts = TaskStore()
    task_id = ts.create("cmd")
    ts.set_running(task_id)
    assert ts.get(task_id)["status"] == "running"


def test_complete_sets_result():
    from core.task_store import TaskStore
    ts = TaskStore()
    task_id = ts.create("cmd")
    ts.set_done(task_id, {"output": "scan done"})
    task = ts.get(task_id)
    assert task["status"] == "done"
    assert task["result"] == {"output": "scan done"}


def test_error_sets_error_field():
    from core.task_store import TaskStore
    ts = TaskStore()
    task_id = ts.create("cmd")
    ts.set_error(task_id, "timeout")
    task = ts.get(task_id)
    assert task["status"] == "error"
    assert task["error"] == "timeout"


def test_get_unknown_task_returns_none():
    from core.task_store import TaskStore
    ts = TaskStore()
    assert ts.get("does_not_exist") is None


def test_module_level_singleton_exists():
    from core.task_store import task_store
    assert task_store is not None
