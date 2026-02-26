# tests/unit/test_async_runner.py
"""Tests for core/async_runner.py — background task execution."""
import time


def test_async_run_returns_task_id_immediately():
    from core.async_runner import async_run
    from core.task_store import task_store
    def slow_fn():
        time.sleep(0.05)
        return {"output": "done"}
    task_id = async_run(slow_fn)
    assert task_id.startswith("task_")
    task = task_store.get(task_id)
    assert task is not None
    assert task["status"] in ("pending", "running")


def test_async_run_eventually_sets_done():
    from core.async_runner import async_run
    from core.task_store import task_store
    def fast_fn():
        return {"output": "ok"}
    task_id = async_run(fast_fn)
    for _ in range(20):
        task = task_store.get(task_id)
        if task and task["status"] == "done":
            break
        time.sleep(0.1)
    assert task["status"] == "done"
    assert task["result"] == {"output": "ok"}


def test_async_run_sets_error_on_exception():
    from core.async_runner import async_run
    from core.task_store import task_store
    def failing_fn():
        raise RuntimeError("boom")
    task_id = async_run(failing_fn)
    for _ in range(20):
        task = task_store.get(task_id)
        if task and task["status"] in ("error", "done"):
            break
        time.sleep(0.1)
    assert task["status"] == "error"
    assert "boom" in task["error"]
