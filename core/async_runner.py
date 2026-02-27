# core/async_runner.py
"""Submit a callable to a background thread, track via TaskStore."""
from __future__ import annotations

import threading
from typing import Callable, Any

from core.task_store import task_store


def async_run(fn: Callable[[], Any], command_label: str = "async_task") -> str:
    """Run *fn* in a daemon thread and return a task_id for polling."""
    task_id = task_store.create(command_label)

    def _worker():
        task_store.set_running(task_id)
        try:
            result = fn()
            task_store.set_done(task_id, result)
        except Exception as exc:
            task_store.set_error(task_id, str(exc))

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return task_id
