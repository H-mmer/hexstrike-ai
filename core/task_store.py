# core/task_store.py
"""In-memory task registry for async scan polling."""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, Optional


class TaskStore:
    """Thread-safe store for async task state: pending -> running -> done/error."""

    def __init__(self) -> None:
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, command: str) -> str:
        task_id = f"task_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._tasks[task_id] = {
                "task_id": task_id,
                "command": command,
                "status": "pending",
                "result": None,
                "error": None,
                "created_at": time.time(),
                "updated_at": time.time(),
            }
        return task_id

    def get(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            task = self._tasks.get(task_id)
            return dict(task) if task else None

    def set_running(self, task_id: str) -> None:
        self._update(task_id, {"status": "running"})

    def set_done(self, task_id: str, result: Any) -> None:
        self._update(task_id, {"status": "done", "result": result})

    def set_error(self, task_id: str, error: str) -> None:
        self._update(task_id, {"status": "error", "error": error})

    def _update(self, task_id: str, fields: Dict[str, Any]) -> None:
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].update(fields)
                self._tasks[task_id]["updated_at"] = time.time()


# Module-level singleton
task_store = TaskStore()
