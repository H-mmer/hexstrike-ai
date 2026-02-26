#!/usr/bin/env python3
"""
HexStrike AI - Resource Monitor

Lightweight memory/CPU monitor singleton used by cache and process pool.
Provides pressure signals so components can adapt (e.g., evict cache entries
under memory pressure, throttle process pool under CPU pressure).
"""
from __future__ import annotations

import threading
import psutil
from typing import Optional

_instance: Optional["ResourceMonitor"] = None
_lock = threading.Lock()


class ResourceMonitor:
    """Reads system resource usage; provides pressure signals to cache/pool."""

    def __init__(self, memory_threshold: float = 85.0, cpu_threshold: float = 90.0):
        self.memory_threshold = memory_threshold
        self.cpu_threshold = cpu_threshold

    # ------------------------------------------------------------------
    # Raw metrics
    # ------------------------------------------------------------------

    def memory_percent(self) -> float:
        """Return current virtual memory usage as a percentage (0-100)."""
        return psutil.virtual_memory().percent

    def cpu_percent(self) -> float:
        """Return current CPU usage as a percentage (0-100)."""
        return psutil.cpu_percent(interval=0.1)

    # ------------------------------------------------------------------
    # Pressure signals
    # ------------------------------------------------------------------

    def is_memory_pressure(self) -> bool:
        """True when memory usage >= memory_threshold."""
        return self.memory_percent() >= self.memory_threshold

    def is_cpu_pressure(self) -> bool:
        """True when CPU usage >= cpu_threshold."""
        return self.cpu_percent() >= self.cpu_threshold


def get_resource_monitor() -> ResourceMonitor:
    """Return process-wide singleton (double-checked locking)."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = ResourceMonitor()
    return _instance
