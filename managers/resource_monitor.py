#!/usr/bin/env python3
"""
HexStrike AI - Resource Monitor

Lightweight memory/CPU monitor singleton used by cache and process pool.
Provides pressure signals so components can adapt (e.g., evict cache entries
under memory pressure, throttle process pool under CPU pressure).
"""
from __future__ import annotations

import time
import threading
import psutil
from typing import Any, Dict, Optional

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

    # ------------------------------------------------------------------
    # Extended metrics (used by EnhancedProcessManager)
    # ------------------------------------------------------------------

    def get_current_usage(self) -> Dict[str, float]:
        """Return a snapshot of system resource usage."""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net = psutil.net_io_counters()
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024 ** 3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024 ** 3),
                "network_bytes_sent": net.bytes_sent,
                "network_bytes_recv": net.bytes_recv,
                "timestamp": time.time(),
            }
        except Exception:
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "memory_available_gb": 0,
                "disk_percent": 0,
                "disk_free_gb": 0,
                "network_bytes_sent": 0,
                "network_bytes_recv": 0,
                "timestamp": time.time(),
            }

    def get_process_usage(self, pid: int) -> Dict[str, Any]:
        """Return resource usage for a specific process by PID."""
        try:
            proc = psutil.Process(pid)
            return {
                "cpu_percent": proc.cpu_percent(),
                "memory_percent": proc.memory_percent(),
                "memory_rss_mb": proc.memory_info().rss / (1024 ** 2),
                "num_threads": proc.num_threads(),
                "status": proc.status(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}


def get_resource_monitor() -> ResourceMonitor:
    """Return process-wide singleton (double-checked locking)."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = ResourceMonitor()
    return _instance
