#!/usr/bin/env python3
"""
Tests for EnhancedProcessManager cleanup (Tasks 12-16):
- No duplicate cache attribute (uses module-level DiskTieredCache)
- CPU-aware worker counts
- Uses ResourceMonitor singleton from managers/resource_monitor.py
"""

import os
import inspect


def test_no_duplicate_cache_attribute():
    """EnhancedProcessManager must NOT have a .cache attribute."""
    from managers.process_manager import EnhancedProcessManager

    pm = EnhancedProcessManager()
    assert not hasattr(pm, "cache"), (
        "EnhancedProcessManager still carries a private cache — remove it"
    )


def test_worker_count_is_cpu_aware():
    """ProcessPool max_workers must not exceed 2 * cpu_count."""
    from managers.process_manager import EnhancedProcessManager

    pm = EnhancedProcessManager()
    cpu_count = os.cpu_count() or 4
    assert pm.process_pool.max_workers <= cpu_count * 2


def test_worker_count_minimum_is_2():
    """ProcessPool min_workers must be at least 2."""
    from managers.process_manager import EnhancedProcessManager

    pm = EnhancedProcessManager()
    assert pm.process_pool.min_workers >= 2


def test_resource_monitor_is_singleton():
    """EnhancedProcessManager must use the shared ResourceMonitor singleton."""
    from managers.process_manager import EnhancedProcessManager
    from managers.resource_monitor import get_resource_monitor

    pm = EnhancedProcessManager()
    singleton = get_resource_monitor()
    assert pm.resource_monitor is singleton, (
        "EnhancedProcessManager.resource_monitor must be the shared singleton "
        "from managers.resource_monitor.get_resource_monitor()"
    )


def test_resource_monitor_imported_in_process_manager():
    """process_manager module must reference get_resource_monitor or ResourceMonitor from resource_monitor."""
    import managers.process_manager as pm_mod

    src = inspect.getsource(pm_mod)
    assert "get_resource_monitor" in src, (
        "process_manager.py must import get_resource_monitor from managers.resource_monitor"
    )


def test_get_comprehensive_stats_has_cache_key():
    """get_comprehensive_stats() must still include a 'cache' key in its output."""
    from managers.process_manager import EnhancedProcessManager

    pm = EnhancedProcessManager()
    stats = pm.get_comprehensive_stats()
    assert "cache" in stats, (
        "get_comprehensive_stats() must still return cache stats "
        "(from the module-level cache singleton)"
    )
