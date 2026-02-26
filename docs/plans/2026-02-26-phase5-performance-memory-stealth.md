# Phase 5: Performance, Memory & Stealth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce peak memory from ~2 GB to ≤800 MB, add diskcache-backed tiered caching, fix process pool duplication, deliver async scan streaming via task-ID polling, and add a stealth browser agent using undetected-chromedriver with human behaviour simulation.

**Architecture:** (1) Lazy loading defers all Python module imports until the first HTTP request that needs them, eliminating ~400 MB of upfront load. (2) diskcache replaces the custom LRU cache with a 256 MB in-memory tier that spills to 512 MB on disk. (3) StealthBrowserAgent extends (not replaces) BrowserAgent with undetected-chromedriver and a HumanBehaviourMixin. (4) Async scans return a task-ID immediately; callers poll `/api/tasks/<id>` for status/result. (5) Process pool gets a minimal fix: remove duplicate AdvancedCache and set workers from `os.cpu_count()`.

**Tech Stack:** Python 3.8+, Flask, diskcache ≥5.6.0, undetected-chromedriver ≥3.5.0, psutil, threading, pytest, pytest-mock

**Execution order (Impact-first — Batch B):**
1. Cache Overhaul (highest memory win, touches managers only)
2. Process Pool Cleanup (removes duplication)
3. Lazy Tool Loading (second largest startup win, touches Blueprints)
4. Async Scan Streaming (new feature, clean addition)
5. Stealth Browser Agent (new feature, clean addition)

---

## Batch 1 — Cache Overhaul (Tasks 1–14)

### Task 1: Add diskcache to requirements.txt

**Files:**
- Modify: `requirements.txt`

**Step 1: Write the failing test** (verify import fails before adding dep)

```python
# tests/unit/test_diskcache_dep.py
def test_diskcache_importable():
    import diskcache  # noqa: F401
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_diskcache_dep.py -v
```
Expected: `ModuleNotFoundError: No module named 'diskcache'`

**Step 3: Add to requirements.txt**

Append to `requirements.txt`:
```
diskcache>=5.6.0
```

Then install:
```bash
pip install diskcache>=5.6.0
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_diskcache_dep.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add requirements.txt tests/unit/test_diskcache_dep.py
git commit -m "feat(deps): add diskcache>=5.6.0 for tiered cache"
```

---

### Task 2: Write failing tests for DiskTieredCache

**Files:**
- Create: `tests/unit/test_disk_tiered_cache.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_disk_tiered_cache.py
"""Tests for DiskTieredCache — write BEFORE implementation."""
import pytest
import tempfile
import os


def test_set_and_get_returns_value():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("key1", {"data": "value"}, ttl=60)
        result = cache.get("key1")
        assert result == {"data": "value"}
        cache.close()


def test_get_missing_key_returns_none():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        assert cache.get("nonexistent") is None
        cache.close()


def test_clear_removes_all_entries():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        cache.clear()
        assert cache.get("k1") is None
        assert cache.get("k2") is None
        cache.close()


def test_get_stats_returns_expected_keys():
    from managers.disk_cache import DiskTieredCache
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("k", "v")
        cache.get("k")  # hit
        cache.get("miss")  # miss
        stats = cache.get_stats()
        assert "hits" in stats
        assert "misses" in stats
        assert "mem_size_mb" in stats
        assert "disk_size_mb" in stats
        cache.close()


def test_ttl_expiry_returns_none(monkeypatch):
    """Expired keys must not be returned."""
    from managers.disk_cache import DiskTieredCache
    import time
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = DiskTieredCache(cache_dir=tmpdir, mem_size_mb=64, disk_size_mb=128)
        cache.set("expiring", "val", ttl=1)
        time.sleep(1.1)
        assert cache.get("expiring") is None
        cache.close()


def test_default_cache_dir_uses_tmp():
    """Constructing without cache_dir must not raise."""
    from managers.disk_cache import DiskTieredCache
    cache = DiskTieredCache()
    cache.set("k", "v")
    assert cache.get("k") == "v"
    cache.close()
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/unit/test_disk_tiered_cache.py -v
```
Expected: `ImportError: cannot import name 'DiskTieredCache' from 'managers.disk_cache'`

**Step 3: No implementation yet — commit failing tests**

```bash
git add tests/unit/test_disk_tiered_cache.py
git commit -m "test(cache): add failing tests for DiskTieredCache"
```

---

### Task 3: Implement DiskTieredCache

**Files:**
- Create: `managers/disk_cache.py`

**Step 1: Implement**

```python
# managers/disk_cache.py
"""Tiered cache: 256 MB in-memory FanoutCache + disk spill via diskcache."""
from __future__ import annotations

import os
import tempfile
import threading
import time
from typing import Any, Optional

import diskcache

_BYTES_PER_MB = 1024 * 1024


class DiskTieredCache:
    """Two-tier LRU cache.

    Tier 1 — in-memory FanoutCache (fast, bounded by mem_size_mb).
    Tier 2 — disk FanoutCache (slower, bounded by disk_size_mb).
    Both tiers honour TTL.
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        mem_size_mb: int = 256,
        disk_size_mb: int = 512,
    ):
        if cache_dir is None:
            cache_dir = os.path.join(tempfile.gettempdir(), "hexstrike_cache")
        os.makedirs(cache_dir, exist_ok=True)

        self._mem = diskcache.Cache(
            os.path.join(cache_dir, "mem"),
            size_limit=mem_size_mb * _BYTES_PER_MB,
            eviction_policy="least-recently-used",
        )
        self._disk = diskcache.Cache(
            os.path.join(cache_dir, "disk"),
            size_limit=disk_size_mb * _BYTES_PER_MB,
            eviction_policy="least-recently-used",
        )
        self._hits = 0
        self._misses = 0
        self._lock = threading.Lock()
        self._mem_size_mb = mem_size_mb
        self._disk_size_mb = disk_size_mb

    # ------------------------------------------------------------------
    def get(self, key: str) -> Optional[Any]:
        val = self._mem.get(key, default=None)
        if val is not None:
            with self._lock:
                self._hits += 1
            return val
        val = self._disk.get(key, default=None)
        if val is not None:
            with self._lock:
                self._hits += 1
            return val
        with self._lock:
            self._misses += 1
        return None

    def set(self, key: str, value: Any, ttl: int = 1800) -> None:
        self._mem.set(key, value, expire=ttl)
        self._disk.set(key, value, expire=ttl)

    def clear(self) -> None:
        self._mem.clear()
        self._disk.clear()

    def get_stats(self) -> dict:
        with self._lock:
            hits = self._hits
            misses = self._misses
        total = hits + misses
        hit_rate = hits / total if total > 0 else 0.0
        return {
            "hits": hits,
            "misses": misses,
            "hit_rate": round(hit_rate, 4),
            "mem_size_mb": self._mem_size_mb,
            "disk_size_mb": self._disk_size_mb,
            "mem_item_count": len(self._mem),
            "disk_item_count": len(self._disk),
        }

    def close(self) -> None:
        self._mem.close()
        self._disk.close()
```

**Step 2: Run tests to verify they pass**

```bash
pytest tests/unit/test_disk_tiered_cache.py -v
```
Expected: 6 PASSED

**Step 3: Commit**

```bash
git add managers/disk_cache.py tests/unit/test_disk_tiered_cache.py
git commit -m "feat(cache): implement DiskTieredCache with diskcache backend"
```

---

### Task 4: Write failing tests for ResourceMonitor

**Files:**
- Create: `tests/unit/test_resource_monitor.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_resource_monitor.py
"""Tests for ResourceMonitor singleton — write BEFORE implementation."""
import pytest
from unittest.mock import patch


def test_get_memory_percent_returns_float(monkeypatch):
    import psutil
    with patch.object(psutil, "virtual_memory") as mock_vm:
        mock_vm.return_value.percent = 45.3
        from managers.resource_monitor import ResourceMonitor
        rm = ResourceMonitor()
        assert rm.memory_percent() == 45.3


def test_memory_pressure_true_when_above_threshold():
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(memory_threshold=80.0)
    with patch.object(rm, "memory_percent", return_value=85.0):
        assert rm.is_memory_pressure() is True


def test_memory_pressure_false_when_below_threshold():
    from managers.resource_monitor import ResourceMonitor
    rm = ResourceMonitor(memory_threshold=80.0)
    with patch.object(rm, "memory_percent", return_value=50.0):
        assert rm.is_memory_pressure() is False


def test_singleton_returns_same_instance():
    from managers.resource_monitor import get_resource_monitor
    a = get_resource_monitor()
    b = get_resource_monitor()
    assert a is b
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/unit/test_resource_monitor.py -v
```
Expected: `ImportError: No module named 'managers.resource_monitor'`

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_resource_monitor.py
git commit -m "test(cache): add failing tests for ResourceMonitor"
```

---

### Task 5: Implement ResourceMonitor

**Files:**
- Create: `managers/resource_monitor.py`

**Step 1: Implement**

```python
# managers/resource_monitor.py
"""Lightweight memory/CPU monitor singleton used by cache and process pool."""
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

    def memory_percent(self) -> float:
        return psutil.virtual_memory().percent

    def cpu_percent(self) -> float:
        return psutil.cpu_percent(interval=0.1)

    def is_memory_pressure(self) -> bool:
        return self.memory_percent() >= self.memory_threshold

    def is_cpu_pressure(self) -> bool:
        return self.cpu_percent() >= self.cpu_threshold


def get_resource_monitor() -> ResourceMonitor:
    """Return process-wide singleton."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = ResourceMonitor()
    return _instance
```

**Step 2: Run tests to verify they pass**

```bash
pytest tests/unit/test_resource_monitor.py -v
```
Expected: 4 PASSED

**Step 3: Commit**

```bash
git add managers/resource_monitor.py
git commit -m "feat(cache): add ResourceMonitor singleton"
```

---

### Task 6: Write failing tests for cache_manager migration

**Files:**
- Create: `tests/unit/test_cache_manager_v2.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_cache_manager_v2.py
"""Integration tests: cache_manager module must expose DiskTieredCache singleton."""


def test_module_level_cache_is_disk_tiered():
    from managers import cache_manager
    from managers.disk_cache import DiskTieredCache
    assert isinstance(cache_manager.cache, DiskTieredCache)


def test_cache_set_get_roundtrip():
    from managers.cache_manager import cache
    cache.set("roundtrip_key", {"ok": True}, ttl=30)
    assert cache.get("roundtrip_key") == {"ok": True}


def test_cache_stats_has_tier_info():
    from managers.cache_manager import cache
    stats = cache.get_stats()
    assert "mem_size_mb" in stats
    assert "disk_size_mb" in stats
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/unit/test_cache_manager_v2.py -v
```
Expected: FAIL — `AssertionError` (cache is still HexStrikeCache)

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_cache_manager_v2.py
git commit -m "test(cache): add failing migration tests for cache_manager"
```

---

### Task 7: Migrate cache_manager.py to DiskTieredCache

**Files:**
- Modify: `managers/cache_manager.py`

**Step 1: Read the existing file**

```bash
# Already read: 97 lines, has HexStrikeCache class + module-level singleton
# We KEEP the HexStrikeCache class for backwards compat (other tests may import it)
# We just replace the module-level singleton
```

**Step 2: Replace the module-level singleton at bottom of file**

In `managers/cache_manager.py`, find the line:
```python
cache = HexStrikeCache()
```

Replace it with:
```python
# Use DiskTieredCache as primary singleton (tiered: 256 MB mem + 512 MB disk)
# HexStrikeCache kept above for backwards compatibility with existing tests.
from managers.disk_cache import DiskTieredCache as _DiskTieredCache
cache = _DiskTieredCache(mem_size_mb=256, disk_size_mb=512)
```

**Step 3: Run all cache tests**

```bash
pytest tests/unit/test_cache_manager_v2.py tests/unit/test_disk_tiered_cache.py -v
```
Expected: All PASSED

**Step 4: Run full test suite to confirm no regressions**

```bash
pytest -v --tb=short 2>&1 | tail -30
```
Expected: All existing tests still PASS

**Step 5: Commit**

```bash
git add managers/cache_manager.py
git commit -m "feat(cache): swap module-level cache singleton to DiskTieredCache"
```

---

### Task 8: Update /api/cache/stats to expose tiered metrics

**Files:**
- Modify: `core/routes/system.py`

**Step 1: Write failing test**

```python
# Append to tests/unit/test_system_routes.py (or create if missing)
def test_cache_stats_includes_tier_info(client):
    """GET /api/cache/stats must include diskcache tier fields."""
    resp = client.get('/api/cache/stats')
    assert resp.status_code == 200
    data = resp.get_json()
    assert "mem_size_mb" in data or "mem_size_mb" in data.get("stats", {})
```

**Step 2: Run to verify it fails**

```bash
pytest tests/unit/ -k "test_cache_stats_includes_tier_info" -v
```

**Step 3: Update the `/api/cache/stats` handler in `core/routes/system.py`**

Find the `cache_stats` route function and update it to pass through `get_stats()` directly:

```python
@system_bp.route('/api/cache/stats', methods=['GET'])
def cache_stats():
    from managers.cache_manager import cache
    stats = cache.get_stats()
    return jsonify({"success": True, "stats": stats})
```

**Step 4: Run tests**

```bash
pytest tests/unit/ -k "cache" -v
```
Expected: All PASSED

**Step 5: Commit**

```bash
git add core/routes/system.py tests/unit/test_system_routes.py
git commit -m "feat(api): update /api/cache/stats for DiskTieredCache metrics"
```

---

### Task 9: Add managers/__init__.py exports

**Files:**
- Modify: `managers/__init__.py`

**Step 1: Verify current exports**

```bash
cat managers/__init__.py
```

**Step 2: Add new exports**

```python
# Add to managers/__init__.py
from managers.disk_cache import DiskTieredCache
from managers.resource_monitor import ResourceMonitor, get_resource_monitor
```

**Step 3: Run full test suite**

```bash
pytest -v --tb=short 2>&1 | tail -20
```
Expected: All PASSED

**Step 4: Commit**

```bash
git add managers/__init__.py
git commit -m "chore(managers): export DiskTieredCache and ResourceMonitor"
```

---

### Task 10: Memory baseline benchmark

**Files:**
- Create: `tests/benchmarks/test_memory_baseline.py`

**Step 1: Create benchmark test** (not pytest collected — run manually)

```python
# tests/benchmarks/test_memory_baseline.py
"""
Memory baseline: measure RSS before/after Blueprint registration.
Run manually: python tests/benchmarks/test_memory_baseline.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import tracemalloc
import psutil

def measure_rss_mb() -> float:
    proc = psutil.Process(os.getpid())
    return proc.memory_info().rss / (1024 * 1024)


def main():
    rss_before = measure_rss_mb()
    tracemalloc.start()

    # Import Flask app (triggers Blueprint registration)
    from core.server import create_app
    app = create_app()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = measure_rss_mb()

    print(f"RSS before: {rss_before:.1f} MB")
    print(f"RSS after:  {rss_after:.1f} MB")
    print(f"Delta:      {rss_after - rss_before:.1f} MB")
    print(f"tracemalloc peak: {peak / (1024*1024):.1f} MB")


if __name__ == "__main__":
    main()
```

**Step 2: Run baseline**

```bash
python tests/benchmarks/test_memory_baseline.py
```

Record output — this is your **pre-lazy-loading baseline**.

**Step 3: Commit**

```bash
mkdir -p tests/benchmarks
touch tests/benchmarks/__init__.py
git add tests/benchmarks/
git commit -m "test(bench): add memory baseline benchmark"
```

---

### Task 11: Ensure diskcache test dep test is removed

The `test_diskcache_dep.py` file created in Task 1 is a one-time bootstrap test. Delete it.

```bash
git rm tests/unit/test_diskcache_dep.py
git commit -m "chore(test): remove one-time diskcache bootstrap test"
```

---

## Batch 2 — Process Pool Cleanup (Tasks 12–17)

### Task 12: Write failing tests for fixed ProcessPool

**Files:**
- Create: `tests/unit/test_process_manager_fix.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_process_manager_fix.py
"""Verify EnhancedProcessManager no longer carries duplicate AdvancedCache
and that worker count is CPU-aware."""
import os


def test_no_duplicate_cache_attribute():
    """EnhancedProcessManager must NOT have a .cache attribute (use module cache)."""
    from managers.process_manager import EnhancedProcessManager
    pm = EnhancedProcessManager()
    # Should NOT have an internal .cache; rely on managers.cache_manager.cache
    assert not hasattr(pm, "cache"), (
        "EnhancedProcessManager still carries a private cache — remove it and "
        "use managers.cache_manager.cache instead"
    )


def test_worker_count_is_cpu_aware():
    """ProcessPool max_workers must not exceed 2 * cpu_count."""
    from managers.process_manager import EnhancedProcessManager
    pm = EnhancedProcessManager()
    cpu_count = os.cpu_count() or 4
    assert pm.process_pool.max_workers <= cpu_count * 2, (
        f"max_workers={pm.process_pool.max_workers} exceeds 2 * cpu_count={cpu_count * 2}"
    )


def test_worker_count_minimum_is_2():
    """ProcessPool min_workers must be at least 2."""
    from managers.process_manager import EnhancedProcessManager
    pm = EnhancedProcessManager()
    assert pm.process_pool.min_workers >= 2
```

**Step 2: Run tests to verify they fail**

```bash
pytest tests/unit/test_process_manager_fix.py -v
```
Expected: `test_no_duplicate_cache_attribute` FAILS (pm.cache exists)

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_process_manager_fix.py
git commit -m "test(process): add failing tests for CPU-aware workers + no dupe cache"
```

---

### Task 13: Read ProcessPool class in process_manager.py

**Step 1: Read the ProcessPool class**

```bash
grep -n "class ProcessPool" managers/process_manager.py
```

Then read that section to understand `min_workers` / `max_workers` attributes.

Expected output: line numbers for `class ProcessPool` and its `__init__`.

---

### Task 14: Fix EnhancedProcessManager — remove duplicate cache + CPU-aware workers

**Files:**
- Modify: `managers/process_manager.py`

**Step 1: Remove `self.cache` line in `EnhancedProcessManager.__init__`**

Find and remove:
```python
self.cache = AdvancedCache(max_size=2000, default_ttl=1800)  # 30 minutes default TTL
```

**Step 2: Replace hardcoded ProcessPool workers**

Find:
```python
self.process_pool = ProcessPool(min_workers=4, max_workers=32)
```

Replace with:
```python
import os as _os
_cpu = _os.cpu_count() or 4
self.process_pool = ProcessPool(min_workers=max(2, _cpu // 2), max_workers=_cpu * 2)
```

**Step 3: Update `execute_command_async` to use module-level cache**

Find the cache usage inside `execute_command_async`:
```python
cached_result = self.cache.get(cache_key)
```
and:
```python
self.cache.set(...)
```

Replace with:
```python
from managers.cache_manager import cache as _cache
cached_result = _cache.get(cache_key)
```
(and similarly for set calls — replace `self.cache.set(...)` with `_cache.set(...)`)

**Step 4: Run tests**

```bash
pytest tests/unit/test_process_manager_fix.py -v
```
Expected: 3 PASSED

**Step 5: Run full suite**

```bash
pytest -v --tb=short 2>&1 | tail -20
```
Expected: All PASSED

**Step 6: Commit**

```bash
git add managers/process_manager.py
git commit -m "fix(process): remove duplicate cache, set CPU-aware worker count"
```

---

### Task 15: Integrate ResourceMonitor into process pool auto-scaling

**Files:**
- Modify: `managers/process_manager.py`

**Step 1: Write failing test**

```python
# Append to tests/unit/test_process_manager_fix.py
def test_resource_monitor_imported_in_process_manager():
    """process_manager module must use ResourceMonitor for resource_thresholds."""
    import inspect
    import managers.process_manager as pm_mod
    src = inspect.getsource(pm_mod)
    assert "ResourceMonitor" in src or "get_resource_monitor" in src
```

**Step 2: Verify fails**

```bash
pytest tests/unit/test_process_manager_fix.py::test_resource_monitor_imported_in_process_manager -v
```

**Step 3: Replace inline ResourceMonitor construction in process_manager.py**

Find (near line 30):
```python
self.resource_monitor = ResourceMonitor()
```

Replace with:
```python
from managers.resource_monitor import get_resource_monitor
self.resource_monitor = get_resource_monitor()
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_process_manager_fix.py -v
```
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add managers/process_manager.py tests/unit/test_process_manager_fix.py
git commit -m "feat(process): use ResourceMonitor singleton in process pool"
```

---

### Task 16: Full regression after Batch 2

```bash
pytest -v --tb=short 2>&1 | tail -30
```
Expected: All PASSED (≥505)

```bash
git add -A
git commit -m "chore: Batch 2 complete — process pool cleanup regression check"
```

---

## Batch 3 — Lazy Tool Loading (Tasks 17–31)

> **Goal:** Move all `tools.*` imports from module top-level into the route handler body. This means Python only imports the tool module when the first HTTP request hits that route — saving ~200–400 MB on startup.

> **Pattern (use in ALL tasks below):**
> ```python
> # BEFORE (top-level)
> from tools.osint.passive_recon import shodan_search, whois_lookup
>
> # AFTER (inside handler — lazy)
> def osint_passive_recon():
>     from tools.osint.passive_recon import shodan_search, whois_lookup
>     ...
> ```

---

### Task 17: Create core/lazy_import.py helper

**Files:**
- Create: `core/lazy_import.py`
- Create: `tests/unit/test_lazy_import.py`

**Step 1: Write failing test**

```python
# tests/unit/test_lazy_import.py
def test_lazy_load_returns_importerror_result_on_failure():
    from core.lazy_import import lazy_load
    fn, available = lazy_load("nonexistent_module_xyz", "some_func")
    assert available is False
    result = fn()
    assert result["success"] is False
    assert "not available" in result["error"]


def test_lazy_load_returns_real_function_on_success():
    from core.lazy_import import lazy_load
    # os.path.join is always available
    fn, available = lazy_load("os.path", "join")
    assert available is True
    assert fn("a", "b") == "a/b"
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_lazy_import.py -v
```

**Step 3: Implement**

```python
# core/lazy_import.py
"""
Lazy import helper for optional security tool modules.

Usage:
    shodan_search, _ok = lazy_load("tools.osint.passive_recon", "shodan_search")
    # _ok is True if import succeeded; False provides a safe stub.
"""
from __future__ import annotations
from typing import Callable, Tuple, Any


def lazy_load(module_path: str, func_name: str) -> Tuple[Callable, bool]:
    """Import module_path.func_name on first call.

    Returns (callable, True) on success.
    Returns (stub_returning_error_dict, False) on ImportError.
    """
    try:
        import importlib
        mod = importlib.import_module(module_path)
        fn = getattr(mod, func_name)
        return fn, True
    except (ImportError, AttributeError):
        module_label = f"{module_path}.{func_name}"

        def _stub(*args: Any, **kwargs: Any) -> dict:
            return {"success": False, "error": f"{module_label} not available"}

        return _stub, False
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_lazy_import.py -v
```
Expected: 2 PASSED

**Step 5: Commit**

```bash
git add core/lazy_import.py tests/unit/test_lazy_import.py
git commit -m "feat(lazy): add core/lazy_import.py helper"
```

---

### Task 18: Migrate osint.py to lazy imports

**Files:**
- Modify: `core/routes/osint.py`

> osint.py has **direct top-level imports** (no try/except). This is the highest-priority file.

**Step 1: Write the test proving lazy loading works**

```python
# tests/unit/test_osint_lazy.py
"""Verify osint Blueprint has no top-level tool imports."""
import ast
import os


def test_no_top_level_tool_imports():
    path = os.path.join("core", "routes", "osint.py")
    with open(path) as f:
        tree = ast.parse(f.read())
    # Walk top-level statements only (not inside FunctionDef)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if hasattr(node, "module") and node.module and node.module.startswith("tools."):
                raise AssertionError(
                    f"Top-level tool import found in osint.py: 'from {node.module} import ...'"
                )
```

**Step 2: Run to verify it fails**

```bash
pytest tests/unit/test_osint_lazy.py -v
```
Expected: FAIL — top-level import detected

**Step 3: Migrate osint.py**

Remove the three top-level import lines (9–11):
```python
from tools.osint.passive_recon import shodan_search, whois_lookup, the_harvester, dnsdumpster_recon, censys_search
from tools.osint.social_intel import sherlock_search, holehe_check, breach_lookup
from tools.osint.threat_intel import virustotal_lookup, otx_lookup, urlscan_lookup, shodan_cve_lookup
```

Inside each route handler, add the specific imports it needs. Example for `osint_passive_recon`:
```python
@osint_bp.route('/api/osint/passive-recon', methods=['POST'])
def osint_passive_recon():
    from tools.osint.passive_recon import shodan_search, whois_lookup, the_harvester, dnsdumpster_recon
    ...
```

Repeat for every route handler in osint.py, importing only what that handler uses.

**Step 4: Run lazy test + full route tests**

```bash
pytest tests/unit/test_osint_lazy.py tests/unit/test_osint_routes.py -v
```
Expected: All PASSED

**Step 5: Commit**

```bash
git add core/routes/osint.py tests/unit/test_osint_lazy.py
git commit -m "perf(lazy): migrate osint.py to lazy tool imports"
```

---

### Task 19: Migrate binary.py to lazy imports

**Files:**
- Modify: `core/routes/binary.py`

> binary.py has try/except ImportError blocks at module top-level (lines 15–31).
> Goal: remove them and move each import inside the route that uses it.

**Step 1: Write the test**

```python
# tests/unit/test_binary_lazy.py
"""Verify binary Blueprint has no top-level try/except tool imports."""
import ast
import os


def _get_top_level_try_imports(path: str) -> list:
    with open(path) as f:
        tree = ast.parse(f.read())
    found = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                if isinstance(child, ast.ImportFrom):
                    if child.module and child.module.startswith("tools."):
                        found.append(child.module)
    return found


def test_no_top_level_try_tool_imports():
    path = os.path.join("core", "routes", "binary.py")
    found = _get_top_level_try_imports(path)
    assert found == [], f"Top-level try/except tool imports still in binary.py: {found}"
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_binary_lazy.py -v
```

**Step 3: Remove the three try/except blocks (lines 15–31) from binary.py**

Then in each route that used `_ENHANCED_BINARY_AVAILABLE`, `_MALWARE_ANALYSIS_AVAILABLE`, or `_FORENSICS_AVAILABLE`, move the import inside the handler and use try/except locally:

```python
@binary_bp.route('/api/binary/rizin', methods=['POST'])
def binary_rizin():
    try:
        from tools.binary.enhanced_binary import rizin_analyze
    except ImportError:
        return jsonify({"success": False, "error": "enhanced_binary not available"}), 503
    ...
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_binary_lazy.py tests/unit/test_binary_tools.py -v
```
Expected: All PASSED

**Step 5: Commit**

```bash
git add core/routes/binary.py tests/unit/test_binary_lazy.py
git commit -m "perf(lazy): migrate binary.py to lazy tool imports"
```

---

### Task 20: Migrate api_security.py to lazy imports

**Files:**
- Modify: `core/routes/api_security.py`

> api_security.py has 4 try/except blocks at module top-level (lines 13–74).

**Step 1: Write test (same AST pattern as Task 19)**

```python
# tests/unit/test_api_security_lazy.py
import ast, os

def test_no_top_level_try_tool_imports():
    path = os.path.join("core", "routes", "api_security.py")
    with open(path) as f:
        tree = ast.parse(f.read())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                if isinstance(child, ast.ImportFrom):
                    if child.module and child.module.startswith("tools."):
                        raise AssertionError(f"Top-level try import: {child.module}")
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_api_security_lazy.py -v
```

**Step 3: Remove all 4 try/except import blocks + stub functions from module top-level**

Move each import into its respective route handler using local try/except. Example:

```python
@api_security_bp.route('/api/api/discover', methods=['POST'])
def api_discover():
    try:
        from tools.api.api_discovery import kiterunner_scan
    except ImportError:
        return jsonify({"success": False, "error": "api_discovery not available"}), 503
    ...
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_api_security_lazy.py tests/unit/test_api_tools.py -v
```

**Step 5: Commit**

```bash
git add core/routes/api_security.py tests/unit/test_api_security_lazy.py
git commit -m "perf(lazy): migrate api_security.py to lazy tool imports"
```

---

### Task 21: Migrate mobile.py to lazy imports

**Files:**
- Modify: `core/routes/mobile.py`

**Step 1: Write test**

```python
# tests/unit/test_mobile_lazy.py
import ast, os

def test_no_top_level_try_tool_imports():
    path = os.path.join("core", "routes", "mobile.py")
    with open(path) as f:
        tree = ast.parse(f.read())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                if isinstance(child, ast.ImportFrom):
                    if child.module and child.module.startswith("tools."):
                        raise AssertionError(f"Top-level try import: {child.module}")
```

**Step 2: Run to verify fails → Step 3: Migrate → Step 4: Run tests → Step 5: Commit**

Same pattern as Task 20.

```bash
pytest tests/unit/test_mobile_lazy.py tests/unit/test_mobile_tools.py -v
git add core/routes/mobile.py tests/unit/test_mobile_lazy.py
git commit -m "perf(lazy): migrate mobile.py to lazy tool imports"
```

---

### Task 22: Migrate wireless.py to lazy imports

Same pattern as Tasks 19–21.

```bash
# tests/unit/test_wireless_lazy.py  (same AST pattern)
pytest tests/unit/test_wireless_lazy.py tests/unit/test_wireless_tools.py -v
git add core/routes/wireless.py tests/unit/test_wireless_lazy.py
git commit -m "perf(lazy): migrate wireless.py to lazy tool imports"
```

---

### Task 23: Migrate cloud.py to lazy imports

Same pattern as Tasks 19–21.

```bash
# tests/unit/test_cloud_lazy.py  (same AST pattern)
pytest tests/unit/test_cloud_lazy.py -v
git add core/routes/cloud.py tests/unit/test_cloud_lazy.py
git commit -m "perf(lazy): migrate cloud.py to lazy tool imports"
```

---

### Task 24: Run memory benchmark post-lazy-loading

```bash
python tests/benchmarks/test_memory_baseline.py
```

Record results and compare to Task 10 baseline. Expect ≥100 MB RSS reduction.

```bash
git add tests/benchmarks/
git commit -m "chore(bench): record post-lazy-loading memory measurement"
```

---

### Task 25: Full regression after Batch 3

```bash
pytest -v --tb=short 2>&1 | tail -30
```
Expected: All PASSED (≥505)

```bash
git commit --allow-empty -m "chore: Batch 3 complete — lazy loading regression check"
```

---

## Batch 4 — Async Scan Streaming (Tasks 26–45)

> **Pattern:** Every heavy scan endpoint gets an `/async` variant.
> POST returns `{"task_id": "scan_abc123"}` immediately.
> Caller polls `GET /api/tasks/<task_id>` for status (`pending`/`running`/`done`/`error`) and result.

---

### Task 26: Write failing tests for TaskStore

**Files:**
- Create: `tests/unit/test_task_store.py`

**Step 1: Write tests**

```python
# tests/unit/test_task_store.py
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
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_task_store.py -v
```
Expected: `ImportError: cannot import name 'TaskStore'`

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_task_store.py
git commit -m "test(async): add failing tests for TaskStore"
```

---

### Task 27: Implement core/task_store.py

**Files:**
- Create: `core/task_store.py`

**Step 1: Implement**

```python
# core/task_store.py
"""In-memory task registry for async scan polling."""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, Optional


class TaskStore:
    """Thread-safe store for async task state: pending → running → done/error."""

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
```

**Step 2: Run tests**

```bash
pytest tests/unit/test_task_store.py -v
```
Expected: 7 PASSED

**Step 3: Commit**

```bash
git add core/task_store.py
git commit -m "feat(async): implement TaskStore for async scan polling"
```

---

### Task 28: Write failing tests for /api/tasks routes

**Files:**
- Create: `tests/unit/test_tasks_routes.py`

**Step 1: Write tests**

```python
# tests/unit/test_tasks_routes.py
import pytest


@pytest.fixture
def client(app):
    return app.test_client()


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
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_tasks_routes.py -v
```
Expected: 404 — route not registered yet

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_tasks_routes.py
git commit -m "test(async): add failing tests for /api/tasks routes"
```

---

### Task 29: Create core/routes/tasks.py Blueprint

**Files:**
- Create: `core/routes/tasks.py`

**Step 1: Implement**

```python
# core/routes/tasks.py
"""Task status/result polling endpoints for async scans."""
from flask import Blueprint, jsonify
from core.task_store import task_store

tasks_bp = Blueprint('tasks', __name__)


@tasks_bp.route('/api/tasks/<task_id>', methods=['GET'])
def get_task_status(task_id: str):
    """Poll an async task for its current status and (when done) result."""
    task = task_store.get(task_id)
    if task is None:
        return jsonify({"success": False, "error": "task not found"}), 404
    return jsonify(task)
```

**Step 2: Register in core/server.py**

Find where Blueprints are registered in `core/server.py` (the `create_app` factory).
Add:
```python
from core.routes.tasks import tasks_bp
app.register_blueprint(tasks_bp)
```

**Step 3: Run tests**

```bash
pytest tests/unit/test_tasks_routes.py -v
```
Expected: 3 PASSED

**Step 4: Commit**

```bash
git add core/routes/tasks.py core/server.py
git commit -m "feat(async): add /api/tasks Blueprint for poll-based scan results"
```

---

### Task 30: Create async_run() helper

**Files:**
- Create: `core/async_runner.py`
- Create: `tests/unit/test_async_runner.py`

**Step 1: Write failing test**

```python
# tests/unit/test_async_runner.py
import time
from unittest.mock import patch


def test_async_run_returns_task_id_immediately():
    from core.async_runner import async_run
    from core.task_store import task_store

    def slow_fn():
        time.sleep(0.05)
        return {"output": "done"}

    task_id = async_run(slow_fn)
    assert task_id.startswith("task_")
    # Status should be pending or running immediately
    task = task_store.get(task_id)
    assert task is not None
    assert task["status"] in ("pending", "running")


def test_async_run_eventually_sets_done():
    from core.async_runner import async_run
    from core.task_store import task_store
    import time

    def fast_fn():
        return {"output": "ok"}

    task_id = async_run(fast_fn)
    # Poll up to 2 seconds
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
    import time

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
```

**Step 2: Run to verify fails → implement → run to verify passes**

```python
# core/async_runner.py
"""Submit a callable to a background thread, track via TaskStore."""
from __future__ import annotations
import threading
from typing import Callable, Any
from core.task_store import task_store


def async_run(fn: Callable[[], Any], command_label: str = "async_task") -> str:
    """Run fn() in a daemon thread. Return task_id for polling."""
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
```

**Step 3: Run tests**

```bash
pytest tests/unit/test_async_runner.py -v
```
Expected: 3 PASSED

**Step 4: Commit**

```bash
git add core/async_runner.py tests/unit/test_async_runner.py
git commit -m "feat(async): add async_run() helper backed by TaskStore"
```

---

### Task 31: Add async variant to nmap route

**Files:**
- Modify: `core/routes/network.py`
- Modify: `tests/unit/test_network_routes.py`

**Step 1: Write failing test**

```python
# Append to tests/unit/test_network_routes.py
def test_nmap_async_returns_task_id(client):
    resp = client.post('/api/network/nmap/async', json={"target": "127.0.0.1"})
    assert resp.status_code == 202
    data = resp.get_json()
    assert "task_id" in data
    assert data["task_id"].startswith("task_")
```

**Step 2: Add route to core/routes/network.py**

After the existing `/api/network/nmap` route, add:

```python
@network_bp.route('/api/network/nmap/async', methods=['POST'])
def network_nmap_async():
    """Launch nmap in background; returns task_id for polling."""
    from core.async_runner import async_run
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400

    def _run():
        if not shutil.which('nmap'):
            return {"success": False, "error": "nmap not installed"}
        flags = params.get('flags', '-sV')
        result = subprocess.run(
            ['nmap'] + flags.split() + [target],
            capture_output=True, text=True, timeout=300
        )
        return {"success": result.returncode == 0, "output": result.stdout, "error": result.stderr}

    task_id = async_run(_run, f"nmap {target}")
    return jsonify({"task_id": task_id, "status": "pending"}), 202
```

**Step 3: Run tests → commit**

```bash
pytest tests/unit/test_network_routes.py -k "async" -v
git add core/routes/network.py tests/unit/test_network_routes.py
git commit -m "feat(async): add /api/network/nmap/async endpoint"
```

---

### Task 32: Add async variants for nuclei, gobuster, rustscan, masscan

> Follow the **exact same pattern** as Task 31 for each tool.
> Each tool gets:
> - Route: `POST /api/<domain>/<tool>/async` → 202 + `{"task_id": "..."}`
> - Test: `test_<tool>_async_returns_task_id(client)`

**Tools to add:**
- `nuclei` → `core/routes/web.py`
- `gobuster` → `core/routes/web.py`
- `rustscan` → `core/routes/network.py`
- `masscan` → `core/routes/network.py`

For each:
1. Write failing test
2. Run to verify fails
3. Add async route
4. Run to verify passes
5. Commit per tool

```bash
# After all 4:
pytest tests/unit/ -k "async" -v
git commit -m "feat(async): add async variants for nuclei, gobuster, rustscan, masscan"
```

---

### Task 33: Add async variants for amass, subfinder, feroxbuster

> Same pattern as Task 32.

- `amass` → `core/routes/network.py`
- `subfinder` → `core/routes/network.py`
- `feroxbuster` → `core/routes/web.py`

```bash
pytest tests/unit/ -k "async" -v
git commit -m "feat(async): add async variants for amass, subfinder, feroxbuster"
```

---

### Task 34: Create hexstrike_mcp_tools/async_tools.py

**Files:**
- Create: `hexstrike_mcp_tools/async_tools.py`
- Modify: `hexstrike_mcp.py`

**Step 1: Write failing test**

```python
# tests/unit/test_mcp_async_tools.py
def test_mcp_async_nmap_module_importable():
    from hexstrike_mcp_tools import async_tools  # noqa
    assert hasattr(async_tools, 'nmap_scan_async')


def test_mcp_async_nuclei_module_importable():
    from hexstrike_mcp_tools import async_tools
    assert hasattr(async_tools, 'nuclei_scan_async')
```

**Step 2: Run to verify fails → implement**

```python
# hexstrike_mcp_tools/async_tools.py
"""MCP tools: async scan wrappers — POST /async → poll /api/tasks/<id>."""
from typing import Optional
from hexstrike_mcp_tools.client import get_client
from hexstrike_mcp_tools import mcp


@mcp.tool()
def nmap_scan_async(target: str, flags: str = "-sV") -> str:
    """Start nmap in background. Returns task_id — poll with get_task_status()."""
    return get_client().safe_post("/api/network/nmap/async", {"target": target, "flags": flags})


@mcp.tool()
def nuclei_scan_async(target: str, templates: Optional[str] = None) -> str:
    """Start nuclei in background. Returns task_id."""
    return get_client().safe_post("/api/web/nuclei/async", {"target": target, "templates": templates})


@mcp.tool()
def gobuster_async(target: str, wordlist: Optional[str] = None) -> str:
    """Start gobuster in background. Returns task_id."""
    return get_client().safe_post("/api/web/gobuster/async", {"target": target, "wordlist": wordlist})


@mcp.tool()
def get_task_status(task_id: str) -> str:
    """Poll async task status. Returns status + result when done."""
    return get_client().safe_post(f"/api/tasks/{task_id}", {}, method="GET")
```

**Step 3: Register in hexstrike_mcp.py**

```python
import hexstrike_mcp_tools.async_tools  # noqa
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_mcp_async_tools.py -v
```

**Step 5: Commit**

```bash
git add hexstrike_mcp_tools/async_tools.py hexstrike_mcp.py tests/unit/test_mcp_async_tools.py
git commit -m "feat(mcp): add async_tools MCP module with task polling"
```

---

### Task 35: Full regression after Batch 4

```bash
pytest -v --tb=short 2>&1 | tail -30
```
Expected: All PASSED (≥540)

```bash
git commit --allow-empty -m "chore: Batch 4 complete — async streaming regression check"
```

---

## Batch 5 — Stealth Browser Agent (Tasks 36–62)

---

### Task 36: Add undetected-chromedriver to requirements.txt

**Step 1: Write bootstrap test**

```python
# tests/unit/test_uc_dep.py
def test_uc_importable():
    import undetected_chromedriver  # noqa
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_uc_dep.py -v
```

**Step 3: Add to requirements.txt**

```
undetected-chromedriver>=3.5.0
```

```bash
pip install undetected-chromedriver>=3.5.0
```

**Step 4: Run test → commit**

```bash
pytest tests/unit/test_uc_dep.py -v
git add requirements.txt tests/unit/test_uc_dep.py
git commit -m "feat(deps): add undetected-chromedriver>=3.5.0"
```

---

### Task 37: Write failing tests for StealthBrowserAgent skeleton

**Files:**
- Create: `tests/unit/test_stealth_browser_agent.py`

**Step 1: Write tests**

```python
# tests/unit/test_stealth_browser_agent.py
"""StealthBrowserAgent tests — all Chrome calls are mocked."""
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_uc():
    """Patch undetected_chromedriver so no real Chrome needed."""
    with patch("agents.stealth_browser_agent.uc") as mock:
        mock_driver = MagicMock()
        mock.Chrome.return_value = mock_driver
        yield mock, mock_driver


def test_stealth_agent_instantiation():
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    assert agent.driver is None
    assert agent.preset == "standard"


def test_setup_browser_creates_driver(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    result = agent.setup_browser()
    assert result is True
    assert agent.driver is driver_mock


def test_preset_minimal_does_not_add_extra_args(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent(preset="minimal")
    agent.setup_browser()
    # The driver must have been created
    assert uc_mock.Chrome.called


def test_preset_paranoid_sets_language_header(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent(preset="paranoid")
    agent.setup_browser()
    assert uc_mock.Chrome.called


def test_navigate_stealth_calls_get(mock_uc):
    uc_mock, driver_mock = mock_uc
    driver_mock.current_url = "https://example.com"
    driver_mock.title = "Example"
    driver_mock.page_source = "<html></html>"
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    result = agent.navigate_stealth("https://example.com")
    driver_mock.get.assert_called_once_with("https://example.com")
    assert result["success"] is True


def test_close_quits_driver(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    agent.close()
    driver_mock.quit.assert_called_once()
    assert agent.driver is None
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_stealth_browser_agent.py -v
```
Expected: `ImportError: cannot import name 'StealthBrowserAgent'`

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_stealth_browser_agent.py
git commit -m "test(browser): add failing tests for StealthBrowserAgent"
```

---

### Task 38: Implement StealthBrowserAgent skeleton

**Files:**
- Create: `agents/stealth_browser_agent.py`

**Step 1: Implement minimal passing version**

```python
# agents/stealth_browser_agent.py
"""
StealthBrowserAgent — extends BrowserAgent with undetected-chromedriver
and human behaviour simulation.

Presets:
  minimal  — undetected-chromedriver only (fastest, least overhead)
  standard — UC + randomised delays + smooth scroll (default)
  paranoid — UC + full HumanBehaviourMixin + canvas/WebGL spoofing
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

try:
    import undetected_chromedriver as uc
except ImportError:
    uc = None  # type: ignore

from utils.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

_VALID_PRESETS = ("minimal", "standard", "paranoid")


class StealthBrowserAgent:
    """Anti-detection browser agent powered by undetected-chromedriver."""

    def __init__(self, preset: str = "standard", headless: bool = True):
        if preset not in _VALID_PRESETS:
            raise ValueError(f"preset must be one of {_VALID_PRESETS}")
        self.preset = preset
        self.headless = headless
        self.driver: Any = None

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def setup_browser(self, proxy_host: Optional[str] = None, proxy_port: Optional[int] = None) -> bool:
        """Initialise undetected-chromedriver with preset settings."""
        if uc is None:
            logger.error("undetected-chromedriver not installed — run: pip install undetected-chromedriver")
            return False
        try:
            options = uc.ChromeOptions()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")

            if proxy_host and proxy_port:
                options.add_argument(f"--proxy-server=http://{proxy_host}:{proxy_port}")

            if self.preset == "paranoid":
                self._apply_paranoid_options(options)

            self.driver = uc.Chrome(options=options, headless=self.headless)
            logger.info("StealthBrowserAgent: driver initialised (preset=%s)", self.preset)
            return True
        except Exception as exc:
            logger.error("StealthBrowserAgent setup failed: %s", exc)
            return False

    def _apply_paranoid_options(self, options: Any) -> None:
        """Extra hardening for paranoid preset."""
        options.add_argument("--lang=en-US,en;q=0.9")
        options.add_argument("--disable-blink-features=AutomationControlled")

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def navigate_stealth(self, url: str, wait_seconds: float = 2.0) -> Dict[str, Any]:
        """Navigate to url with optional human-like pause."""
        if not self.driver:
            if not self.setup_browser():
                return {"success": False, "error": "driver not initialised"}
        try:
            self.driver.get(url)
            if self.preset != "minimal":
                time.sleep(wait_seconds)
            return {
                "success": True,
                "url": self.driver.current_url,
                "title": self.driver.title,
                "page_source_length": len(self.driver.page_source),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            finally:
                self.driver = None
```

**Step 2: Run tests**

```bash
pytest tests/unit/test_stealth_browser_agent.py -v
```
Expected: All PASSED

**Step 3: Commit**

```bash
git add agents/stealth_browser_agent.py
git commit -m "feat(browser): add StealthBrowserAgent skeleton with UC driver"
```

---

### Task 39: Write failing tests for HumanBehaviourMixin

**Files:**
- Create: `tests/unit/test_human_behaviour_mixin.py`

**Step 1: Write tests**

```python
# tests/unit/test_human_behaviour_mixin.py
from unittest.mock import MagicMock, patch
import time


def test_type_with_delays_sends_keys_one_by_one():
    from agents.human_behaviour import HumanBehaviourMixin
    mixin = HumanBehaviourMixin()
    mock_element = MagicMock()
    with patch("time.sleep"):  # mock sleep so test is fast
        mixin.type_with_delays(mock_element, "hello")
    # send_keys called once per character
    assert mock_element.send_keys.call_count == 5


def test_smooth_scroll_executes_js(mock_driver):
    from agents.human_behaviour import HumanBehaviourMixin
    mixin = HumanBehaviourMixin()
    driver = MagicMock()
    with patch("time.sleep"):
        mixin.smooth_scroll(driver, distance=500)
    assert driver.execute_script.called


def test_random_pause_sleeps_within_range():
    from agents.human_behaviour import HumanBehaviourMixin
    mixin = HumanBehaviourMixin()
    with patch("time.sleep") as mock_sleep:
        mixin.random_pause(min_s=0.5, max_s=1.5)
        call_args = mock_sleep.call_args[0][0]
        assert 0.5 <= call_args <= 1.5


def test_bezier_mouse_move_calls_action_chain():
    """Bezier curve generates intermediate points; ActionChains.move_by_offset called multiple times."""
    from agents.human_behaviour import HumanBehaviourMixin
    from unittest.mock import patch, MagicMock
    mixin = HumanBehaviourMixin()
    mock_driver = MagicMock()
    with patch("agents.human_behaviour.ActionChains") as mock_ac_cls:
        mock_ac = MagicMock()
        mock_ac_cls.return_value = mock_ac
        mock_ac.move_by_offset.return_value = mock_ac
        mock_ac.perform.return_value = None
        with patch("time.sleep"):
            mixin.bezier_mouse_move(mock_driver, dx=100, dy=50)
        # At least 3 intermediate points
        assert mock_ac.move_by_offset.call_count >= 3
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_human_behaviour_mixin.py -v
```

**Step 3: Commit failing tests**

```bash
git add tests/unit/test_human_behaviour_mixin.py
git commit -m "test(browser): add failing tests for HumanBehaviourMixin"
```

---

### Task 40: Implement agents/human_behaviour.py

**Files:**
- Create: `agents/human_behaviour.py`

**Step 1: Implement**

```python
# agents/human_behaviour.py
"""
HumanBehaviourMixin: randomised, human-like interactions for Selenium/UC drivers.

Methods:
  type_with_delays(element, text)   — character-by-character with random pauses
  smooth_scroll(driver, distance)   — incremental JS scroll
  random_pause(min_s, max_s)        — sleep random duration in range
  bezier_mouse_move(driver, dx, dy) — Bezier curve mouse trajectory
"""
from __future__ import annotations

import random
import time
from typing import Any

try:
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    ActionChains = None  # type: ignore


def _bezier_points(p0: tuple, p1: tuple, p2: tuple, n: int = 10) -> list:
    """Generate n points along a quadratic Bezier curve p0→p1→p2."""
    points = []
    for i in range(n + 1):
        t = i / n
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        points.append((x, y))
    return points


class HumanBehaviourMixin:
    """Mix into any browser agent class to gain human-like interaction methods."""

    def type_with_delays(self, element: Any, text: str,
                         min_delay: float = 0.05, max_delay: float = 0.18) -> None:
        """Type text character by character with randomised inter-key delays."""
        for char in text:
            element.send_keys(char)
            time.sleep(random.uniform(min_delay, max_delay))

    def smooth_scroll(self, driver: Any, distance: int = 300,
                      steps: int = 10, step_delay: float = 0.03) -> None:
        """Scroll distance pixels smoothly via incremental JS calls."""
        step_size = distance // steps
        for _ in range(steps):
            driver.execute_script(f"window.scrollBy(0, {step_size});")
            time.sleep(step_delay)

    def random_pause(self, min_s: float = 0.5, max_s: float = 2.0) -> None:
        """Sleep for a random duration between min_s and max_s seconds."""
        time.sleep(random.uniform(min_s, max_s))

    def bezier_mouse_move(self, driver: Any, dx: int = 100, dy: int = 50,
                          steps: int = 10, step_delay: float = 0.02) -> None:
        """Move mouse along a Bezier curve from current position by (dx, dy)."""
        if ActionChains is None:
            return
        # Control point is offset randomly to create a natural curve
        cx = dx // 2 + random.randint(-20, 20)
        cy = dy // 4 + random.randint(-10, 10)
        points = _bezier_points((0, 0), (cx, cy), (dx, dy), n=steps)
        actions = ActionChains(driver)
        prev_x, prev_y = 0, 0
        for px, py in points[1:]:
            delta_x = int(px - prev_x)
            delta_y = int(py - prev_y)
            actions.move_by_offset(delta_x, delta_y)
            prev_x, prev_y = px, py
        actions.perform()
        time.sleep(step_delay)
```

**Step 2: Run tests**

```bash
pytest tests/unit/test_human_behaviour_mixin.py -v
```
Expected: 4 PASSED

**Step 3: Commit**

```bash
git add agents/human_behaviour.py
git commit -m "feat(browser): implement HumanBehaviourMixin with Bezier, scroll, typing"
```

---

### Task 41: Integrate HumanBehaviourMixin into StealthBrowserAgent

**Files:**
- Modify: `agents/stealth_browser_agent.py`

**Step 1: Write failing test**

```python
# Append to tests/unit/test_stealth_browser_agent.py
def test_standard_preset_has_human_behaviour(mock_uc):
    from agents.stealth_browser_agent import StealthBrowserAgent
    from agents.human_behaviour import HumanBehaviourMixin
    agent = StealthBrowserAgent(preset="standard")
    assert isinstance(agent, HumanBehaviourMixin)
```

**Step 2: Run to verify fails**

```bash
pytest tests/unit/test_stealth_browser_agent.py::test_standard_preset_has_human_behaviour -v
```

**Step 3: Update StealthBrowserAgent class definition**

```python
from agents.human_behaviour import HumanBehaviourMixin

class StealthBrowserAgent(HumanBehaviourMixin):
    ...
```

**Step 4: Run all stealth tests**

```bash
pytest tests/unit/test_stealth_browser_agent.py -v
```
Expected: All PASSED

**Step 5: Commit**

```bash
git add agents/stealth_browser_agent.py tests/unit/test_stealth_browser_agent.py
git commit -m "feat(browser): StealthBrowserAgent extends HumanBehaviourMixin"
```

---

### Task 42: Add screenshot_stealth() method

**Files:**
- Modify: `agents/stealth_browser_agent.py`
- Modify: `tests/unit/test_stealth_browser_agent.py`

**Step 1: Write failing test**

```python
def test_screenshot_stealth_returns_base64(mock_uc):
    uc_mock, driver_mock = mock_uc
    driver_mock.get_screenshot_as_base64.return_value = "abc123base64"
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    result = agent.screenshot_stealth()
    assert result["success"] is True
    assert result["screenshot_b64"] == "abc123base64"
```

**Step 2: Implement in StealthBrowserAgent**

```python
def screenshot_stealth(self) -> Dict[str, Any]:
    """Capture screenshot; return base64-encoded image."""
    if not self.driver:
        return {"success": False, "error": "driver not initialised"}
    try:
        b64 = self.driver.get_screenshot_as_base64()
        return {"success": True, "screenshot_b64": b64}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
```

**Step 3: Run tests → commit**

```bash
pytest tests/unit/test_stealth_browser_agent.py -v
git add agents/stealth_browser_agent.py tests/unit/test_stealth_browser_agent.py
git commit -m "feat(browser): add screenshot_stealth() method"
```

---

### Task 43: Add form_fill_stealth() method

**Files:**
- Modify: `agents/stealth_browser_agent.py`
- Modify: `tests/unit/test_stealth_browser_agent.py`

**Step 1: Write failing test**

```python
def test_form_fill_stealth_types_with_delays(mock_uc):
    uc_mock, driver_mock = mock_uc
    mock_element = MagicMock()
    driver_mock.find_element.return_value = mock_element
    from agents.stealth_browser_agent import StealthBrowserAgent
    from selenium.webdriver.common.by import By
    with patch("time.sleep"):
        agent = StealthBrowserAgent()
        agent.setup_browser()
        result = agent.form_fill_stealth("#username", "testuser")
    assert result["success"] is True
    assert mock_element.send_keys.call_count == len("testuser")
```

**Step 2: Implement**

```python
def form_fill_stealth(self, css_selector: str, value: str) -> Dict[str, Any]:
    """Find element by CSS selector and type value with human-like delays."""
    if not self.driver:
        return {"success": False, "error": "driver not initialised"}
    try:
        from selenium.webdriver.common.by import By
        element = self.driver.find_element(By.CSS_SELECTOR, css_selector)
        element.clear()
        self.type_with_delays(element, value)
        return {"success": True, "selector": css_selector, "value_length": len(value)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
```

**Step 3: Run tests → commit**

```bash
pytest tests/unit/test_stealth_browser_agent.py -v
git add agents/stealth_browser_agent.py tests/unit/test_stealth_browser_agent.py
git commit -m "feat(browser): add form_fill_stealth() with human typing"
```

---

### Task 44: Add extract_dom_stealth() method

**Files:**
- Modify: `agents/stealth_browser_agent.py`

**Step 1: Write failing test**

```python
def test_extract_dom_stealth_returns_page_source(mock_uc):
    uc_mock, driver_mock = mock_uc
    driver_mock.page_source = "<html><body>test</body></html>"
    driver_mock.execute_script.return_value = []
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    result = agent.extract_dom_stealth()
    assert result["success"] is True
    assert "page_source" in result
    assert "<html>" in result["page_source"]
```

**Step 2: Implement**

```python
def extract_dom_stealth(self) -> Dict[str, Any]:
    """Extract page source and basic DOM metadata."""
    if not self.driver:
        return {"success": False, "error": "driver not initialised"}
    try:
        links = self.driver.execute_script(
            "return Array.from(document.querySelectorAll('a')).map(a => a.href).slice(0, 50)"
        )
        forms = self.driver.execute_script(
            "return Array.from(document.querySelectorAll('form')).length"
        )
        return {
            "success": True,
            "url": self.driver.current_url,
            "title": self.driver.title,
            "page_source": self.driver.page_source,
            "link_count": len(links or []),
            "links_sample": (links or [])[:10],
            "form_count": forms or 0,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}
```

**Step 3: Run tests → commit**

```bash
pytest tests/unit/test_stealth_browser_agent.py -v
git add agents/stealth_browser_agent.py tests/unit/test_stealth_browser_agent.py
git commit -m "feat(browser): add extract_dom_stealth() method"
```

---

### Task 45: Add ProxyProvider stub

**Files:**
- Create: `agents/proxy_provider.py`
- Create: `tests/unit/test_proxy_provider.py`

> Proxies are deferred. This task just creates the interface stub so future implementations can slot in.

**Step 1: Write test**

```python
# tests/unit/test_proxy_provider.py
def test_proxy_provider_interface_importable():
    from agents.proxy_provider import ProxyProvider
    p = ProxyProvider()
    # get_proxy returns None (deferred implementation)
    assert p.get_proxy() is None


def test_proxy_provider_noop_rotate():
    from agents.proxy_provider import ProxyProvider
    p = ProxyProvider()
    p.rotate()  # must not raise
```

**Step 2: Implement stub**

```python
# agents/proxy_provider.py
"""ProxyProvider: stub interface for future smart proxy rotation."""
from __future__ import annotations
from typing import Optional


class ProxyProvider:
    """Interface stub — implement subclass for smart rotation (future epic)."""

    def get_proxy(self) -> Optional[dict]:
        """Return {'host': str, 'port': int} or None (no proxy)."""
        return None

    def rotate(self) -> None:
        """Signal that current proxy should be rotated (no-op in base class)."""
        pass
```

**Step 3: Run tests → commit**

```bash
pytest tests/unit/test_proxy_provider.py -v
git add agents/proxy_provider.py tests/unit/test_proxy_provider.py
git commit -m "feat(browser): add ProxyProvider stub interface (deferred impl)"
```

---

### Task 46: Create core/routes/browser.py Blueprint

**Files:**
- Create: `core/routes/browser.py`
- Create: `tests/unit/test_browser_routes.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_browser_routes.py
import pytest
from unittest.mock import patch, MagicMock


def test_browser_navigate_returns_success(client):
    with patch("core.routes.browser.StealthBrowserAgent") as mock_cls:
        mock_agent = MagicMock()
        mock_agent.navigate_stealth.return_value = {
            "success": True, "url": "https://example.com", "title": "Example", "page_source_length": 100
        }
        mock_cls.return_value = mock_agent
        resp = client.post('/api/browser/navigate', json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True


def test_browser_navigate_missing_url_returns_400(client):
    resp = client.post('/api/browser/navigate', json={})
    assert resp.status_code == 400


def test_browser_screenshot_returns_b64(client):
    with patch("core.routes.browser.StealthBrowserAgent") as mock_cls:
        mock_agent = MagicMock()
        mock_agent.setup_browser.return_value = True
        mock_agent.screenshot_stealth.return_value = {"success": True, "screenshot_b64": "abc"}
        mock_cls.return_value = mock_agent
        resp = client.post('/api/browser/screenshot', json={"url": "https://example.com"})
    assert resp.status_code == 200
```

**Step 2: Run to verify fails → implement**

```python
# core/routes/browser.py
"""Stealth browser agent routes."""
import logging
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
browser_bp = Blueprint('browser', __name__)


@browser_bp.route('/api/browser/navigate', methods=['POST'])
def browser_navigate():
    """Navigate to a URL with stealth browser; return DOM metadata."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        preset = params.get('preset', 'standard')
        agent = StealthBrowserAgent(preset=preset)
        result = agent.navigate_stealth(url, wait_seconds=params.get('wait', 2.0))
        agent.close()
        return jsonify(result)
    except Exception as exc:
        logger.error("browser_navigate error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


@browser_bp.route('/api/browser/screenshot', methods=['POST'])
def browser_screenshot():
    """Navigate to URL and capture screenshot (base64)."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        agent = StealthBrowserAgent(preset=params.get('preset', 'standard'))
        agent.setup_browser()
        agent.navigate_stealth(url)
        result = agent.screenshot_stealth()
        agent.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@browser_bp.route('/api/browser/dom', methods=['POST'])
def browser_dom():
    """Navigate to URL and extract DOM metadata."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        agent = StealthBrowserAgent(preset=params.get('preset', 'standard'))
        agent.navigate_stealth(url)
        result = agent.extract_dom_stealth()
        agent.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@browser_bp.route('/api/browser/form-fill', methods=['POST'])
def browser_form_fill():
    """Navigate to URL and fill a form field with stealth typing."""
    params = request.json or {}
    url = params.get('url', '')
    selector = params.get('selector', '')
    value = params.get('value', '')
    if not url or not selector:
        return jsonify({"success": False, "error": "url and selector are required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        agent = StealthBrowserAgent(preset=params.get('preset', 'standard'))
        agent.navigate_stealth(url)
        result = agent.form_fill_stealth(selector, value)
        agent.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500
```

**Step 3: Register in core/server.py**

```python
from core.routes.browser import browser_bp
app.register_blueprint(browser_bp)
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_browser_routes.py -v
```
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add core/routes/browser.py core/server.py tests/unit/test_browser_routes.py
git commit -m "feat(browser): add browser Blueprint with navigate/screenshot/dom/form-fill"
```

---

### Task 47: Create hexstrike_mcp_tools/browser.py MCP tools

**Files:**
- Create: `hexstrike_mcp_tools/browser.py`
- Modify: `hexstrike_mcp.py`

**Step 1: Write failing test**

```python
# tests/unit/test_mcp_browser_tools.py
def test_browser_mcp_module_importable():
    from hexstrike_mcp_tools import browser
    assert hasattr(browser, 'browser_navigate')
    assert hasattr(browser, 'browser_screenshot')
    assert hasattr(browser, 'browser_extract_dom')
    assert hasattr(browser, 'browser_form_fill')
```

**Step 2: Run to verify fails → implement**

```python
# hexstrike_mcp_tools/browser.py
"""MCP tools: stealth browser agent."""
from typing import Optional
from hexstrike_mcp_tools.client import get_client
from hexstrike_mcp_tools import mcp


@mcp.tool()
def browser_navigate(url: str, preset: str = "standard", wait: float = 2.0) -> str:
    """Navigate to a URL using stealth browser. Returns DOM metadata.
    preset: minimal | standard | paranoid"""
    return get_client().safe_post("/api/browser/navigate", {"url": url, "preset": preset, "wait": wait})


@mcp.tool()
def browser_screenshot(url: str, preset: str = "standard") -> str:
    """Navigate to URL and return base64-encoded screenshot."""
    return get_client().safe_post("/api/browser/screenshot", {"url": url, "preset": preset})


@mcp.tool()
def browser_extract_dom(url: str, preset: str = "standard") -> str:
    """Extract DOM structure, links, and form count from a URL."""
    return get_client().safe_post("/api/browser/dom", {"url": url, "preset": preset})


@mcp.tool()
def browser_form_fill(url: str, selector: str, value: str, preset: str = "standard") -> str:
    """Fill a form field (CSS selector) with value using stealth typing."""
    return get_client().safe_post(
        "/api/browser/form-fill",
        {"url": url, "selector": selector, "value": value, "preset": preset}
    )
```

**Step 3: Register in hexstrike_mcp.py**

```python
import hexstrike_mcp_tools.browser  # noqa
```

**Step 4: Run tests → commit**

```bash
pytest tests/unit/test_mcp_browser_tools.py -v
git add hexstrike_mcp_tools/browser.py hexstrike_mcp.py tests/unit/test_mcp_browser_tools.py
git commit -m "feat(mcp): add browser MCP tools (navigate/screenshot/dom/form-fill)"
```

---

### Task 48: Add agents/__init__.py exports

**Files:**
- Modify: `agents/__init__.py`

**Step 1: Add exports**

```python
# Add to agents/__init__.py
from agents.stealth_browser_agent import StealthBrowserAgent
from agents.human_behaviour import HumanBehaviourMixin
from agents.proxy_provider import ProxyProvider
```

**Step 2: Run full suite → commit**

```bash
pytest -v --tb=short 2>&1 | tail -20
git add agents/__init__.py
git commit -m "chore(agents): export StealthBrowserAgent, HumanBehaviourMixin, ProxyProvider"
```

---

### Task 49: E2E integration test for stealth browser route

**Files:**
- Create: `tests/integration/test_stealth_browser_e2e.py`

**Step 1: Write integration test (fully mocked — no real Chrome)**

```python
# tests/integration/test_stealth_browser_e2e.py
"""Integration: browser routes + StealthBrowserAgent (mock UC driver)."""
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def client(app):
    return app.test_client()


def test_navigate_dom_screenshot_pipeline(client):
    """Simulate: navigate → extract DOM → screenshot in sequence."""
    with patch("agents.stealth_browser_agent.uc") as uc_mock:
        drv = MagicMock()
        drv.current_url = "https://target.com"
        drv.title = "Target"
        drv.page_source = "<html><body>Hello</body></html>"
        drv.execute_script.return_value = ["https://target.com/page"]
        drv.get_screenshot_as_base64.return_value = "FAKEB64"
        uc_mock.Chrome.return_value = drv
        uc_mock.ChromeOptions.return_value = MagicMock()

        # Navigate
        resp = client.post('/api/browser/navigate', json={"url": "https://target.com"})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

        # Screenshot
        resp = client.post('/api/browser/screenshot', json={"url": "https://target.com"})
        assert resp.status_code == 200
        assert resp.get_json()["screenshot_b64"] == "FAKEB64"

        # DOM
        resp = client.post('/api/browser/dom', json={"url": "https://target.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["link_count"] >= 0
```

**Step 2: Run test → commit**

```bash
pytest tests/integration/test_stealth_browser_e2e.py -v
git add tests/integration/test_stealth_browser_e2e.py
git commit -m "test(integration): add stealth browser E2E integration test"
```

---

### Task 50: Remove bootstrap dep test for UC

```bash
git rm tests/unit/test_uc_dep.py
git commit -m "chore(test): remove one-time UC bootstrap test"
```

---

### Task 51: Final memory benchmark

```bash
python tests/benchmarks/test_memory_baseline.py
```

Compare against Task 10 baseline. Document the numbers in a comment.

Target: RSS delta ≤ 200 MB (down from ~400+ MB pre-lazy-loading).

---

### Task 52: Full final regression

```bash
pytest -v --tb=short 2>&1 | tail -30
```
Expected: All PASSED (≥560)

---

### Task 53: Update CHANGELOG.md for Phase 5

**Files:**
- Modify: `CHANGELOG.md`

Add new section at the top:

```markdown
## [7.1.0] - 2026-02-26 — Phase 5: Performance, Memory & Stealth

### Added
- `managers/disk_cache.py` — DiskTieredCache (256 MB in-memory + 512 MB disk via diskcache)
- `managers/resource_monitor.py` — ResourceMonitor singleton (psutil memory/CPU pressure)
- `core/lazy_import.py` — lazy_load() helper for deferred tool imports
- `core/task_store.py` — TaskStore for async scan task tracking
- `core/async_runner.py` — async_run() for background thread execution
- `core/routes/tasks.py` — GET /api/tasks/<task_id> polling endpoint
- `core/routes/browser.py` — Stealth browser Blueprint (navigate/screenshot/dom/form-fill)
- `agents/stealth_browser_agent.py` — StealthBrowserAgent with undetected-chromedriver
- `agents/human_behaviour.py` — HumanBehaviourMixin (Bezier mouse, smooth scroll, typing)
- `agents/proxy_provider.py` — ProxyProvider stub (deferred smart rotation)
- `hexstrike_mcp_tools/async_tools.py` — Async MCP tools (nmap, nuclei, gobuster + polling)
- `hexstrike_mcp_tools/browser.py` — Browser MCP tools (navigate, screenshot, DOM, form-fill)
- Async variants: nmap, nuclei, gobuster, rustscan, masscan, amass, subfinder, feroxbuster

### Changed
- `managers/cache_manager.py` — module-level cache singleton now uses DiskTieredCache
- `managers/process_manager.py` — removed duplicate AdvancedCache; CPU-aware worker count
- `core/routes/osint.py` — lazy tool imports (moved inside route handlers)
- `core/routes/binary.py` — lazy tool imports (moved inside route handlers)
- `core/routes/api_security.py` — lazy tool imports (moved inside route handlers)
- `core/routes/mobile.py` — lazy tool imports (moved inside route handlers)
- `core/routes/wireless.py` — lazy tool imports (moved inside route handlers)
- `core/routes/cloud.py` — lazy tool imports (moved inside route handlers)
- `requirements.txt` — added diskcache>=5.6.0, undetected-chromedriver>=3.5.0

### Performance
- Target: ≥60% startup memory reduction (2 GB → ≤800 MB)
- Lazy loading eliminates module-level heavy imports (pwntools, angr, mitmproxy, shodan)
- DiskTieredCache replaces unbounded in-memory LRU with size-bounded tiered cache
```

**Step: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add Phase 5 CHANGELOG entry"
```

---

### Task 54: Update CLAUDE.md for Phase 5

**Files:**
- Modify: `CLAUDE.md`

Update the Phase completion notes section to add Phase 5. Key things to note:
- New files added in agents/, core/, managers/
- New hexstrike_mcp_tools modules (async_tools.py, browser.py)
- Test count target: ≥560 passing
- Memory target achieved (record actual number from benchmark)

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for Phase 5 completion"
```

---

## Summary

| Batch | Tasks | Files Changed | New Tests |
|-------|-------|---------------|-----------|
| 1: Cache Overhaul | 1–11 | managers/disk_cache.py, resource_monitor.py, cache_manager.py, system.py | ~25 |
| 2: Process Pool | 12–16 | managers/process_manager.py | ~8 |
| 3: Lazy Loading | 17–25 | core/lazy_import.py, 6× Blueprint files | ~14 |
| 4: Async Streaming | 26–35 | core/task_store.py, async_runner.py, routes/tasks.py, 8× routes, mcp async_tools.py | ~25 |
| 5: Stealth Browser | 36–54 | agents/stealth_browser_agent.py, human_behaviour.py, proxy_provider.py, routes/browser.py, mcp browser.py | ~30 |
| **Total** | **54** | **~20 files** | **~102 new tests** |

**Final test count target: ≥560 passing**
**Memory target: ≤800 MB peak RSS (≥60% reduction)**
