# Phase 5: Performance, Memory & Stealth — Design Document

**Date:** 2026-02-25
**Branch:** v7.0-dev
**Status:** Approved

---

## Overview

Phase 5 delivers two major capabilities on top of the Phase 1-4 foundation:

1. **Memory Optimization** — reduce server baseline from ~2GB to ≤800MB (60% reduction) through lazy tool loading, task-based async scanning, diskcache-backed caching, and process pool cleanup.
2. **Stealth Browser Agent** — replace the detectable `BrowserAgent` with a `StealthBrowserAgent` backed by `undetected-chromedriver`, human-like behaviour, and configurable stealth presets for bug bounty/recon/CTF.

**Approach:** Impact-first (Batch 1 proves memory target before later batches build on it).

---

## Hard Targets

| Metric | Before | Target |
|--------|--------|--------|
| Server RSS at startup | ~2GB | ≤800MB |
| Peak RSS during heavy scan | ~4GB | ≤2GB |
| Cloudflare bot challenge pass rate | ~0% | >90% |
| DataDome / PerimeterX detection | Always detected | <10% detection |
| Existing tests | 505 passing | 505 + new benchmarks passing |

---

## Batch 1: Lazy Tool Loading

### Problem

All 12 Flask Blueprints import their tool modules at the top of their files. Python executes these imports at server startup, loading every heavy library — angr (~500MB), androguard (~200MB), volatility3 (~150MB), pwntools (~100MB) — whether or not a single scan runs during the session.

MCP tool registrations stay eager — FastMCP must know all tools at startup, but MCP tools are thin `safe_post` stubs with negligible memory footprint.

### Solution

Move tool imports inside route handler functions. Python's module cache (`sys.modules`) ensures the import cost is paid only once per process lifetime — first call loads the module, all subsequent calls get the cached module instantly.

**New helper: `core/lazy_import.py`**

```python
import importlib
from typing import Any

def lazy_import(module_path: str, attr: str) -> Any:
    """Import a module attribute on demand. Thread-safe via Python's import lock."""
    mod = importlib.import_module(module_path)
    return getattr(mod, attr)
```

**Pattern applied to all 12 Blueprints:**

```python
# Before (module top-level — loads at startup):
from tools.binary.angr_tools import angr_analyze

@binary_bp.route('/api/tools/binary/angr', methods=['POST'])
def binary_angr():
    ...

# After (inside handler — loads on first call):
@binary_bp.route('/api/tools/binary/angr', methods=['POST'])
def binary_angr():
    from tools.binary.angr_tools import angr_analyze
    ...
```

### Memory Benchmark Suite

**`tests/benchmarks/test_memory_baseline.py`** using `tracemalloc` + `psutil`:

- `test_server_startup_rss` — asserts RSS after `create_app()` < 800MB
- `test_blueprint_import_lazy` — asserts importing a Blueprint does NOT load its tool modules
- `test_tool_loads_on_first_request` — asserts tool module absent from `sys.modules` before first route hit, present after
- `test_peak_rss_heavy_scan` — mocked nmap scan, asserts peak RSS delta < 50MB (no buffering)

These become regression guards in CI.

### Expected Savings

~800MB–1GB at startup from deferring angr, androguard, volatility3, pwntools, and heavy web tool libraries.

---

## Batch 2: Async Scan Streaming (Task ID + Polling)

### Problem

Heavy scans (nmap, nuclei, masscan, gobuster, ffuf, feroxbuster, sqlmap, theHarvester) run for minutes and buffer entire stdout output into memory before responding. A single nmap XML result can be 5–50MB. MCP clients block with no feedback until the scan finishes.

### Solution: Task ID + Polling

Scan endpoints return immediately with a `task_id`. The scan runs in a background thread. The client polls a status endpoint until complete.

**New module: `core/task_store.py`**

```python
class TaskStore:
    """Thread-safe in-memory store for async scan tasks."""

    def create(self, cmd: list, timeout: int) -> str:
        """Start scan in background thread, return task_id."""

    def get_status(self, task_id: str) -> dict:
        """Return {status: pending|running|done|error, output: [...], progress: int}."""

    def get_result(self, task_id: str) -> dict:
        """Return final result. Raises if not done."""

    def cleanup_expired(self, max_age_seconds: int = 3600):
        """Remove completed tasks older than max_age. Called by background thread."""
```

**Internal streaming subprocess wrapper: `core/streaming.py`**

```python
def stream_subprocess(cmd: list, timeout: int, on_line: callable):
    """Run subprocess, call on_line(line) for each stdout line. Never buffers."""
    proc = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE, text=True)
    for line in proc.stdout:
        on_line(line.rstrip())
    proc.wait(timeout=timeout)
    return proc.returncode
```

**Route pattern (applied to 8 heavy tools):**

```python
# Start scan — returns immediately
POST /api/tools/nmap/async
→ {"task_id": "nmap_1234567890", "status": "running", "poll_url": "/api/tasks/nmap_1234567890"}

# Poll status
GET /api/tasks/{task_id}
→ {"status": "running", "progress": 42, "output": ["line1", "line2", ...], "elapsed": 15.3}

# Final result (status == "done")
→ {"status": "done", "output": [...], "result": {...}, "elapsed": 47.2}
```

Existing synchronous endpoints (`POST /api/tools/nmap`) remain unchanged — backward compatible.

**New routes: `core/routes/tasks.py`** (`tasks_bp`)
- `GET /api/tasks/{task_id}` — poll status
- `DELETE /api/tasks/{task_id}` — cancel running scan
- `GET /api/tasks` — list active tasks

**MCP tools: `hexstrike_mcp_tools/async_tools.py`**

Helper that wraps the poll loop:
```python
@mcp.tool()
def nmap_scan_async(target: str, scan_type: str = "-sV") -> dict:
    """Run nmap scan asynchronously. Returns when complete."""
    task = get_client().safe_post("api/tools/nmap/async", {...})
    return get_client().poll_task(task["task_id"])  # polls until done
```

**Tools with async variants (8):** nmap, nuclei, masscan, gobuster, ffuf, feroxbuster, sqlmap, theHarvester.

---

## Batch 3: Cache Overhaul (diskcache)

### Problem

`HexStrikeCache` is LRU-by-count (max 1000 items) with no memory-size awareness. A single cached nmap XML result can be 5–50MB. 1000 such entries = unbounded RAM consumption.

### Solution: `diskcache`-backed `HybridCache`

Replace `HexStrikeCache` with `diskcache.Cache` (or `diskcache.FanoutCache` for concurrency).

**Configuration:**

```python
import diskcache

cache = diskcache.FanoutCache(
    directory='/tmp/hexstrike-cache',
    size_limit=int(256e6),          # 256MB in-memory
    disk_min_file_size=0,           # all items eligible for disk
    cull_limit=10,                  # evict 10% when full
    statistics=True,
)

DISK_SIZE_LIMIT = int(512e6)        # 512MB disk cap
```

**Expensive scan marking:**

```python
# Routes mark long-running scan results as expensive (no TTL eviction)
cache.set(key, result, expire=None, tag='expensive')

# Normal results get standard TTL
cache.set(key, result, expire=3600)
```

**psutil pressure eviction:**

`core/resource_monitor.py` — singleton background thread:

```python
class ResourceMonitor:
    """Watches system RAM and triggers cache eviction under pressure."""

    def _monitor(self):
        while True:
            mem = psutil.virtual_memory()
            if mem.percent > 85:
                cache.cull()               # aggressive eviction
            elif mem.percent > 70:
                cache.expire()             # expire TTL entries only
            time.sleep(30)
```

**Backward-compatible interface** — same `get(command, params)` / `set(command, params, result)` API. `expensive=True` kwarg added to `set()`.

**`/api/cache/stats` updated** to expose diskcache statistics:

```json
{
  "hits": 142, "misses": 38, "hit_rate": "78.9%",
  "memory_size_mb": 187.3, "disk_size_mb": 412.1,
  "disk_entries": 2341, "evictions": 12
}
```

### New dependency

```
diskcache>=5.6.0
```

---

## Batch 4: Process Pool Cleanup (Minimal Fix)

### Problem

`EnhancedProcessManager` creates its own internal `AdvancedCache` instance, duplicating the module-level `cache` singleton. Worker counts are hardcoded (min=4, max=32) regardless of host hardware.

### Changes (surgical, no rewrite)

1. **Remove `AdvancedCache`** from `EnhancedProcessManager.__init__` — use `from managers.cache_manager import cache` instead.
2. **CPU-aware worker count** at init:
   ```python
   cpu = os.cpu_count() or 4
   self.min_workers = max(2, cpu // 2)
   self.max_workers = min(cpu * 2, 32)
   ```
3. **`ResourceMonitor` integration** — `EnhancedProcessManager` subscribes to the same singleton from `core/resource_monitor.py` started in Batch 3. When RAM > 85%, throttle active workers to `min_workers`.

No other changes to `process_manager.py`.

---

## Batch 5: Stealth Browser Agent

### Problem

`BrowserAgent` uses `--user-agent=HexStrike-BrowserAgent/1.0`, exposes the `navigator.webdriver` flag, and makes straight-line mouse movements. Any modern WAF or Cloudflare challenge detects it immediately.

### Solution: `StealthBrowserAgent` with `undetected-chromedriver`

**New file: `agents/stealth_browser_agent.py`**

```python
import undetected_chromedriver as uc
from agents.browser_agent import BrowserAgent

class StealthBrowserAgent(BrowserAgent):
    """Drop-in replacement for BrowserAgent with anti-detection."""

    PRESETS = {
        'minimal':  {'ua_rotation': True, 'canvas_spoof': False, 'human_behaviour': False},
        'standard': {'ua_rotation': True, 'canvas_spoof': True,  'human_behaviour': True},
        'paranoid': {'ua_rotation': True, 'canvas_spoof': True,  'human_behaviour': True,
                     'spoof_locale': True, 'random_viewport': True},
    }

    def __init__(self, profile: str = 'standard', proxy_provider=None):
        super().__init__()
        self.profile = self.PRESETS[profile]
        self.proxy_provider = proxy_provider  # interface for future smart rotation
```

**`undetected-chromedriver` setup:**

```python
def setup_browser(self, headless: bool = True, proxy_port: int = None):
    options = uc.ChromeOptions()
    # Standard security testing options inherited from BrowserAgent
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--ignore-certificate-errors')

    if proxy_port:
        options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')

    self.driver = uc.Chrome(options=options, headless=headless)
    self._apply_stealth_patches()
```

**Anti-detection patches (`_apply_stealth_patches`):**

1. **UA rotation** — pool of 20 real Chrome UA strings (Win/Mac/Linux, Chrome 120-131), randomly selected per session, set via CDP `Network.setUserAgentOverride`
2. **Canvas spoofing** — CDP `Page.addScriptToEvaluateOnNewDocument` injects per-session noise into `canvas.toDataURL()` and `canvas.getContext('2d').getImageData()`
3. **WebGL renderer spoofing** — randomise `UNMASKED_RENDERER_WEBGL` and `UNMASKED_VENDOR_WEBGL` from a pool of real GPU strings
4. **Timezone/locale** (paranoid only) — CDP `Emulation.setTimezoneOverride` + `Emulation.setLocaleOverride`
5. **Random viewport** (paranoid only) — one of 8 common resolutions (1366×768, 1920×1080, 2560×1440, etc.)

**`HumanBehaviourMixin`:**

```python
class HumanBehaviourMixin:
    def human_click(self, element):
        """Move to element via Bezier curve, micro-pause, click."""

    def human_type(self, element, text):
        """Type with per-character delays (30-120ms), occasional typo+backspace."""

    def human_scroll(self, pixels):
        """Smooth incremental scroll with micro-pauses."""

    def think_time(self, min_s=0.8, max_s=3.0):
        """Random pause simulating human reading time."""
```

**Proxy provider interface (deferred implementation):**

```python
class ProxyProvider(Protocol):
    def get_proxy(self) -> str: ...    # returns "host:port"
    def report_failure(self, proxy: str): ...
```

`StealthBrowserAgent` calls `self.proxy_provider.get_proxy()` if set. Smart rotation implemented later by passing a concrete `ProxyProvider` — zero changes to `StealthBrowserAgent`.

**New routes: `core/routes/browser.py`** (`browser_bp`)

| Route | Description |
|-------|-------------|
| `POST /api/browser/stealth-navigate` | Navigate + inspect with stealth profile |
| `POST /api/browser/screenshot` | Stealth screenshot |
| `POST /api/browser/form-submit` | Human-like form interaction |
| `POST /api/browser/js-eval` | Evaluate JS in stealth context |

**New MCP tools: `hexstrike_mcp_tools/browser.py`**

```python
@mcp.tool()
def stealth_browse(url: str, profile: str = "standard") -> dict:
    """Navigate to URL with anti-detection. profile: minimal|standard|paranoid"""

@mcp.tool()
def stealth_screenshot(url: str, profile: str = "standard") -> dict:
    """Take screenshot with anti-detection browser."""

@mcp.tool()
def browser_form_submit(url: str, fields: dict, profile: str = "standard") -> dict:
    """Submit form with human-like typing and mouse movements."""
```

### New dependency

```
undetected-chromedriver>=3.5.0
```

---

## New Files Summary

| File | Purpose |
|------|---------|
| `core/lazy_import.py` | Thread-safe lazy import helper |
| `core/resource_monitor.py` | psutil singleton — shared by cache + process pool |
| `core/streaming.py` | Non-buffering subprocess line streamer |
| `core/task_store.py` | Async scan task lifecycle management |
| `core/routes/tasks.py` | `/api/tasks/*` routes (poll, cancel, list) |
| `agents/stealth_browser_agent.py` | StealthBrowserAgent + HumanBehaviourMixin |
| `core/routes/browser.py` | Browser Blueprint routes |
| `hexstrike_mcp_tools/browser.py` | Browser MCP tools |
| `hexstrike_mcp_tools/async_tools.py` | Async scan MCP tools with poll loop |
| `tests/benchmarks/` | Memory baseline + regression benchmark tests |

## Modified Files Summary

| File | Change |
|------|--------|
| All 12 `core/routes/*.py` | Tool imports moved inside handlers |
| `managers/cache_manager.py` | Replace HexStrikeCache with diskcache |
| `managers/process_manager.py` | Remove AdvancedCache dup, CPU-aware workers |
| `core/server.py` | Register `tasks_bp` + `browser_bp` |
| `hexstrike_mcp.py` | Import `browser` + `async_tools` modules |
| `requirements.txt` | Add `diskcache>=5.6.0`, `undetected-chromedriver>=3.5.0` |

---

## Implementation Order (Impact-First)

```
Batch 1: Lazy Tool Loading          ← proves 60% memory target
Batch 2: Async Scan Streaming       ← task store + 8 heavy tools
Batch 3: Cache Overhaul (diskcache) ← replaces HexStrikeCache
Batch 4: Process Pool Cleanup       ← surgical 3-line fix
Batch 5: Stealth Browser Agent      ← undetected-chromedriver + human behaviour
```

---

## Success Criteria

```bash
# 1. Memory target
python3 -c "
import psutil, os
os.system('python3 hexstrike_server.py &')
import time; time.sleep(3)
procs = [p for p in psutil.process_iter() if 'hexstrike' in ' '.join(p.cmdline())]
print(f'RSS: {procs[0].memory_info().rss / 1e6:.0f}MB')
# Expected: < 800MB
"

# 2. All tests pass
pytest -v
# Expected: 505+ tests passing

# 3. Benchmark suite
pytest tests/benchmarks/ -v
# Expected: all memory assertions pass

# 4. Stealth browser
python3 -c "
from agents.stealth_browser_agent import StealthBrowserAgent
agent = StealthBrowserAgent(profile='standard')
agent.setup_browser(headless=True)
result = agent.navigate_and_inspect('https://www.google.com')
print(result['success'])  # Expected: True
"
```
