# Changelog

All notable changes to HexStrike AI are documented here.

---

## v7.0.0-dev — Phase 5: Performance, Memory Optimization & Stealth Browser

**Branch:** `v7.0-dev`
**Status:** Complete (54 tasks)

### Summary

Added tiered disk caching, lazy tool imports, async scan infrastructure,
and a full stealth browser agent powered by undetected-chromedriver with
human behaviour simulation. Total tests: 607 passing.

### New Files

**Managers:**
- `managers/disk_cache.py` — DiskTieredCache: LRU (memory) + diskcache (disk) two-tier cache
- `managers/resource_monitor.py` — ResourceMonitor singleton: RSS, CPU, disk metrics via psutil

**Core:**
- `core/lazy_import.py` — `lazy_import()` helper for deferred module loading in Blueprints
- `core/task_store.py` — TaskStore: in-memory async task tracking (pending/running/done/failed)
- `core/async_runner.py` — `async_run()`: ThreadPoolExecutor wrapper for non-blocking tool execution
- `core/routes/tasks.py` — `/api/tasks` Blueprint: submit, poll, list, cancel async scans
- `core/routes/browser.py` — `/api/browser` Blueprint: navigate, screenshot, DOM extraction, form fill

**Agents:**
- `agents/stealth_browser_agent.py` — StealthBrowserAgent: UC driver with 3 presets (minimal/standard/paranoid)
- `agents/human_behaviour.py` — HumanBehaviourMixin: type_with_delays, smooth_scroll, bezier_mouse_move, random_pause
- `agents/proxy_provider.py` — ProxyProvider stub: round-robin proxy rotation interface

**MCP Tools:**
- `hexstrike_mcp_tools/async_tools.py` — Async MCP tools: submit_async_scan, poll_task, list_tasks, cancel_task
- `hexstrike_mcp_tools/browser.py` — Browser MCP tools: browser_navigate, browser_screenshot, browser_dom, browser_form_fill

### Changed Files

**Cache & Process:**
- `managers/cache_manager.py` — Singleton migrated to DiskTieredCache backend; `/api/cache/stats` exposes tiered metrics
- `managers/process_manager.py` — Removed duplicate cache; CPU-aware worker pool (os.cpu_count())
- `managers/__init__.py` — Exports DiskTieredCache and ResourceMonitor

**Lazy Import Migration (6 Blueprints):**
- `core/routes/binary.py` — Lazy tool imports via `core.lazy_import`
- `core/routes/api_security.py` — Lazy tool imports
- `core/routes/mobile.py` — Lazy tool imports
- `core/routes/wireless.py` — Lazy tool imports
- `core/routes/cloud.py` — Lazy tool imports
- `core/routes/osint.py` — Lazy tool imports

**Async Route Variants (8 tools):**
- `core/routes/network.py` — Added `/api/nmap/async`, `/api/rustscan/async`, `/api/masscan/async`, `/api/amass/async`, `/api/subfinder/async`
- `core/routes/web.py` — Added `/api/gobuster/async`, `/api/nuclei/async`, `/api/feroxbuster/async`

**Other:**
- `core/server.py` — Registers 14 Blueprints (added tasks_bp, browser_bp)
- `hexstrike_mcp.py` — Imports async_tools and browser MCP modules
- `agents/__init__.py` — Exports StealthBrowserAgent, HumanBehaviourMixin, ProxyProvider
- `requirements.txt` — Added `undetected-chromedriver>=3.5.0`, `diskcache>=5.6.0`

### Performance Notes

- **Lazy loading**: 6 Blueprints defer tool imports until first request; reduces startup RSS
- **DiskTieredCache**: Two-tier caching (in-memory LRU + on-disk diskcache) for expensive scan results
- **Async scans**: 8 tools support non-blocking execution via `/api/<tool>/async` + task polling
- **Memory baseline**: RSS ~55.3 MB at startup (vs 51.2 MB pre-diskcache; delta from diskcache dependency)

### Testing (607 tests)

**New test files (32):**
- Unit: test_disk_tiered_cache, test_resource_monitor, test_cache_manager_v2, test_lazy_import, test_task_store, test_async_runner, test_async_routes, test_tasks_routes, test_stealth_browser_agent, test_human_behaviour_mixin, test_proxy_provider, test_browser_routes, test_process_manager_fix, 5 lazy-import AST tests, test_async_mcp
- Benchmarks: test_memory_baseline
- Integration: test_stealth_browser_e2e (7 tests: navigate, screenshot, DOM, full pipeline, 3 error cases)

---

## [v7.0.0-dev] - Phase 1-3 Gap Closure Complete

### Summary
Decomposed monolithic hexstrike_server.py (17,004 lines) and hexstrike_mcp.py (~5,450 lines) into a clean modular architecture using Flask Blueprints and organized MCP tool modules.

### Changes

**Architecture Decomposition:**
- hexstrike_server.py: 17,004 lines → 38 lines (thin entry point)
- hexstrike_mcp.py: ~5,450 lines → 48 lines (thin MCP launcher)

**New: core/routes/ (12 Flask Blueprints)**
- system.py — health, telemetry, cache, processes, command
- network.py — nmap, rustscan, masscan, amass, subfinder, httpx, waybackurls, gau, dnsenum, enum4linux, smbmap, netexec, wafw00f, naabu, snmp, zmap, advanced tools
- web.py — gobuster, nuclei, nikto, sqlmap, ffuf, feroxbuster, wpscan, dalfox, dirsearch, wfuzz, katana, arjun, paramspider, js-analysis, injection, cms-scan, auth-test, cdn-bypass
- cloud.py — trivy, prowler, kube-hunter, kube-bench, docker-bench, scout-suite, cloudmapper, pacu, falco, checkov, terrascan, kubescape, container-escape, rbac-audit
- binary.py — gdb, radare2, ghidra, binwalk, checksec, strings, objdump, ropgadget, volatility3, foremost, steghide, exiftool, msfvenom, angr, rizin, yara, floss, forensics
- ctf.py — CTF workflow endpoints
- bugbounty.py — bug bounty workflow endpoints
- intelligence.py — AI intelligence, vulnerability intel, CVE analysis
- mobile.py — APK analysis, iOS analysis, Drozer, MITM (Phase 2 complete)
- api_security.py — API discovery, fuzzing, auth testing, monitoring (Phase 2 complete)
- wireless.py — WiFi attack, Bluetooth scan, RF analysis (Phase 2 complete)
- osint.py — passive recon, threat intel, social recon, breach check, Shodan

**New: hexstrike_mcp_tools/ (11 MCP modules)**
- Organized MCP tool registrations for each category
- 84+ MCP tools registered via @mcp.tool() decorators

**New: tools/osint/ (implemented from scratch)**
- passive_recon.py — shodan, whois, theHarvester, dnsdumpster, censys
- social_intel.py — sherlock, holehe, breach_lookup, linkedin_recon
- threat_intel.py — virustotal, OTX, URLScan, shodan CVE lookup

**Testing:**
- Total tests: 505 passing (up from 177 baseline)
- New test files: core/routes tests, hexstrike_mcp_tools tests, OSINT tools tests, integration blueprint tests

---

## v7.0.0-dev — Phase 4: Installation Infrastructure

**Branch:** `v7.0-dev`
**Status:** Complete (22/22 tasks)

### New Features

#### Automated Installer (`scripts/installer/`)
- **One-command installation** of 105 security tools via `bash scripts/installer/install.sh`
- **Three installation modes**: quick (25 tools, ~5 min), standard (64 tools, ~15 min), complete (105 tools, ~30 min)
- **Six category filters**: network, web, cloud, binary, mobile, forensics
- **Dry-run mode** (`--dry-run`) to preview installations without changes
- **Multi-format reports**: terminal (Rich tables), HTML, JSON for CI/CD

#### Pre-flight Validation (`scripts/installer/core/dependency_checker.py`)
- Checks Python 3.8+, pip, git, disk space (5 GB), and internet connectivity
- `--skip-checks` flag for advanced users
- Clear status output with pass/fail indicators

#### Tool Registry (`scripts/installer/registry.yaml`)
- 105 security tools with full metadata (package name, manager, category, tier, description)
- Organized by tier: Essential (25), Core (64), Specialized (16)
- Organized by category: Network (25), Web (30), Cloud (10), Binary (15), Mobile (8), Forensics (8)
- Supports apt, pip, and npm package managers

#### Docker Support
- **Multi-stage Dockerfile** with 5 build stages (base, installer, quick-mode, standard-mode, complete-mode)
- **docker-compose.yml** orchestrating 3 services on ports 8888/8889/8890
- **DOCKER.md** comprehensive deployment guide

#### Test Suite (177 tests)
- **85 unit tests** covering all installer modules (~22s)
- **25 integration tests**: E2E workflow (6), mode hierarchy (9), category filtering (10) (~73s)
- In-process integration tests (no subprocess scanning) for safety and speed

### Bug Fixes

- **Ghidra GUI launch crash**: Removed `_get_version()` call from `check_installed()` in `tool_manager.py`. Ghidra opens its full GUI when invoked with `--version`, crashing test runs. Using `shutil.which()` alone is sufficient for install detection.
- **Virtual environment isolation**: All subprocess tests now use `sys.executable` instead of bare `python3` to ensure the correct interpreter with dependencies is used.
- **Bash wrapper PATH**: Tests use `_ENV_WITH_PYTHON` to prepend the correct Python interpreter's directory to `PATH`.

### Architecture

```
scripts/installer/
├── install.sh              # Bash wrapper entry point
├── main.py                 # Click CLI with Rich progress output
├── registry.yaml           # 105-tool registry
├── DOCKER.md               # Docker deployment guide
├── core/
│   ├── os_detector.py      # Kali/Parrot OS detection and apt management
│   ├── tool_manager.py     # Multi-package-manager tool detection/installation
│   ├── reporter.py         # Terminal/HTML/JSON reporting
│   └── dependency_checker.py  # Pre-flight validation
├── modes/
│   ├── quick.py            # Essential tier (25 tools)
│   ├── standard.py         # Essential + Core tiers (64 tools)
│   └── complete.py         # All tiers (105 tools)
└── categories/
    ├── network.py           # 25 network/recon tools
    ├── web.py               # 30 web security tools
    ├── cloud.py             # 10 cloud security tools
    ├── binary.py            # 15 binary analysis tools
    ├── mobile.py            # 8 mobile security tools
    └── forensics.py         # 8 forensics tools

Dockerfile                  # Multi-stage build
docker-compose.yml          # 3-service orchestration
```

### Implementation Details (22 Tasks)

| Task | Description | Tests |
|------|-------------|-------|
| 1 | Registry YAML structure | 3 |
| 2 | OS Detector | 4 |
| 3 | Tool Manager | 5 |
| 4 | Reporter (terminal/HTML/JSON) | 2 |
| 5 | Jinja2 HTML template | included |
| 6 | Quick mode | 2 |
| 7 | Standard mode | 2 |
| 8 | Complete mode | 2 |
| 9 | Network category | 2 |
| 10 | Web category | 2 |
| 11 | Cloud/Binary/Mobile/Forensics categories | 8 |
| 12 | Main CLI (Click + Rich) | 7 |
| 13 | Bash wrapper | 5 |
| 14 | Dependency Checker | 9 |
| 15 | Pre-flight validation | 4 |
| 16 | Dockerfile (multi-stage) | 11 |
| 17 | docker-compose.yml | 10 |
| 18 | Docker documentation | 7 |
| 19 | E2E integration tests | 6 |
| 20 | Mode hierarchy integration tests | 9 |
| 21 | Category filtering integration tests | 10 |
| 22 | Final documentation | 16 |

---

## v6.0.0 — AI Agents + Modular Architecture (Phase 1-3)

### New Features

- **Modular refactor**: Split monolithic server into `agents/`, `managers/`, `tools/`, `core/`, `utils/`
- **12+ AI agents**: Decision engine, bug bounty manager, CTF solver, CVE intelligence, browser agent
- **150+ security tools** organized by domain (network, web, cloud, binary, mobile, API, wireless, OSINT)
- **Real-time dashboards**: `ModernVisualEngine` with reddish hacker theme
- **LRU cache with TTL** for expensive tool results
- **EnhancedProcessManager** with real-time output streaming
- **BrowserAgent** using headless Chrome + Selenium
- **FastMCP integration** exposing all tools to AI agents

---

## v5.x and Earlier

See git history for changes prior to the Phase 1 modular refactor.
