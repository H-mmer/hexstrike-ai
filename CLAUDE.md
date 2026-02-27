# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HexStrike AI is an AI-powered penetration testing MCP (Model Context Protocol) framework that provides 105+ security tools and 12+ autonomous AI agents for cybersecurity automation. It features a modular architecture with organized components:

**Main Components:**
1. **hexstrike_server.py** - Thin entry point (~38 lines); imports and starts the Flask app from `core/server.py`
2. **hexstrike_mcp.py** - Thin MCP launcher (~48 lines); imports and runs tools from `hexstrike_mcp_tools/`
3. **Modular architecture** - agents/, managers/, tools/, core/, utils/ directories (Phase 1-3)
4. **core/routes/** - 14 Flask Blueprints (Phase 1-3 + Phase 5 additions)
5. **hexstrike_mcp_tools/** - Organized MCP tool modules, one per security category (Phase 1-3 Gap Closure - COMPLETE)
6. **Installation system** - scripts/installer/ with automated tool installation (Phase 4 - COMPLETE, 22/22 tasks)
7. **Performance & stealth** - DiskTieredCache, lazy imports, async scans, StealthBrowserAgent (Phase 5 - COMPLETE, 54 tasks)

## Prerequisites

- **Python 3.8+** (required)
- **Chrome/Chromium browser** (required for BrowserAgent and StealthBrowserAgent)
- **External security tools** (150+ tools - see Installation section)
- **bcrypt 4.0.1** - Pinned version for pwntools compatibility (specified in requirements.txt)
- **undetected-chromedriver** - Anti-detection Chrome driver for StealthBrowserAgent
- **diskcache** - On-disk cache backend for DiskTieredCache

## Development Commands

### Environment Setup

```bash
# Create and activate virtual environment
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate  # Linux/Mac
# hexstrike-env\Scripts\activate   # Windows

# Install dependencies
pip3 install -r requirements.txt
```

### Running the System

```bash
# Start the MCP server (default port 8888)
python3 hexstrike_server.py

# With debug mode
python3 hexstrike_server.py --debug

# Custom port
python3 hexstrike_server.py --port 9000

# Run MCP client (connects to server)
python3 hexstrike_mcp.py --server http://localhost:8888

# Debug MCP client
python3 hexstrike_mcp.py --debug
```

### Testing and Verification

```bash
# Run all unit tests
pytest

# Run specific test file
pytest tests/unit/test_visual_engine.py

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=. --cov-report=html

# Test server health
curl http://localhost:8888/health

# Test AI intelligence endpoint
curl -X POST http://localhost:8888/api/intelligence/analyze-target \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "analysis_type": "comprehensive"}'

# Check cache statistics
curl http://localhost:8888/api/cache/stats

# View running processes
curl http://localhost:8888/api/processes/list
```

## Architecture

### Modular Architecture (Phase 1-3 Refactor)

The codebase has been refactored from monolithic files into a clean modular structure:

**Core Components (`core/`):**
- `server.py` - Flask application factory; registers 14 Blueprints
- `constants.py` - Shared constants and configuration values
- `task_store.py` - TaskStore: in-memory async task tracking with status transitions (Phase 5)
- `async_runner.py` - `async_run()`: ThreadPoolExecutor wrapper for non-blocking tool execution (Phase 5)
- `core/routes/` - 14 Flask Blueprints, one per security domain:
  - `system.py` — health, telemetry, cache, processes, command
  - `network.py` — nmap, rustscan, masscan, amass, subfinder, httpx, waybackurls, gau, dnsenum, enum4linux, smbmap, netexec, wafw00f, naabu, snmp, zmap, advanced recon + async variants
  - `web.py` — gobuster, nuclei, nikto, sqlmap, ffuf, feroxbuster, wpscan, dalfox, dirsearch, wfuzz, katana, arjun, paramspider, js-analysis, injection, cms-scan, auth-test, cdn-bypass + async variants
  - `cloud.py` — trivy, prowler, kube-hunter, kube-bench, docker-bench, scout-suite, cloudmapper, pacu, falco, checkov, terrascan, kubescape, container-escape, rbac-audit (lazy imports)
  - `binary.py` — gdb, radare2, ghidra, binwalk, checksec, strings, objdump, ropgadget, volatility3, foremost, steghide, exiftool, msfvenom, angr, rizin, yara, floss, forensics (lazy imports)
  - `ctf.py` — CTF workflow endpoints
  - `bugbounty.py` — bug bounty workflow endpoints
  - `intelligence.py` — AI intelligence, vulnerability intel, CVE analysis
  - `mobile.py` — APK analysis, iOS analysis, Drozer, MITM (lazy imports)
  - `api_security.py` — API discovery, fuzzing, auth testing, monitoring (lazy imports)
  - `wireless.py` — WiFi attack, Bluetooth scan, RF analysis (lazy imports)
  - `osint.py` — passive recon, threat intel, social recon, breach check, Shodan (lazy imports)
  - `tasks.py` — async task submission, polling, listing, cancellation (Phase 5)
  - `browser.py` — stealth browser navigate, screenshot, DOM extraction, form fill (Phase 5)

**AI Agents (`agents/`):**
- `decision_engine.py` - Intelligent tool selection and parameter optimization
- `bugbounty_manager.py` - Bug bounty workflow automation
- `ctf_manager.py` - CTF challenge solving workflows
- `ctf_tools.py` - CTF-specific tool management
- `cve_intelligence.py` - Vulnerability intelligence and exploit analysis
- `browser_agent.py` - Headless Chrome automation with Selenium
- `stealth_browser_agent.py` - Anti-detection browser with undetected-chromedriver (Phase 5)
- `human_behaviour.py` - HumanBehaviourMixin: typing delays, smooth scroll, Bezier mouse (Phase 5)
- `proxy_provider.py` - Round-robin proxy rotation interface (Phase 5)
- `base.py` - Base classes for agent implementations

**Managers (`managers/`):**
- `process_manager.py` - Smart process control with real-time monitoring (CPU-aware pool, Phase 5)
- `cache_manager.py` - Tiered cache singleton backed by DiskTieredCache (Phase 5 migration)
- `disk_cache.py` - DiskTieredCache: LRU memory + diskcache disk two-tier cache (Phase 5)
- `resource_monitor.py` - ResourceMonitor singleton: RSS, CPU, disk metrics (Phase 5)
- `file_manager.py` - File operations and artifact handling

**Security Tools (`tools/`):**
- `tools/network/` - Network reconnaissance (nmap, rustscan, masscan, amass, etc.)
- `tools/web/` - Web application testing (gobuster, nuclei, sqlmap, nikto, etc.)
- `tools/cloud/` - Cloud security (prowler, trivy, kube-hunter, etc.)
- `tools/binary/` - Binary analysis (ghidra, radare2, gdb, volatility, etc.)
- `tools/mobile/` - Mobile security (APK analysis, iOS tools)
- `tools/api/` - API security (discovery, fuzzing, auth testing)
- `tools/wireless/` - Wireless security (WiFi, Bluetooth, RF tools)
- `tools/osint/` - OSINT and intelligence gathering (passive_recon.py, social_intel.py, threat_intel.py)

**Utilities (`utils/`):**
- `visual_engine.py` - Real-time dashboards and visual output (ModernVisualEngine)
- `logger.py` - Enhanced logging with emojis and colors

**MCP Tools (`hexstrike_mcp_tools/`):**
- `__init__.py` - Package init and MCP app instantiation
- `client.py` - HexStrikeClient wrapper (safe_post helper, shared state)
- `system.py` - System/health/cache/process MCP tools
- `network.py` - Network recon MCP tools
- `web.py` - Web security MCP tools
- `cloud.py` - Cloud security MCP tools
- `binary.py` - Binary analysis MCP tools
- `mobile.py` - Mobile security MCP tools
- `api_security.py` - API security MCP tools
- `wireless.py` - Wireless security MCP tools
- `osint.py` - OSINT MCP tools
- `workflows.py` - CTF, bug bounty, and intelligence workflow MCP tools
- `async_tools.py` - Async scan MCP tools: submit, poll, list, cancel (Phase 5)
- `browser.py` - Stealth browser MCP tools: navigate, screenshot, DOM, form fill (Phase 5)

**MCP Launcher:**
- `hexstrike_mcp.py` - Thin launcher (~48 lines); imports all modules from `hexstrike_mcp_tools/` and starts FastMCP

**Server Entry Point:**
- `hexstrike_server.py` - Thin entry point (~38 lines); imports `core/server.py` app factory and starts Flask

### Key API Endpoints

- `/health` - Health check with tool availability
- `/api/command` - Execute arbitrary commands with caching
- `/api/intelligence/*` - AI intelligence endpoints
- `/api/processes/*` - Process management endpoints
- `/api/cache/stats` - Cache performance metrics (tiered: memory + disk)
- `/api/tasks/*` - Async task submission, polling, listing, cancellation (Phase 5)
- `/api/browser/*` - Stealth browser navigate, screenshot, DOM, form fill (Phase 5)
- `/api/<tool>/async` - Async scan variants for nmap, rustscan, masscan, amass, subfinder, gobuster, nuclei, feroxbuster (Phase 5)

### MCP Tool Registration Pattern

Tools are registered in the appropriate module under `hexstrike_mcp_tools/` (e.g., `hexstrike_mcp_tools/network.py`):

```python
from hexstrike_mcp_tools.client import get_client

@mcp.tool()
def tool_name(param1: str, param2: Optional[int] = None) -> str:
    """Tool description for AI agent"""
    return get_client().safe_post(
        "/api/endpoint",
        {"param1": param1, "param2": param2}
    )
```

All tools follow the pattern: import `get_client` from `hexstrike_mcp_tools.client` → `@mcp.tool()` decorator → docstring → `get_client().safe_post()` call.

Each module is imported in `hexstrike_mcp.py` (the thin launcher) to register all tools at startup.

### Installation Infrastructure (Phase 4 - COMPLETE)

**Status:** 100% Complete (22/22 tasks)
**Location:** `scripts/installer/`
**Goal:** Reduce setup time from 45+ minutes to 3-15 minutes

**Core Modules** (`scripts/installer/core/`):
- `os_detector.py` (134 lines, 4 tests) - OS detection and repository management
  - Detects Kali/Parrot Linux from `/etc/os-release`
  - Verifies supported OS and updates package repositories
  - Manages apt package installation
- `tool_manager.py` (237 lines, 5 tests) - Multi-package-manager tool detection and installation
  - Detects installed tools via `which` and `dpkg`
  - Installs via apt (primary), pip (fallback), npm (fallback)
  - Returns detailed installation results with error handling
- `reporter.py` (152 lines, 2 tests) - Multi-format installation reporting
  - Rich terminal tables with color-coded status
  - HTML reports with responsive design (Jinja2 templates)
  - JSON export for CI/CD integration

**Installation Modes** (`scripts/installer/modes/`):
- `quick.py` (29 lines, 2 tests) - 20 essential tools for CTF/quick pentests
- `standard.py` (30 lines, 2 tests) - 36 tools for bug bounty/standard pentests
- `complete.py` (24 lines, 2 tests) - 54+ tools for comprehensive pentesting

**Category Filters** (`scripts/installer/categories/`):
- `network.py` (30 lines, 2 tests) - 25 network/reconnaissance tools
- `web.py` (30 lines, 2 tests) - 30 web application security tools
- `cloud.py` (30 lines, 2 tests) - 10 cloud security tools
- `binary.py` (30 lines, 2 tests) - 15 binary analysis/reverse engineering tools
- `mobile.py` (28 lines, 2 tests) - 8 mobile security tools (Android/iOS)
- `forensics.py` (30 lines, 2 tests) - 8 forensics and malware analysis tools

**Tool Registry** (`scripts/installer/registry.yaml`):
- 105 security tools with complete metadata
- Fields: package name, manager (apt/pip/npm), category, tier, description
- Organized by tier: Essential (25), Core (64), Specialized (16)
- Organized by category: Network (25), Web (30), Cloud (10), Binary (15), Mobile (8), Forensics (8)

**Docker Infrastructure** (`scripts/installer/docker/`):
- `Dockerfile` - 5-stage multi-stage build (base, installer, quick-mode, standard-mode, complete-mode)
- `docker-compose.yml` - Orchestration with HexStrike server + PostgreSQL
- `DOCKER.md` - Full Docker usage documentation

**Testing** (`tests/`):
- **Unit tests** (`tests/unit/test_installer/`): 85 tests - 100% passing
  - `test_os_detector.py`, `test_tool_manager.py`, `test_reporter.py`, `test_modes.py`, `test_categories.py`, `test_registry.py`, `test_main_cli.py`, `test_wrapper.py`, `test_dependency_checker.py`, `test_preflight.py`, `test_dockerfile.py`, `test_docker_compose.py`, `test_docker_files.py`
- **Integration tests** (`tests/integration/`): 25 tests - in-process approach (no subprocess scanning)
  - `test_full_workflow.py` (6 tests) - subprocess CLI verification
  - `test_modes_integration.py` (9 tests) - mode hierarchy in-process
  - `test_categories_integration.py` (10 tests) - category filtering in-process
- **Total: 110 tests passing**
- Tests use flexible assertions (`>=` for counts) to handle registry growth

**Installer Testing Commands:**
```bash
# Run ALL tests (unit + integration)
pytest -v

# Run only unit tests (fast, ~22s)
pytest tests/unit/ -v

# Run only integration tests (~73s, safe - no subprocess scanning)
pytest tests/integration/ -v

# Run specific test suites
pytest tests/unit/test_installer/test_modes.py -v
pytest tests/unit/test_installer/test_categories.py -v
pytest tests/unit/test_installer/test_tool_manager.py -v

# Check installer test coverage
pytest tests/unit/test_installer/ --cov=scripts/installer --cov-report=html

# Run smoke test (verify imports and counts)
python3 -c "
from scripts.installer.modes import quick, standard, complete
from scripts.installer.categories import network, web, cloud, binary, mobile, forensics
print(f'Quick: {len(quick.get_quick_tools())} tools')
print(f'Standard: {len(standard.get_standard_tools())} tools')
print(f'Complete: {len(complete.get_complete_tools())} tools')
print(f'Network: {len(network.get_network_tools())} tools')
print(f'Web: {len(web.get_web_tools())} tools')
"
```

**CRITICAL - Subprocess Safety:**
NEVER run the full installer CLI (main.py) in integration tests with `subprocess` + `--mode complete`.
`scan_tools()` calls `check_installed()` for each of 105 tools sequentially. While each call is now safe
(version detection removed), avoid spawning the full CLI in subprocess from integration tests.
Use in-process imports for mode/category logic tests (see `tests/integration/test_modes_integration.py`).
Reserve subprocess only for CLI interface verification (`tests/integration/test_full_workflow.py`).

**Installer Usage:**
```bash
# Quick installation (20 essential tools, ~5 minutes)
python3 -m scripts.installer.main --mode quick

# Standard installation (36 tools, ~15 minutes)
python3 -m scripts.installer.main --mode standard

# Complete installation (54+ tools, ~30 minutes)
python3 -m scripts.installer.main --mode complete

# Install specific categories only
python3 -m scripts.installer.main --categories network,web
python3 -m scripts.installer.main --mode standard --categories cloud,binary

# Dry run (preview what would be installed)
python3 -m scripts.installer.main --mode quick --dry-run

# Generate reports
python3 -m scripts.installer.main --mode standard --output html  # HTML report
python3 -m scripts.installer.main --mode quick --output json    # JSON export
```

**Implementation Pattern:**
All modes and categories follow a simple function-based pattern:
```python
def get_quick_tools() -> List[str]:
    """Get list of essential tier tools"""
    registry_path = Path('scripts/installer/registry.yaml')
    with open(registry_path) as f:
        data = yaml.safe_load(f)
    tools = data.get('tools', {})
    essential_tools = [
        name for name, info in tools.items()
        if info.get('tier') == 'essential'
    ]
    return sorted(essential_tools)
```

This pattern is used for all 3 modes (filter by tier) and all 6 categories (filter by category).

## Code Organization Principles

### Color Theming

The codebase uses a consistent "reddish hacker theme" color palette defined in both files:
- **Server**: `ModernVisualEngine.COLORS` (hexstrike_server.py)
- **Client**: `HexStrikeColors` (hexstrike_mcp.py)

When adding visual output, use these predefined color constants. Never hardcode ANSI color codes.

### Logging Standards

Both files use enhanced logging with emojis and colors:
- Use `logger.info()`, `logger.warning()`, `logger.error()`, `logger.debug()`
- Emojis are used for visual categorization (✅ success, ❌ error, 🔍 info, etc.)
- Colors are applied via `ColoredFormatter` class

### Error Handling Pattern

The codebase uses comprehensive try/except blocks with:
- Detailed error logging with stack traces
- User-friendly error messages
- Graceful degradation (tools work even if some dependencies fail)
- Recovery mechanisms in AI agents

### API Response Format

All API endpoints return JSON with this structure:
```python
{
    "success": bool,
    "data": {...},      # On success
    "error": str,       # On failure
    "timestamp": str,
    "execution_time": float
}
```

## External Dependencies

### Python Packages (requirements.txt)

**Core Framework**:
- flask - Web framework for API server
- fastmcp - MCP framework integration
- requests - HTTP client library
- psutil - System and process utilities

**Web Automation**:
- selenium - Browser automation
- webdriver-manager - ChromeDriver management
- undetected-chromedriver - Anti-detection Chrome driver (StealthBrowserAgent, Phase 5)
- beautifulsoup4 - HTML parsing
- aiohttp - Async HTTP client

**Caching**:
- diskcache - On-disk cache backend for DiskTieredCache (Phase 5)

**Security Tools**:
- pwntools - Binary exploitation framework
- angr - Binary analysis with symbolic execution
- mitmproxy - HTTP proxy for traffic interception

### External Security Tools

**Tool Registry:** 105 security tools in `scripts/installer/registry.yaml`

**By Tier (Installation Modes):**
- **Essential** (25 tools) - Quick mode installations, CTF competitions, rapid deployment
- **Core** (64 tools) - Standard mode installations, bug bounty hunting, balanced pentesting
- **Specialized** (16 tools) - Complete mode installations, comprehensive security labs

**By Category (Domain-Specific):**
- **Network/Recon** (25 tools): nmap, rustscan, masscan, amass, subfinder, dnsx, nuclei, httprobe, waybackurls, shodan, censys, etc.
- **Web Security** (30 tools): gobuster, nuclei, sqlmap, nikto, burpsuite, zaproxy, feroxbuster, ffuf, wpscan, wfuzz, dalfox, etc.
- **Cloud Security** (10 tools): trivy, scout-suite, prowler, cloudmapper, pacu, kube-hunter, kubescape, kube-bench, etc.
- **Binary Analysis** (15 tools): gdb, ghidra, radare2, rizin, pwndbg, checksec, binwalk, foremost, objdump, ltrace, strace, etc.
- **Mobile Security** (8 tools): apktool, jadx, mobsf, frida, androguard, dex2jar, objection, etc.
- **Forensics/Malware** (8 tools): yara, volatility3, autopsy, sleuthkit, clamav, bulk-extractor, scalpel, testdisk

**Authentication Tools:** Included in Web category (hydra, john, hashcat in registry)

Tools are invoked via subprocess - the system gracefully handles missing tools. Use `scripts/installer/` for automated installation.

## Configuration

### Environment Variables

- `HEXSTRIKE_PORT` - Server port (default: 8888)
- `HEXSTRIKE_HOST` - Server host (default: 127.0.0.1)

### AI Client Integration

Claude Desktop/Cursor config (`~/.config/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/path/to/hexstrike-ai/hexstrike_mcp.py", "--server", "http://localhost:8888"],
      "timeout": 300
    }
  }
}
```

## Important Development Notes

### Files to Ignore (.gitignore)

Add these to your .gitignore:
```
hexstrike-env/          # Virtual environment
__pycache__/            # Python bytecode cache
*.pyc                   # Compiled Python files
*.pyo                   # Optimized Python files
hexstrike.log           # Runtime logs
.pytest_cache/          # Pytest cache
*.log                   # All log files
.coverage               # Coverage reports
htmlcov/                # Coverage HTML output
```

### Security Tool Execution

All security tools are executed via subprocess with:
- Timeout mechanisms (default varies by tool)
- Output capture (stdout/stderr)
- Return code checking
- Process management for long-running tools

When adding new tools, follow the pattern in existing tool functions.

### Caching System

The server implements a two-tier cache via `DiskTieredCache` (Phase 5):
- **Tier 1**: In-memory LRU cache (fast, bounded by `maxsize`)
- **Tier 2**: On-disk `diskcache` backend (persistent across restarts)
- Cache key: `hashlib.md5(command.encode()).hexdigest()`
- Default TTL: varies by tool type
- Manual cache invalidation available
- Tiered cache stats available at `/api/cache/stats` (memory hits, disk hits, misses)

Expensive operations (nmap, nuclei, etc.) are automatically cached.

### Process Management

Long-running tools use `EnhancedProcessManager`:
- Real-time output streaming
- Process termination on timeout
- Resource monitoring
- Graceful cleanup on server shutdown

### Browser Agent Specifics

`BrowserAgent` class uses Selenium with headless Chrome:
- Requires chromium-browser or google-chrome installed
- Uses webdriver-manager for driver management
- Supports proxy integration (mitmproxy)
- Captures screenshots, analyzes DOM, monitors network traffic

`StealthBrowserAgent` (Phase 5) uses undetected-chromedriver for anti-detection:
- Three presets: `minimal` (UC only), `standard` (UC + delays + scroll), `paranoid` (UC + full human simulation)
- Inherits `HumanBehaviourMixin`: type_with_delays, smooth_scroll, bezier_mouse_move, random_pause
- `ProxyProvider` stub for round-robin proxy rotation
- Routes: `/api/browser/navigate`, `/api/browser/screenshot`, `/api/browser/dom`, `/api/browser/form-fill`

## Common Workflows

### Adding a New Security Tool

1. **Add to tool registry** (`scripts/installer/registry.yaml`):
   ```yaml
   tool-name:
     package: package-name
     manager: apt  # or pip, npm
     category: network  # or web, cloud, binary, mobile, forensics
     tier: core  # or essential, specialized
     description: "Brief description of the tool"
   ```

2. **Add tool implementation** to appropriate `tools/` subdirectory:
   - `tools/network/` for network/reconnaissance tools
   - `tools/web/` for web application testing
   - `tools/cloud/` for cloud security
   - `tools/binary/` for binary analysis/forensics
   - `tools/mobile/` for mobile security
   - `tools/api/` for API testing
   - `tools/wireless/` for wireless security

3. **Import in `tools/<category>/__init__.py`**

4. **Add MCP tool decorator** in the matching `hexstrike_mcp_tools/<category>.py` module

5. **Add unit tests** in `tests/unit/test_<category>_tools.py`

6. **Verify installation** works:
   ```bash
   # Test tool detection
   python -c "
   from scripts.installer.core.tool_manager import ToolManager
   from scripts.installer.core.os_detector import OSDetector
   tm = ToolManager(OSDetector())
   status = tm.check_installed('tool-name')
   print(f'Installed: {status.installed}, Path: {status.path}')
   "
   ```

7. **Document in README.md** tool list

8. **Handle missing tool gracefully** (check with `shutil.which()`)

### Adding a New AI Agent

1. Create new file in `agents/` directory
2. Create class inheriting from `agents/base.py` (see existing agents)
3. Implement required methods (analyze, execute, report)
4. Import in `agents/__init__.py`
5. Integrate with `decision_engine.py` if needed
6. Add colored output using `ModernVisualEngine.COLORS` from `utils/visual_engine.py`
7. Add unit tests in `tests/unit/`

### Debugging Issues

1. Enable debug mode: `python3 hexstrike_server.py --debug`
2. Check server logs: `hexstrike.log`
3. Test endpoints individually with curl
4. Use `/api/processes/list` to monitor running tools
5. Check `/api/cache/stats` for cache hit/miss ratios

## CLAUDE.md Maintenance

This file should be updated after major changes:
- After significant refactors, verify architecture section matches actual code structure
- Use `#` key during Claude Code sessions to auto-incorporate learnings
- Use `/claude-md-management:claude-md-improver` skill to audit CLAUDE.md quality periodically
- The project evolved from monolithic (pre-Phase 1) to modular (Phase 1-3) - keep documentation in sync with such changes
- **Phase 1-3 Gap Closure is complete**: hexstrike_server.py decomposed into 12 Flask Blueprints in `core/routes/`, MCP tools reorganized into `hexstrike_mcp_tools/`. Both entry points are now thin launchers (~50 lines each). Total tests: 505 passing.
- **Phase 4 (Installation Infrastructure) is 100% complete (22/22 tasks)**
  - Completed: Core modules, modes, categories, CLI (Task 12), bash wrapper (Task 13), dependency checker (Task 14), pre-flight (Task 15), Dockerfile (Task 16), docker-compose (Task 17), DOCKER.md (Task 18), E2E integration tests (Task 19), mode hierarchy tests (Task 20), category tests (Task 21), final documentation (Task 22)
  - See docs/installation.md for the user-facing installation guide
  - See CHANGELOG.md for Phase 4 release notes
  - Update tool counts as registry expands beyond 105 tools
- **Phase 5 (Performance, Memory & Stealth Browser) is 100% complete (54 tasks)**
  - DiskTieredCache (memory LRU + diskcache), ResourceMonitor, lazy Blueprint imports
  - TaskStore + async_run() + 8 async route variants + MCP async_tools
  - StealthBrowserAgent (UC driver, 3 presets) + HumanBehaviourMixin + ProxyProvider stub
  - Browser Blueprint (4 routes) + browser MCP tools (4 tools)
  - 14 Flask Blueprints total (12 original + tasks + browser)
  - Total tests: 607 passing
  - See CHANGELOG.md for Phase 5 release notes

## IMPORTANT INSTRUCTIONS
- Start all new Phases, Features, and/or Major changes by first understanding the requirements through brainstorming (use skill /brainstorming), then creating a detailed implementation plan (use skill /writing-plans).
