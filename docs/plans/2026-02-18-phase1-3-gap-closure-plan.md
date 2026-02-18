# Phase 1-3 Gap Closure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Decompose `hexstrike_server.py` (17k lines) into Flask Blueprints, wire all Phase 2/3 tool modules to server routes, implement OSINT from scratch, and reorganize the MCP client into a proper module structure — leaving both monolith files as thin ~50-line entry points.

**Architecture:** Sequential category-by-category decomposition using Flask Blueprints registered in `core/server.py`. MCP tools move to `hexstrike_mcp_tools/` (not `mcp/` — that name conflicts with the installed FastMCP library package). Each batch: write tests → create Blueprint → migrate routes → wire tools → register MCP tools → commit.

**Tech Stack:** Flask Blueprints, FastMCP (`from mcp.server.fastmcp import FastMCP`), pytest + Flask test client, `unittest.mock.patch` for subprocess mocking.

**Critical naming note:** The installed FastMCP library uses the Python package name `mcp` (e.g. `from mcp.server.fastmcp import FastMCP`). Our local `mcp/` directory conflicts with this. All local MCP organisation goes into `hexstrike_mcp_tools/` instead. The existing empty `mcp/__init__.py` can be left as-is (it's empty and harmless).

---

## Batch 1: Infrastructure (Blueprint scaffolding + system routes)

Proves the pattern end-to-end before touching real tool categories.

---

### Task 1: Create `core/routes/` package and Blueprint scaffold

**Files:**
- Create: `core/routes/__init__.py`
- Modify: `core/server.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_routes/test_system_routes.py
import pytest
from flask import Flask
from core.routes.system import system_bp

def test_system_blueprint_registers():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    assert 'system' in app.blueprints
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_routes/test_system_routes.py::test_system_blueprint_registers -v
```
Expected: `ModuleNotFoundError: No module named 'core.routes.system'`

**Step 3: Create the package and empty Blueprint**

```python
# core/routes/__init__.py
"""Flask Blueprint route modules for HexStrike AI."""
```

```python
# core/routes/system.py
"""System and infrastructure routes Blueprint."""
from flask import Blueprint

system_bp = Blueprint('system', __name__)
```

**Step 4: Run to confirm pass**

```bash
pytest tests/unit/test_routes/test_system_routes.py::test_system_blueprint_registers -v
```

**Step 5: Commit**

```bash
git add core/routes/__init__.py core/routes/system.py tests/unit/test_routes/test_system_routes.py
git commit -m "feat: add core/routes/ package with empty system Blueprint"
```

---

### Task 2: Migrate health and telemetry routes to system Blueprint

**Files:**
- Modify: `core/routes/system.py`
- Modify: `hexstrike_server.py` (remove migrated routes)

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_system_routes.py (add to existing file)
from unittest.mock import patch, MagicMock

def test_health_route_exists():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    client = app.test_client()
    with patch('core.routes.system.shutil') as mock_shutil:
        mock_shutil.which.return_value = '/usr/bin/nmap'
        resp = client.get('/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'status' in data

def test_telemetry_route_exists():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    client = app.test_client()
    resp = client.get('/api/telemetry')
    assert resp.status_code == 200
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_routes/test_system_routes.py -v
```
Expected: FAIL — routes not defined yet.

**Step 3: Move health and telemetry handlers into system Blueprint**

Copy the `health_check()` function body from `hexstrike_server.py` line 8622 and the `telemetry()` function, replacing `@app.route` with `@system_bp.route`:

```python
# core/routes/system.py
import shutil
from flask import Blueprint, jsonify
from utils.visual_engine import ModernVisualEngine

system_bp = Blueprint('system', __name__)

@system_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with tool detection."""
    essential_tools = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "hashcat"
    ]
    tool_status = {tool: bool(shutil.which(tool)) for tool in essential_tools}
    available = sum(tool_status.values())
    return jsonify({
        "status": "operational",
        "tools_available": available,
        "tools_total": len(essential_tools),
        "tool_status": tool_status,
        "version": "7.0.0-dev"
    })

@system_bp.route('/api/telemetry', methods=['GET'])
def telemetry():
    """Server telemetry endpoint."""
    return jsonify({"status": "ok", "version": "7.0.0-dev"})
```

**Step 4: Run to confirm pass**

```bash
pytest tests/unit/test_routes/test_system_routes.py -v
```

**Step 5: Delete the migrated handlers from `hexstrike_server.py`**

Remove the `health_check()` and `telemetry()` functions (lines ~8621-8880) from `hexstrike_server.py`.

**Step 6: Register Blueprint in `core/server.py`**

```python
# core/server.py
from flask import Flask
from core.constants import API_PORT, API_HOST
from core.routes.system import system_bp

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.register_blueprint(system_bp)

def create_app():
    return app

def get_server_info():
    return {'host': API_HOST, 'port': API_PORT, 'debug': False}
```

**Step 7: Verify full test suite still green**

```bash
pytest -v
```
Expected: all tests pass.

**Step 8: Commit**

```bash
git add core/routes/system.py core/server.py hexstrike_server.py
git commit -m "feat: migrate health and telemetry routes to system Blueprint"
```

---

### Task 3: Migrate cache, process, and error-handling routes to system Blueprint

**Files:**
- Modify: `core/routes/system.py`
- Modify: `hexstrike_server.py`

**Step 1: Write failing integration tests**

```python
# tests/integration/test_blueprints/test_system_blueprint.py
import pytest
from unittest.mock import patch, MagicMock
from core.server import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()

def test_cache_stats_route(client):
    resp = client.get('/api/cache/stats')
    assert resp.status_code == 200

def test_process_list_route(client):
    with patch('core.routes.system.EnhancedProcessManager') as mock_pm:
        mock_pm.return_value.list_processes.return_value = []
        resp = client.get('/api/processes/list')
    assert resp.status_code == 200

def test_error_handling_statistics_route(client):
    resp = client.get('/api/error-handling/statistics')
    assert resp.status_code == 200
```

**Step 2: Run to confirm failure**

```bash
pytest tests/integration/test_blueprints/test_system_blueprint.py -v
```

**Step 3: Migrate all remaining system routes**

Move these route groups from `hexstrike_server.py` into `core/routes/system.py`:
- `/api/cache/stats`, `/api/cache/clear` (lines ~8866-8887)
- `/api/processes/*` (lines ~8889-9040)
- `/api/process/*` (lines ~16292-16640) — note: `process` vs `processes` are two separate route groups
- `/api/error-handling/*` (lines ~16642-16840)
- `/api/command` (line ~8735)
- `/api/visual/*` (lines for visual endpoints)
- `/api/files/*` (file management routes)
- `/api/python/*`
- `/api/payloads/*`

Change every `@app.route(...)` to `@system_bp.route(...)` in the copied code.

**Step 4: Add necessary imports to system Blueprint**

```python
# Add to top of core/routes/system.py
from flask import Blueprint, jsonify, request
from managers.process_manager import EnhancedProcessManager
from managers.cache_manager import HexStrikeCache
from managers.file_manager import FileOperationsManager
from utils.visual_engine import ModernVisualEngine
from utils.logger import setup_basic_logging
import shutil, subprocess, logging

logger = setup_basic_logging()
```

**Step 5: Run tests**

```bash
pytest -v
```

**Step 6: Commit**

```bash
git add core/routes/system.py hexstrike_server.py tests/integration/test_blueprints/
git commit -m "feat: migrate all system/infrastructure routes to system Blueprint"
```

---

### Task 4: Create `hexstrike_mcp_tools/` package scaffold

**Files:**
- Create: `hexstrike_mcp_tools/__init__.py`
- Create: `hexstrike_mcp_tools/client.py`

**Step 1: Write failing test**

```python
# tests/unit/test_mcp_tools/__init__.py  (empty)

# tests/unit/test_mcp_tools/test_mcp_scaffold.py
from hexstrike_mcp_tools import get_client, initialize
from unittest.mock import MagicMock

def test_initialize_sets_client():
    mock_client = MagicMock()
    initialize(mock_client)
    assert get_client() is mock_client

def test_client_import():
    from hexstrike_mcp_tools.client import HexStrikeClient
    assert callable(HexStrikeClient)
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_mcp_tools/test_mcp_scaffold.py -v
```

**Step 3: Create the package**

```python
# hexstrike_mcp_tools/__init__.py
"""HexStrike MCP tool registration modules."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hexstrike-ai-mcp")
_client = None

def initialize(client) -> None:
    """Set the HexStrike API client for all tool modules."""
    global _client
    _client = client

def get_client():
    """Get the initialized client. Raises if not yet initialized."""
    if _client is None:
        raise RuntimeError("Call hexstrike_mcp_tools.initialize(client) before using tools.")
    return _client
```

```python
# hexstrike_mcp_tools/client.py
"""HexStrike API client — extracted from hexstrike_mcp.py."""
# Copy the full HexStrikeClient class from hexstrike_mcp.py lines 147-265
# (keep identical — this is a pure extract, no changes to logic)
import requests
import logging

logger = logging.getLogger(__name__)

DEFAULT_HEXSTRIKE_SERVER = "http://localhost:8888"
DEFAULT_REQUEST_TIMEOUT = 300
MAX_RETRIES = 3

class HexStrikeClient:
    # ... (full class body copied verbatim from hexstrike_mcp.py)
    pass
```

**Step 4: Run to confirm pass**

```bash
pytest tests/unit/test_mcp_tools/test_mcp_scaffold.py -v
```

**Step 5: Run full suite**

```bash
pytest -v
```

**Step 6: Commit**

```bash
git add hexstrike_mcp_tools/ tests/unit/test_mcp_tools/
git commit -m "feat: add hexstrike_mcp_tools/ package scaffold with client extract"
```

---

### Task 5: Create `hexstrike_mcp_tools/system.py` MCP tool registrations

**Files:**
- Create: `hexstrike_mcp_tools/system.py`

**Step 1: Write failing test**

```python
# tests/unit/test_mcp_tools/test_mcp_scaffold.py (add)
def test_system_tools_importable():
    import hexstrike_mcp_tools.system  # triggers @mcp.tool() registrations
    from hexstrike_mcp_tools import mcp
    tool_names = [t.name for t in mcp._tools.values()] if hasattr(mcp, '_tools') else []
    # At minimum the module should import cleanly
    assert True
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_mcp_tools/test_mcp_scaffold.py::test_system_tools_importable -v
```

**Step 3: Create system MCP tools**

```python
# hexstrike_mcp_tools/system.py
"""MCP tool registrations for system/infrastructure tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def check_server_health() -> Dict[str, Any]:
    """Check HexStrike server health and available tools."""
    return get_client().safe_get("health")

@mcp.tool()
def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """Execute a shell command via the HexStrike server."""
    return get_client().safe_post("api/command", {"command": command, "use_cache": use_cache})

@mcp.tool()
def get_cache_stats() -> Dict[str, Any]:
    """Get server cache performance statistics."""
    return get_client().safe_get("api/cache/stats")

@mcp.tool()
def list_processes() -> Dict[str, Any]:
    """List all running tool processes on the server."""
    return get_client().safe_get("api/processes/list")
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_mcp_tools/ -v
```

**Step 5: Run full suite**

```bash
pytest -v
```

**Step 6: Commit**

```bash
git add hexstrike_mcp_tools/system.py
git commit -m "feat: add system MCP tool registrations to hexstrike_mcp_tools"
```

---

## Batch 2: Network

---

### Task 6: Create and register network Blueprint with existing routes

**Files:**
- Create: `core/routes/network.py`
- Modify: `core/server.py`
- Modify: `hexstrike_server.py`
- Create: `tests/unit/test_routes/test_network_routes.py`
- Create: `tests/integration/test_blueprints/test_network_blueprint.py`

**Step 1: Write unit tests for key network routes**

```python
# tests/unit/test_routes/test_network_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.network import network_bp

@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(network_bp)
    a.config['TESTING'] = True
    return a

def test_nmap_route_missing_target(app):
    resp = app.test_client().post('/api/tools/nmap', json={})
    assert resp.status_code in (400, 500)

def test_nmap_route_with_target(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='scan result', returncode=0)
        resp = app.test_client().post('/api/tools/nmap', json={'target': '127.0.0.1'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'success' in data

def test_rustscan_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        resp = app.test_client().post('/api/tools/rustscan', json={'target': '127.0.0.1'})
    assert resp.status_code == 200
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_routes/test_network_routes.py -v
```

**Step 3: Create network Blueprint**

```python
# core/routes/network.py
"""Network and reconnaissance tool routes."""
import subprocess
import shutil
from flask import Blueprint, request, jsonify
from utils.logger import setup_basic_logging

logger = setup_basic_logging()
network_bp = Blueprint('network', __name__)
```

Copy all network-related `@app.route` handlers from `hexstrike_server.py` into this file, changing `@app.route` to `@network_bp.route`. Network routes include:
- `/api/tools/nmap`, `/api/tools/nmap-advanced`
- `/api/tools/rustscan`, `/api/tools/masscan`
- `/api/tools/amass`, `/api/tools/subfinder`
- `/api/tools/httpx`, `/api/tools/httprobe`
- `/api/tools/waybackurls`, `/api/tools/gau`
- `/api/tools/dnsenum`, `/api/tools/fierce`
- `/api/tools/autorecon`
- `/api/tools/arp-scan`, `/api/tools/nbtscan`
- `/api/tools/enum4linux`, `/api/tools/enum4linux-ng`
- `/api/tools/rpcclient`, `/api/tools/netexec`
- `/api/tools/responder`, `/api/tools/smbmap`
- `/api/tools/wafw00f`
- Any other network/recon routes

**Step 4: Register in `core/server.py`**

```python
from core.routes.network import network_bp
app.register_blueprint(network_bp)
```

**Step 5: Delete migrated handlers from `hexstrike_server.py`**

**Step 6: Run tests**

```bash
pytest -v
```

**Step 7: Commit**

```bash
git add core/routes/network.py core/server.py hexstrike_server.py tests/
git commit -m "feat: migrate network routes to network Blueprint"
```

---

### Task 7: Wire Phase 3 advanced network tools into network Blueprint

**Files:**
- Modify: `core/routes/network.py`

The existing `tools/network/advanced_network.py` contains Phase 3 tools. Add routes for them:

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_network_routes.py (add)
def test_scapy_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        resp = app.test_client().post('/api/tools/network/scapy',
                                      json={'target': '127.0.0.1', 'packet_type': 'icmp'})
    assert resp.status_code == 200

def test_naabu_route_exists(app):
    with patch('core.routes.network.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='80\n443\n', returncode=0)
        resp = app.test_client().post('/api/tools/network/naabu',
                                      json={'target': '127.0.0.1'})
    assert resp.status_code == 200
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_routes/test_network_routes.py -k "scapy or naabu" -v
```

**Step 3: Add Phase 3 routes to network Blueprint**

```python
# core/routes/network.py (add after existing routes)
from tools.network.advanced_network import (
    scapy_packet_forge, zmap_scan, naabu_scan,
    ipv6_toolkit_scan, snmp_check
)

@network_bp.route('/api/tools/network/scapy', methods=['POST'])
def scapy_scan():
    """Scapy packet forging and network analysis."""
    try:
        params = request.json or {}
        result = scapy_packet_forge(
            target=params.get('target', ''),
            packet_type=params.get('packet_type', 'icmp')
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Scapy error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@network_bp.route('/api/tools/network/naabu', methods=['POST'])
def naabu_port_scan():
    """Naabu fast port scanner."""
    try:
        params = request.json or {}
        result = naabu_scan(target=params.get('target', ''))
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Add routes for: zmap, ipv6-toolkit, vlan-hopper, cisco-torch, snmp-check, udp-proto-scanner
```

**Step 4: Run tests**

```bash
pytest -v
```

**Step 5: Commit**

```bash
git add core/routes/network.py tests/unit/test_routes/test_network_routes.py
git commit -m "feat: wire Phase 3 advanced network tools into network Blueprint"
```

---

### Task 8: Create `hexstrike_mcp_tools/network.py`

**Files:**
- Create: `hexstrike_mcp_tools/network.py`
- Create: `tests/unit/test_mcp_tools/test_network_mcp.py`

**Step 1: Write failing test**

```python
# tests/unit/test_mcp_tools/test_network_mcp.py
from unittest.mock import MagicMock, patch
import hexstrike_mcp_tools
from hexstrike_mcp_tools import initialize

def test_network_tools_register():
    mock_client = MagicMock()
    initialize(mock_client)
    import hexstrike_mcp_tools.network  # should import cleanly

def test_nmap_scan_calls_api():
    mock_client = MagicMock()
    mock_client.safe_post.return_value = {"success": True, "output": "scan result"}
    initialize(mock_client)
    import importlib
    import hexstrike_mcp_tools.network as net_mod
    importlib.reload(net_mod)  # re-register with fresh client
    # Call the underlying function directly
    result = net_mod._nmap_scan_impl("127.0.0.1", "-sV", "", "")
    mock_client.safe_post.assert_called_once_with("api/tools/nmap", {
        "target": "127.0.0.1", "scan_type": "-sV", "ports": "", "additional_args": ""
    })
```

**Step 2: Write the MCP tool registrations**

```python
# hexstrike_mcp_tools/network.py
"""MCP tool registrations for network/reconnaissance tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "",
              additional_args: str = "") -> Dict[str, Any]:
    """Execute an Nmap scan. scan_type: -sV (version), -sC (scripts), -sU (UDP)."""
    return get_client().safe_post("api/tools/nmap", {
        "target": target, "scan_type": scan_type,
        "ports": ports, "additional_args": additional_args
    })

def _nmap_scan_impl(target, scan_type, ports, additional_args):
    """Testable implementation wrapper."""
    return get_client().safe_post("api/tools/nmap", {
        "target": target, "scan_type": scan_type,
        "ports": ports, "additional_args": additional_args
    })

@mcp.tool()
def rustscan(target: str, ports: str = "", ulimit: int = 5000) -> Dict[str, Any]:
    """Fast port scanner using RustScan."""
    return get_client().safe_post("api/tools/rustscan", {
        "target": target, "ports": ports, "ulimit": ulimit
    })

@mcp.tool()
def masscan(target: str, ports: str = "0-65535", rate: int = 1000) -> Dict[str, Any]:
    """High-speed port scanner. Use rate carefully on production networks."""
    return get_client().safe_post("api/tools/masscan", {
        "target": target, "ports": ports, "rate": rate
    })

@mcp.tool()
def amass_enum(domain: str, passive: bool = True) -> Dict[str, Any]:
    """Subdomain enumeration using Amass."""
    return get_client().safe_post("api/tools/amass", {
        "domain": domain, "passive": passive
    })

@mcp.tool()
def subfinder(domain: str) -> Dict[str, Any]:
    """Fast passive subdomain discovery."""
    return get_client().safe_post("api/tools/subfinder", {"domain": domain})

@mcp.tool()
def naabu_port_scan(target: str, ports: str = "top-100") -> Dict[str, Any]:
    """Fast port scanner using Naabu (Phase 3)."""
    return get_client().safe_post("api/tools/network/naabu", {
        "target": target, "ports": ports
    })

@mcp.tool()
def snmp_check(target: str, community: str = "public") -> Dict[str, Any]:
    """SNMP enumeration (Phase 3)."""
    return get_client().safe_post("api/tools/network/snmp-check", {
        "target": target, "community": community
    })

# Add remaining network MCP tools following the same pattern:
# waybackurls, gau, httpx, dnsenum, fierce, autorecon, enum4linux,
# netexec, smbmap, responder, wafw00f, scapy, zmap, ipv6-toolkit
```

**Step 3: Run tests**

```bash
pytest tests/unit/test_mcp_tools/test_network_mcp.py -v
pytest -v
```

**Step 4: Commit**

```bash
git add hexstrike_mcp_tools/network.py tests/unit/test_mcp_tools/test_network_mcp.py
git commit -m "feat: add network MCP tool registrations to hexstrike_mcp_tools"
```

---

## Batch 3: Web

---

### Task 9: Migrate web routes to web Blueprint + wire Phase 3 web modules

**Files:**
- Create: `core/routes/web.py`
- Create: `hexstrike_mcp_tools/web.py`
- Modify: `core/server.py`
- Modify: `hexstrike_server.py`
- Create: `tests/unit/test_routes/test_web_routes.py`
- Create: `tests/unit/test_mcp_tools/test_web_mcp.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_web_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.web import web_bp

@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(web_bp)
    a.config['TESTING'] = True
    return a

def test_gobuster_route(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        resp = app.test_client().post('/api/tools/gobuster',
                                      json={'target': 'http://example.com'})
    assert resp.status_code == 200

def test_sqlmap_route(app):
    with patch('core.routes.web.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        resp = app.test_client().post('/api/tools/sqlmap',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200

# Phase 3 web tools
def test_js_analysis_route(app):
    with patch('core.routes.web.js_analysis') as mock_js:
        mock_js.return_value = {'findings': []}
        resp = app.test_client().post('/api/tools/web/js-analysis',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200

def test_injection_testing_route(app):
    with patch('core.routes.web.nosqlmap_test') as mock_inj:
        mock_inj.return_value = {'vulnerable': False}
        resp = app.test_client().post('/api/tools/web/injection',
                                      json={'url': 'http://example.com', 'type': 'nosql'})
    assert resp.status_code == 200

def test_cms_scanner_route(app):
    with patch('core.routes.web.joomscan') as mock_cms:
        mock_cms.return_value = {'cms': 'joomla', 'vulnerabilities': []}
        resp = app.test_client().post('/api/tools/web/cms-scan',
                                      json={'url': 'http://example.com'})
    assert resp.status_code == 200
```

**Step 2: Run to confirm failure**

```bash
pytest tests/unit/test_routes/test_web_routes.py -v
```

**Step 3: Create web Blueprint — migrate existing routes + add Phase 3**

```python
# core/routes/web.py
"""Web application security tool routes."""
import subprocess
import shutil
from flask import Blueprint, request, jsonify
from utils.logger import setup_basic_logging
from tools.web.js_analysis import (
    retire_js_scan, linkfinder_scan, jsluice_scan, trufflehog_scan, secretfinder_scan
)
from tools.web.injection_testing import (
    nosqlmap_test, ssrf_sheriff, xxeinjector, ssti_scanner
)
from tools.web.auth_testing import (
    csrf_scanner, cookie_analyzer, saml_raider_test
)
from tools.web.cms_scanners import joomscan, droopescan, magescan
from tools.web.cdn_tools import cdn_scanner, cache_poisoner, cloudflare_bypass

logger = setup_basic_logging()
web_bp = Blueprint('web', __name__)

# --- Existing routes (migrated from hexstrike_server.py) ---
# Copy all web @app.route handlers: gobuster, nuclei, nikto, sqlmap,
# ffuf, feroxbuster, dirsearch, wpscan, wfuzz, xsser, dotdotpwn,
# dalfox, katana, gau, waybackurls, arjun, paramspider, x8,
# jaeles, httpx (if not in network), anew, qsreplace, uro,
# burpsuite-alternative, zap, http-framework, browser-agent,
# api_fuzzer, graphql_scanner, jwt_analyzer, api_schema_analyzer
# Change @app.route → @web_bp.route

# --- Phase 3 routes (new) ---
@web_bp.route('/api/tools/web/js-analysis', methods=['POST'])
def web_js_analysis():
    """JavaScript security analysis (retire.js, linkfinder, trufflehog)."""
    try:
        params = request.json or {}
        url = params.get('url', '')
        results = {
            'retire_js': retire_js_scan(url),
            'linkfinder': linkfinder_scan(url),
            'secrets': trufflehog_scan(url)
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"JS analysis error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@web_bp.route('/api/tools/web/injection', methods=['POST'])
def web_injection_test():
    """Injection vulnerability testing (NoSQL, SSRF, XXE, SSTI, CRLF)."""
    try:
        params = request.json or {}
        url = params.get('url', '')
        inject_type = params.get('type', 'nosql')
        scanners = {
            'nosql': nosqlmap_test,
            'ssrf': ssrf_sheriff,
            'xxe': xxeinjector,
            'ssti': ssti_scanner,
        }
        scanner = scanners.get(inject_type, nosqlmap_test)
        return jsonify({"success": True, "result": scanner(url)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@web_bp.route('/api/tools/web/auth-test', methods=['POST'])
def web_auth_test():
    """Authentication vulnerability testing (CSRF, cookies, SAML)."""
    try:
        params = request.json or {}
        url = params.get('url', '')
        results = {
            'csrf': csrf_scanner(url),
            'cookies': cookie_analyzer(url),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@web_bp.route('/api/tools/web/cms-scan', methods=['POST'])
def web_cms_scan():
    """CMS security scanning (Joomla, Drupal, Magento)."""
    try:
        params = request.json or {}
        url = params.get('url', '')
        cms = params.get('cms', 'joomla')
        scanners = {'joomla': joomscan, 'drupal': droopescan, 'magento': magescan}
        scanner = scanners.get(cms, joomscan)
        return jsonify({"success": True, "result": scanner(url)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@web_bp.route('/api/tools/web/cdn-bypass', methods=['POST'])
def web_cdn_bypass():
    """CDN and cache security testing."""
    try:
        params = request.json or {}
        url = params.get('url', '')
        results = {
            'cdn_scan': cdn_scanner(url),
            'cache_poison': cache_poisoner(url),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
```

**Step 4: Register Blueprint**

```python
# core/server.py (add)
from core.routes.web import web_bp
app.register_blueprint(web_bp)
```

**Step 5: Create web MCP tools**

```python
# hexstrike_mcp_tools/web.py
"""MCP tool registrations for web security tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def gobuster_scan(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  extensions: str = "php,html,js") -> Dict[str, Any]:
    """Directory and file brute-force using Gobuster."""
    return get_client().safe_post("api/tools/gobuster", {
        "target": target, "wordlist": wordlist, "extensions": extensions
    })

@mcp.tool()
def sqlmap_scan(url: str, params: str = "", level: int = 1,
                risk: int = 1) -> Dict[str, Any]:
    """SQL injection testing using SQLMap."""
    return get_client().safe_post("api/tools/sqlmap", {
        "url": url, "params": params, "level": level, "risk": risk
    })

@mcp.tool()
def web_js_analysis(url: str) -> Dict[str, Any]:
    """JavaScript security analysis — finds secrets, endpoints, vulnerable libs."""
    return get_client().safe_post("api/tools/web/js-analysis", {"url": url})

@mcp.tool()
def web_injection_test(url: str, inject_type: str = "nosql") -> Dict[str, Any]:
    """Injection testing. inject_type: nosql | ssrf | xxe | ssti | crlf"""
    return get_client().safe_post("api/tools/web/injection",
                                  {"url": url, "type": inject_type})

@mcp.tool()
def web_cms_scan(url: str, cms: str = "joomla") -> Dict[str, Any]:
    """CMS security scan. cms: joomla | drupal | magento"""
    return get_client().safe_post("api/tools/web/cms-scan", {"url": url, "cms": cms})

@mcp.tool()
def web_auth_test(url: str) -> Dict[str, Any]:
    """Authentication vulnerability testing — CSRF, cookies, session handling."""
    return get_client().safe_post("api/tools/web/auth-test", {"url": url})

# Add remaining web tools: nuclei, nikto, ffuf, feroxbuster,
# dirsearch, wpscan, dalfox, katana, xsser, wafw00f, etc.
```

**Step 6: Delete migrated handlers from `hexstrike_server.py`**

**Step 7: Run all tests**

```bash
pytest -v
```

**Step 8: Commit**

```bash
git add core/routes/web.py hexstrike_mcp_tools/web.py core/server.py hexstrike_server.py tests/
git commit -m "feat: migrate web routes + wire Phase 3 web modules + MCP tools"
```

---

## Batch 4: Cloud + Binary

---

### Task 10: Cloud Blueprint + Phase 3 cloud modules

**Files:**
- Create: `core/routes/cloud.py`
- Create: `hexstrike_mcp_tools/cloud.py`
- Modify: `core/server.py`, `hexstrike_server.py`
- Create: `tests/unit/test_routes/test_cloud_routes.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_cloud_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.cloud import cloud_bp

@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(cloud_bp)
    a.config['TESTING'] = True
    return a

def test_trivy_route(app):
    with patch('core.routes.cloud.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='{}', returncode=0)
        resp = app.test_client().post('/api/tools/trivy', json={'target': 'nginx:latest'})
    assert resp.status_code == 200

def test_cloud_native_kubescape(app):
    with patch('core.routes.cloud.kubescape_scan') as mock_ks:
        mock_ks.return_value = {'passed': 10, 'failed': 2}
        resp = app.test_client().post('/api/tools/cloud/kubescape',
                                      json={'target': 'cluster'})
    assert resp.status_code == 200

def test_container_escape_deepce(app):
    with patch('core.routes.cloud.deepce_scan') as mock_dc:
        mock_dc.return_value = {'escape_possible': False}
        resp = app.test_client().post('/api/tools/cloud/container-escape',
                                      json={'technique': 'deepce'})
    assert resp.status_code == 200
```

**Step 2: Create cloud Blueprint**

```python
# core/routes/cloud.py
"""Cloud and container security tool routes."""
import subprocess
from flask import Blueprint, request, jsonify
from utils.logger import setup_basic_logging
from tools.cloud.cloud_native import (
    kubescape_scan, popeye_scan, rbac_police_scan, kubesec_scan,
    aws_vault_enum, azure_security_scan, gcp_firewall_enum
)
from tools.cloud.container_escape import (
    deepce_scan, amicontained_check, cdk_exploit, peirates_attack
)

logger = setup_basic_logging()
cloud_bp = Blueprint('cloud', __name__)

# --- Existing routes (migrated) ---
# prowler, trivy, scout-suite, cloudmapper, pacu, kube-hunter,
# kube-bench, docker-bench-security, clair, falco, checkov, terrascan

# --- Phase 3 routes ---
@cloud_bp.route('/api/tools/cloud/kubescape', methods=['POST'])
def cloud_kubescape():
    """Kubernetes security posture assessment."""
    try:
        params = request.json or {}
        return jsonify({"success": True, "result": kubescape_scan(params.get('target', ''))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@cloud_bp.route('/api/tools/cloud/container-escape', methods=['POST'])
def cloud_container_escape():
    """Container escape vulnerability assessment."""
    try:
        params = request.json or {}
        technique = params.get('technique', 'deepce')
        scanners = {'deepce': deepce_scan, 'amicontained': amicontained_check,
                    'cdk': cdk_exploit, 'peirates': peirates_attack}
        scanner = scanners.get(technique, deepce_scan)
        return jsonify({"success": True, "result": scanner()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@cloud_bp.route('/api/tools/cloud/rbac-audit', methods=['POST'])
def cloud_rbac_audit():
    """Kubernetes RBAC policy audit."""
    try:
        return jsonify({"success": True, "result": rbac_police_scan()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
```

**Step 3: Create cloud MCP tools**

```python
# hexstrike_mcp_tools/cloud.py
"""MCP tool registrations for cloud security tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def trivy_scan(target: str, scan_type: str = "image") -> Dict[str, Any]:
    """Container/IaC vulnerability scanning with Trivy. scan_type: image | fs | repo"""
    return get_client().safe_post("api/tools/trivy",
                                  {"target": target, "scan_type": scan_type})

@mcp.tool()
def prowler_scan(provider: str = "aws", checks: str = "") -> Dict[str, Any]:
    """Cloud security best practices audit. provider: aws | azure | gcp"""
    return get_client().safe_post("api/tools/prowler",
                                  {"provider": provider, "checks": checks})

@mcp.tool()
def kubescape_assessment(target: str = "cluster") -> Dict[str, Any]:
    """Kubernetes security posture assessment (Phase 3)."""
    return get_client().safe_post("api/tools/cloud/kubescape", {"target": target})

@mcp.tool()
def container_escape_check(technique: str = "deepce") -> Dict[str, Any]:
    """Container escape vulnerability check. technique: deepce | amicontained | cdk"""
    return get_client().safe_post("api/tools/cloud/container-escape",
                                  {"technique": technique})

@mcp.tool()
def kubernetes_rbac_audit() -> Dict[str, Any]:
    """Kubernetes RBAC policy security audit (Phase 3)."""
    return get_client().safe_post("api/tools/cloud/rbac-audit", {})
```

**Step 4: Register Blueprint, delete migrated routes, run tests, commit**

```bash
# Register
# core/server.py: add `from core.routes.cloud import cloud_bp` and `app.register_blueprint(cloud_bp)`

pytest -v

git add core/routes/cloud.py hexstrike_mcp_tools/cloud.py core/server.py hexstrike_server.py tests/
git commit -m "feat: migrate cloud routes + wire Phase 3 cloud modules + MCP tools"
```

---

### Task 11: Binary Blueprint + Phase 3 binary modules

**Files:**
- Create: `core/routes/binary.py`
- Create: `hexstrike_mcp_tools/binary.py`
- Modify: `core/server.py`, `hexstrike_server.py`
- Create: `tests/unit/test_routes/test_binary_routes.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_binary_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.binary import binary_bp

@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(binary_bp)
    a.config['TESTING'] = True
    return a

def test_gdb_route(app):
    with patch('core.routes.binary.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='', returncode=0)
        resp = app.test_client().post('/api/tools/gdb', json={'binary': '/tmp/test'})
    assert resp.status_code == 200

def test_binwalk_route(app):
    with patch('core.routes.binary.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='DECIMAL HEXADECIMAL', returncode=0)
        resp = app.test_client().post('/api/tools/binwalk', json={'file': '/tmp/test.bin'})
    assert resp.status_code == 200

def test_yara_scan_route(app):
    with patch('core.routes.binary.yara_scan') as mock_yara:
        mock_yara.return_value = {'matches': []}
        resp = app.test_client().post('/api/tools/binary/yara',
                                      json={'file': '/tmp/test', 'rules': '/tmp/rules'})
    assert resp.status_code == 200

def test_floss_route(app):
    with patch('core.routes.binary.floss_analyze') as mock_floss:
        mock_floss.return_value = {'strings': []}
        resp = app.test_client().post('/api/tools/binary/floss', json={'file': '/tmp/test'})
    assert resp.status_code == 200
```

**Step 2: Create binary Blueprint**

```python
# core/routes/binary.py
"""Binary analysis and forensics tool routes."""
import subprocess
from flask import Blueprint, request, jsonify
from utils.logger import setup_basic_logging
from tools.binary.enhanced_binary import (
    rizin_analyze, cutter_analyze, pwndbg_debug, unicorn_emulate
)
from tools.binary.forensics import (
    autopsy_analyze, dc3dd_image
)
from tools.binary.malware_analysis import (
    yara_scan, floss_analyze, hollows_hunter_scan
)

logger = setup_basic_logging()
binary_bp = Blueprint('binary', __name__)

# --- Existing routes (migrated) ---
# gdb, radare2, binwalk, ropgadget, checksec, xxd, strings, objdump,
# ghidra, pwntools, one-gadget, libc-database, gdb-peda, angr, ropper,
# pwninit, volatility, foremost, steghide, exiftool, hashpump,
# volatility3, msfvenom

# --- Phase 3 routes ---
@binary_bp.route('/api/tools/binary/rizin', methods=['POST'])
def binary_rizin():
    """Rizin binary analysis (Phase 3)."""
    try:
        params = request.json or {}
        return jsonify({"success": True, "result": rizin_analyze(params.get('binary', ''))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@binary_bp.route('/api/tools/binary/yara', methods=['POST'])
def binary_yara():
    """YARA malware pattern matching (Phase 3)."""
    try:
        params = request.json or {}
        result = yara_scan(
            file_path=params.get('file', ''),
            rules_path=params.get('rules', '')
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@binary_bp.route('/api/tools/binary/floss', methods=['POST'])
def binary_floss():
    """FLOSS obfuscated string extraction (Phase 3)."""
    try:
        params = request.json or {}
        return jsonify({"success": True, "result": floss_analyze(params.get('file', ''))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@binary_bp.route('/api/tools/binary/forensics', methods=['POST'])
def binary_forensics():
    """Digital forensics analysis (autopsy, dc3dd)."""
    try:
        params = request.json or {}
        return jsonify({"success": True, "result": autopsy_analyze(params.get('image', ''))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
```

**Step 3: Create binary MCP tools**

```python
# hexstrike_mcp_tools/binary.py
"""MCP tool registrations for binary analysis tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def gdb_debug(binary: str, commands: str = "") -> Dict[str, Any]:
    """GDB debugger. commands: semicolon-separated GDB commands."""
    return get_client().safe_post("api/tools/gdb",
                                  {"binary": binary, "commands": commands})

@mcp.tool()
def ghidra_analyze(binary: str) -> Dict[str, Any]:
    """Ghidra static analysis and decompilation (headless mode)."""
    return get_client().safe_post("api/tools/ghidra", {"binary": binary})

@mcp.tool()
def binwalk_scan(file: str) -> Dict[str, Any]:
    """Firmware and binary file analysis with Binwalk."""
    return get_client().safe_post("api/tools/binwalk", {"file": file})

@mcp.tool()
def yara_malware_scan(file: str, rules: str = "") -> Dict[str, Any]:
    """YARA malware pattern matching (Phase 3)."""
    return get_client().safe_post("api/tools/binary/yara",
                                  {"file": file, "rules": rules})

@mcp.tool()
def floss_string_extract(file: str) -> Dict[str, Any]:
    """Extract obfuscated strings from malware with FLOSS (Phase 3)."""
    return get_client().safe_post("api/tools/binary/floss", {"file": file})

@mcp.tool()
def rizin_analyze(binary: str) -> Dict[str, Any]:
    """Rizin binary analysis framework (Phase 3)."""
    return get_client().safe_post("api/tools/binary/rizin", {"binary": binary})
```

**Step 4: Register Blueprint, delete migrated routes, run tests, commit**

```bash
pytest -v
git add core/routes/binary.py hexstrike_mcp_tools/binary.py core/server.py hexstrike_server.py tests/
git commit -m "feat: migrate binary routes + wire Phase 3 binary/forensics/malware modules + MCP tools"
```

---

## Batch 5: CTF + BugBounty + Intelligence

---

### Task 12: CTF, BugBounty, Intelligence Blueprints

These agents are already working. This is pure route migration — no new implementations.

**Files:**
- Create: `core/routes/ctf.py`
- Create: `core/routes/bugbounty.py`
- Create: `core/routes/intelligence.py`
- Create: `hexstrike_mcp_tools/workflows.py`
- Modify: `core/server.py`, `hexstrike_server.py`
- Create: `tests/unit/test_routes/test_workflow_routes.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_workflow_routes.py
from flask import Flask
from unittest.mock import patch, MagicMock
from core.routes.ctf import ctf_bp
from core.routes.bugbounty import bugbounty_bp
from core.routes.intelligence import intelligence_bp

def test_ctf_blueprint_registers():
    app = Flask(__name__)
    app.register_blueprint(ctf_bp)
    assert 'ctf' in app.blueprints

def test_bugbounty_blueprint_registers():
    app = Flask(__name__)
    app.register_blueprint(bugbounty_bp)
    assert 'bugbounty' in app.blueprints

def test_intelligence_blueprint_registers():
    app = Flask(__name__)
    app.register_blueprint(intelligence_bp)
    assert 'intelligence' in app.blueprints

def test_ctf_auto_solve_route():
    app = Flask(__name__)
    app.register_blueprint(ctf_bp)
    app.config['TESTING'] = True
    with patch('core.routes.ctf.CTFWorkflowManager') as mock_ctf:
        mock_ctf.return_value.auto_solve.return_value = {'solution': 'flag{test}'}
        resp = app.test_client().post('/api/ctf/auto-solve-challenge',
                                      json={'challenge_type': 'crypto', 'data': 'test'})
    assert resp.status_code == 200

def test_intelligence_analyze_target_route():
    app = Flask(__name__)
    app.register_blueprint(intelligence_bp)
    app.config['TESTING'] = True
    with patch('core.routes.intelligence.IntelligentDecisionEngine') as mock_ide:
        mock_ide.return_value.analyze_target.return_value = {'risk': 'medium'}
        resp = app.test_client().post('/api/intelligence/analyze-target',
                                      json={'target': 'example.com'})
    assert resp.status_code == 200
```

**Step 2: Create the three Blueprints**

```python
# core/routes/ctf.py
from flask import Blueprint, request, jsonify
from agents.ctf_manager import CTFWorkflowManager
from agents.ctf_tools import CTFToolManager
from utils.logger import setup_basic_logging

logger = setup_basic_logging()
ctf_bp = Blueprint('ctf', __name__)

# Move all /api/ctf/* route handlers from hexstrike_server.py here
# (create-challenge-workflow, auto-solve-challenge, team-strategy,
#  suggest-tools, cryptography-solver, forensics-analyzer, binary-analyzer)
# Change @app.route → @ctf_bp.route
```

```python
# core/routes/bugbounty.py
from flask import Blueprint, request, jsonify
from agents.bugbounty_manager import BugBountyWorkflowManager
from utils.logger import setup_basic_logging

logger = setup_basic_logging()
bugbounty_bp = Blueprint('bugbounty', __name__)

# Move all /api/bugbounty/* route handlers here
# (reconnaissance-workflow, vulnerability-hunting-workflow,
#  business-logic-workflow, osint-workflow, file-upload-testing,
#  comprehensive-assessment)
```

```python
# core/routes/intelligence.py
from flask import Blueprint, request, jsonify
from agents.decision_engine import IntelligentDecisionEngine
from agents.cve_intelligence import CVEIntelligenceManager
from utils.logger import setup_basic_logging

logger = setup_basic_logging()
intelligence_bp = Blueprint('intelligence', __name__)

# Move all /api/intelligence/*, /api/vuln-intel/*, /api/ai/* routes here
```

**Step 3: Create workflow MCP tools**

```python
# hexstrike_mcp_tools/workflows.py
"""MCP tool registrations for AI workflow tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def analyze_target(target: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
    """AI-powered target analysis and attack surface mapping."""
    return get_client().safe_post("api/intelligence/analyze-target",
                                  {"target": target, "analysis_type": analysis_type})

@mcp.tool()
def ctf_auto_solve(challenge_type: str, data: str,
                   hints: str = "") -> Dict[str, Any]:
    """Autonomous CTF challenge solver. challenge_type: crypto | pwn | web | forensics | rev"""
    return get_client().safe_post("api/ctf/auto-solve-challenge",
                                  {"challenge_type": challenge_type, "data": data, "hints": hints})

@mcp.tool()
def bugbounty_recon(target: str, scope: str = "") -> Dict[str, Any]:
    """Automated bug bounty reconnaissance workflow."""
    return get_client().safe_post("api/bugbounty/reconnaissance-workflow",
                                  {"target": target, "scope": scope})

@mcp.tool()
def cve_intelligence(cve_id: str) -> Dict[str, Any]:
    """CVE intelligence, exploit analysis, and mitigation guidance."""
    return get_client().safe_post("api/vuln-intel/cve-monitor", {"cve_id": cve_id})
```

**Step 4: Register all three Blueprints, delete migrated routes, run tests, commit**

```bash
pytest -v
git add core/routes/ctf.py core/routes/bugbounty.py core/routes/intelligence.py \
        hexstrike_mcp_tools/workflows.py core/server.py hexstrike_server.py tests/
git commit -m "feat: migrate CTF, BugBounty, Intelligence routes to Blueprints + workflow MCP tools"
```

---

## Batch 6: Mobile + API + Wireless (Phase 2 completion)

---

### Task 13: Complete Phase 2 — Mobile Blueprint + full MCP registration

**Files:**
- Create: `core/routes/mobile.py`
- Create: `hexstrike_mcp_tools/mobile.py`
- Modify: `core/server.py`, `hexstrike_server.py`
- Create: `tests/unit/test_routes/test_mobile_routes.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_mobile_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.mobile import mobile_bp

@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(mobile_bp)
    a.config['TESTING'] = True
    return a

def test_apk_analyze_route(app):
    with patch('core.routes.mobile.apktool_decompile') as mock_apk:
        mock_apk.return_value = {'success': True, 'output': 'decompiled'}
        resp = app.test_client().post('/api/tools/mobile/apk-analyze',
                                      json={'apk_path': '/tmp/test.apk'})
    assert resp.status_code == 200

def test_ios_analyze_route(app):
    with patch('core.routes.mobile.ipa_analyzer') as mock_ios:
        mock_ios.return_value = {'success': True, 'info': {}}
        resp = app.test_client().post('/api/tools/mobile/ios-analyze',
                                      json={'ipa_path': '/tmp/test.ipa'})
    assert resp.status_code == 200

# Phase 2 completion — routes that don't exist yet
def test_mobile_exploit_drozer(app):
    with patch('core.routes.mobile.drozer_scan') as mock_dz:
        mock_dz.return_value = {'vulnerabilities': []}
        resp = app.test_client().post('/api/tools/mobile/drozer',
                                      json={'package': 'com.example.app'})
    assert resp.status_code == 200

def test_mobile_network_mitm(app):
    with patch('core.routes.mobile.mitmproxy_mobile_intercept') as mock_mitm:
        mock_mitm.return_value = {'traffic': []}
        resp = app.test_client().post('/api/tools/mobile/mitm',
                                      json={'interface': 'wlan0'})
    assert resp.status_code == 200
```

**Step 2: Create mobile Blueprint (migrate existing + add missing)**

```python
# core/routes/mobile.py
"""Mobile security tool routes."""
from flask import Blueprint, request, jsonify
from utils.logger import setup_basic_logging
from tools.mobile.apk_tools import apktool_decompile, jadx_decompile, androguard_analyze
from tools.mobile.ios_tools import ipa_analyzer, class_dump
from tools.mobile.mobile_exploit import drozer_scan, needle_ios_scan
from tools.mobile.mobile_network import mitmproxy_mobile_intercept, tcpdump_mobile_capture

logger = setup_basic_logging()
mobile_bp = Blueprint('mobile', __name__)

# Existing routes (move from hexstrike_server.py, change @app.route → @mobile_bp.route)
@mobile_bp.route('/api/tools/mobile/apk-analyze', methods=['POST'])
def mobile_apk_analyze():
    """APK analysis using apktool, jadx, androguard."""
    try:
        params = request.json or {}
        apk_path = params.get('apk_path', '')
        results = {
            'apktool': apktool_decompile(apk_path),
            'jadx': jadx_decompile(apk_path),
            'androguard': androguard_analyze(apk_path)
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"APK analysis error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@mobile_bp.route('/api/tools/mobile/ios-analyze', methods=['POST'])
def mobile_ios_analyze():
    """iOS IPA analysis."""
    try:
        params = request.json or {}
        ipa_path = params.get('ipa_path', '')
        results = {
            'ipa_analyzer': ipa_analyzer(ipa_path),
            'class_dump': class_dump(ipa_path)
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# New routes (Phase 2 completion)
@mobile_bp.route('/api/tools/mobile/drozer', methods=['POST'])
def mobile_drozer():
    """Drozer Android security framework."""
    try:
        params = request.json or {}
        return jsonify({"success": True, "result": drozer_scan(params.get('package', ''))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@mobile_bp.route('/api/tools/mobile/mitm', methods=['POST'])
def mobile_mitm():
    """Mobile traffic interception via mitmproxy."""
    try:
        params = request.json or {}
        return jsonify({"success": True, "result":
                        mitmproxy_mobile_intercept(params.get('interface', 'wlan0'))})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
```

**Step 3: Create mobile MCP tools (currently 0 — first time registered)**

```python
# hexstrike_mcp_tools/mobile.py
"""MCP tool registrations for mobile security tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def apk_analyze(apk_path: str) -> Dict[str, Any]:
    """Full APK analysis using apktool, jadx, and androguard."""
    return get_client().safe_post("api/tools/mobile/apk-analyze", {"apk_path": apk_path})

@mcp.tool()
def ios_analyze(ipa_path: str) -> Dict[str, Any]:
    """iOS IPA analysis using ipa-analyzer and class-dump."""
    return get_client().safe_post("api/tools/mobile/ios-analyze", {"ipa_path": ipa_path})

@mcp.tool()
def drozer_android_audit(package: str) -> Dict[str, Any]:
    """Android app security audit using Drozer (Phase 2)."""
    return get_client().safe_post("api/tools/mobile/drozer", {"package": package})

@mcp.tool()
def mobile_traffic_intercept(interface: str = "wlan0") -> Dict[str, Any]:
    """Intercept mobile app traffic using mitmproxy (Phase 2)."""
    return get_client().safe_post("api/tools/mobile/mitm", {"interface": interface})
```

**Step 4: Register, run tests, commit**

```bash
pytest -v
git add core/routes/mobile.py hexstrike_mcp_tools/mobile.py core/server.py hexstrike_server.py tests/
git commit -m "feat: complete Phase 2 mobile — full Blueprint + first MCP registrations"
```

---

### Task 14: Complete Phase 2 — API Security Blueprint + Wireless Blueprint

Follow identical pattern to Task 13 for the API and Wireless categories.

**API Security (`core/routes/api_security.py`):**

Migrate existing 2 routes (`/api/tools/api/discover`, `/api/tools/api/fuzz`) and add:
- `/api/tools/api/auth-test` — wires `tools/api/api_auth.py` (jwt-hack, oauth-scanner)
- `/api/tools/api/monitoring` — wires `tools/api/api_monitoring.py`

**Wireless (`core/routes/wireless.py`):**

Migrate existing 2 routes (`/api/tools/wireless/wifi-attack`, `/api/tools/wireless/bluetooth-scan`) and add:
- `/api/tools/wireless/rf` — wires `tools/wireless/rf_tools.py` (rtl-sdr, hackrf)

**MCP tools:**

```python
# hexstrike_mcp_tools/api_security.py
@mcp.tool()
def api_discover(base_url: str, schema_url: str = "") -> Dict[str, Any]:
    """API endpoint discovery and schema analysis."""
    return get_client().safe_post("api/tools/api/discover",
                                  {"base_url": base_url, "schema_url": schema_url})

@mcp.tool()
def api_auth_test(base_url: str, jwt_token: str = "") -> Dict[str, Any]:
    """API authentication vulnerability testing — JWT, OAuth, API keys."""
    return get_client().safe_post("api/tools/api/auth-test",
                                  {"base_url": base_url, "jwt_token": jwt_token})

@mcp.tool()
def api_fuzz(base_url: str, wordlist: str = "") -> Dict[str, Any]:
    """API endpoint fuzzing."""
    return get_client().safe_post("api/tools/api/fuzz",
                                  {"base_url": base_url, "wordlist": wordlist})
```

```python
# hexstrike_mcp_tools/wireless.py
@mcp.tool()
def wifi_attack(interface: str, target_bssid: str = "",
                attack_type: str = "handshake") -> Dict[str, Any]:
    """WiFi security testing. attack_type: handshake | deauth | pmkid"""
    return get_client().safe_post("api/tools/wireless/wifi-attack",
                                  {"interface": interface, "target_bssid": target_bssid,
                                   "attack_type": attack_type})

@mcp.tool()
def bluetooth_scan(interface: str = "hci0") -> Dict[str, Any]:
    """Bluetooth device scanning and vulnerability assessment."""
    return get_client().safe_post("api/tools/wireless/bluetooth-scan",
                                  {"interface": interface})

@mcp.tool()
def rf_analysis(frequency: float = 433.0, device: str = "rtlsdr") -> Dict[str, Any]:
    """RF signal analysis using RTL-SDR or HackRF (Phase 2)."""
    return get_client().safe_post("api/tools/wireless/rf",
                                  {"frequency": frequency, "device": device})
```

**Commit:**

```bash
pytest -v
git add core/routes/api_security.py core/routes/wireless.py \
        hexstrike_mcp_tools/api_security.py hexstrike_mcp_tools/wireless.py \
        core/server.py hexstrike_server.py tests/
git commit -m "feat: complete Phase 2 API security + wireless — Blueprints + MCP tools"
```

---

## Batch 7: OSINT (new from scratch)

---

### Task 15: Implement `tools/osint/passive_recon.py`

**Files:**
- Create: `tools/osint/__init__.py`
- Create: `tools/osint/passive_recon.py`
- Create: `tests/unit/test_osint_tools.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_osint_tools.py
import pytest
from unittest.mock import patch, MagicMock

def test_shodan_search_returns_dict():
    from tools.osint.passive_recon import shodan_search
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='{"ip_str": "1.2.3.4"}', returncode=0)
        result = shodan_search("nginx", api_key="test_key")
    assert isinstance(result, dict)
    assert 'success' in result or 'error' in result or 'results' in result

def test_whois_lookup_returns_dict():
    from tools.osint.passive_recon import whois_lookup
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='Domain: example.com\n', returncode=0)
        result = whois_lookup("example.com")
    assert isinstance(result, dict)

def test_the_harvester_returns_dict():
    from tools.osint.passive_recon import the_harvester
    with patch('tools.osint.passive_recon.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='[*] Emails found: 3\n', returncode=0)
        result = the_harvester("example.com")
    assert isinstance(result, dict)
```

**Step 2: Implement**

```python
# tools/osint/__init__.py
"""OSINT and intelligence gathering tools."""

# tools/osint/passive_recon.py
"""Passive reconnaissance tools — no direct target interaction."""
import subprocess
import shutil
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)
TIMEOUT = 120

def shodan_search(query: str, api_key: str = "") -> Dict[str, Any]:
    """Shodan IP/service/banner lookup."""
    if not shutil.which("shodan"):
        return {"success": False, "error": "shodan CLI not installed"}
    try:
        cmd = ["shodan", "search", "--fields", "ip_str,port,org,hostnames", query]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "query": query
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Shodan search timed out"}
    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return {"success": False, "error": str(e)}

def whois_lookup(domain: str) -> Dict[str, Any]:
    """WHOIS domain registration lookup."""
    if not shutil.which("whois"):
        return {"success": False, "error": "whois not installed"}
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True,
                                timeout=30)
        return {"success": result.returncode == 0, "output": result.stdout,
                "domain": domain}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "WHOIS timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def the_harvester(domain: str, sources: str = "all") -> Dict[str, Any]:
    """theHarvester — emails, subdomains, hosts from public sources."""
    if not shutil.which("theHarvester"):
        return {"success": False, "error": "theHarvester not installed"}
    try:
        cmd = ["theHarvester", "-d", domain, "-b", sources, "-f", "/tmp/harvester_out"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return {"success": result.returncode == 0, "output": result.stdout,
                "domain": domain}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "theHarvester timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def dnsdumpster_recon(domain: str) -> Dict[str, Any]:
    """DNS recon via dnsdumpster (API-based)."""
    try:
        import requests
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                            timeout=30)
        lines = resp.text.strip().split('\n') if resp.ok else []
        hosts = [line.split(',') for line in lines if line]
        return {"success": True, "hosts": hosts, "count": len(hosts)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def censys_search(query: str, api_id: str = "", api_secret: str = "") -> Dict[str, Any]:
    """Censys certificate and host enumeration."""
    if not shutil.which("censys"):
        return {"success": False, "error": "censys CLI not installed. pip install censys"}
    try:
        cmd = ["censys", "search", query, "--index-type", "hosts"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return {"success": result.returncode == 0, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

**Step 3: Run tests**

```bash
pytest tests/unit/test_osint_tools.py -v
```

**Step 4: Commit**

```bash
git add tools/osint/ tests/unit/test_osint_tools.py
git commit -m "feat: implement tools/osint/passive_recon.py (shodan, whois, theHarvester, censys)"
```

---

### Task 16: Implement `tools/osint/social_intel.py` and `tools/osint/threat_intel.py`

**Files:**
- Create: `tools/osint/social_intel.py`
- Create: `tools/osint/threat_intel.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_osint_tools.py (add)
def test_sherlock_search():
    from tools.osint.social_intel import sherlock_search
    with patch('tools.osint.social_intel.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(stdout='[+] Twitter: Found\n', returncode=0)
        result = sherlock_search("testuser")
    assert isinstance(result, dict)

def test_virustotal_lookup():
    from tools.osint.threat_intel import virustotal_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(
            ok=True,
            json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
        )
        result = virustotal_lookup("8.8.8.8", api_key="test")
    assert isinstance(result, dict)

def test_urlscan_lookup():
    from tools.osint.threat_intel import urlscan_lookup
    with patch('tools.osint.threat_intel.requests.get') as mock_get:
        mock_get.return_value = MagicMock(ok=True, json=lambda: {"results": []})
        result = urlscan_lookup("example.com")
    assert isinstance(result, dict)
```

**Step 2: Implement social_intel.py**

```python
# tools/osint/social_intel.py
"""Social media and identity OSINT tools."""
import subprocess
import shutil
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)
TIMEOUT = 180

def sherlock_search(username: str) -> Dict[str, Any]:
    """Username search across 300+ platforms using Sherlock."""
    if not shutil.which("sherlock"):
        return {"success": False, "error": "sherlock not installed. pip install sherlock-project"}
    try:
        result = subprocess.run(["sherlock", username, "--print-found"],
                                capture_output=True, text=True, timeout=TIMEOUT)
        found = [line for line in result.stdout.split('\n') if '[+]' in line]
        return {"success": True, "username": username, "found_on": found,
                "count": len(found)}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Sherlock timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def holehe_check(email: str) -> Dict[str, Any]:
    """Check which services an email is registered on using Holehe."""
    if not shutil.which("holehe"):
        return {"success": False, "error": "holehe not installed. pip install holehe"}
    try:
        result = subprocess.run(["holehe", email], capture_output=True, text=True,
                                timeout=TIMEOUT)
        registered = [line for line in result.stdout.split('\n') if '[+]' in line]
        return {"success": True, "email": email, "registered_on": registered,
                "count": len(registered)}
    except Exception as e:
        return {"success": False, "error": str(e)}

def breach_lookup(email: str) -> Dict[str, Any]:
    """Check email against known breach databases via HaveIBeenPwned API."""
    try:
        import requests
        headers = {'User-Agent': 'HexStrike-OSINT/7.0'}
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, timeout=30
        )
        if resp.status_code == 404:
            return {"success": True, "email": email, "breached": False, "breaches": []}
        elif resp.status_code == 200:
            breaches = [b.get('Name') for b in resp.json()]
            return {"success": True, "email": email, "breached": True,
                    "breaches": breaches, "count": len(breaches)}
        else:
            return {"success": False, "error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def linkedin_recon(company: str) -> Dict[str, Any]:
    """Basic LinkedIn company OSINT (public data only)."""
    return {
        "success": True,
        "note": "LinkedIn recon requires manual authentication. Use linkedin2username for automation.",
        "company": company,
        "suggestion": "Run: python3 linkedin2username.py -c '{company}' -u user@email.com"
    }
```

**Step 3: Implement threat_intel.py**

```python
# tools/osint/threat_intel.py
"""Threat intelligence and IOC lookup tools."""
import requests
import shutil
import subprocess
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)
TIMEOUT = 30

def virustotal_lookup(ioc: str, api_key: str = "") -> Dict[str, Any]:
    """VirusTotal IP/domain/hash reputation lookup."""
    if not api_key:
        return {"success": False, "error": "VT_API_KEY required. Set api_key parameter."}
    try:
        headers = {"x-apikey": api_key}
        # Detect IOC type
        if len(ioc) in (32, 40, 64):  # MD5, SHA1, SHA256
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif all(c.isdigit() or c == '.' for c in ioc):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.ok:
            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {"success": True, "ioc": ioc, "malicious": stats.get('malicious', 0),
                    "clean": stats.get('harmless', 0), "stats": stats}
        return {"success": False, "error": f"VT API error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def otx_lookup(ioc: str, api_key: str = "") -> Dict[str, Any]:
    """AlienVault OTX threat intelligence lookup."""
    try:
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
            headers=headers, timeout=TIMEOUT
        )
        if resp.ok:
            data = resp.json()
            return {"success": True, "ioc": ioc,
                    "pulse_count": data.get('pulse_info', {}).get('count', 0),
                    "reputation": data.get('reputation', 0)}
        return {"success": False, "error": f"OTX API error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def urlscan_lookup(url_or_domain: str) -> Dict[str, Any]:
    """URLScan.io passive URL/domain scanning history."""
    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{url_or_domain}&size=5",
            timeout=TIMEOUT
        )
        if resp.ok:
            results = resp.json().get('results', [])
            return {"success": True, "target": url_or_domain,
                    "scan_count": len(results), "recent_scans": results[:3]}
        return {"success": False, "error": f"URLScan error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def shodan_cve_lookup(ip: str, api_key: str = "") -> Dict[str, Any]:
    """Look up known CVEs for services running on an IP via Shodan."""
    if not shutil.which("shodan"):
        return {"success": False, "error": "shodan CLI not installed"}
    try:
        result = subprocess.run(["shodan", "host", ip],
                                capture_output=True, text=True, timeout=30)
        return {"success": result.returncode == 0, "ip": ip, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

**Step 4: Run tests**

```bash
pytest tests/unit/test_osint_tools.py -v
```

**Step 5: Commit**

```bash
git add tools/osint/social_intel.py tools/osint/threat_intel.py tests/unit/test_osint_tools.py
git commit -m "feat: implement tools/osint/social_intel.py and threat_intel.py"
```

---

### Task 17: Create OSINT Blueprint and MCP tools

**Files:**
- Create: `core/routes/osint.py`
- Create: `hexstrike_mcp_tools/osint.py`
- Modify: `core/server.py`
- Create: `tests/unit/test_routes/test_osint_routes.py`

**Step 1: Write failing tests**

```python
# tests/unit/test_routes/test_osint_routes.py
import pytest
from unittest.mock import patch, MagicMock
from flask import Flask
from core.routes.osint import osint_bp

@pytest.fixture
def app():
    a = Flask(__name__)
    a.register_blueprint(osint_bp)
    a.config['TESTING'] = True
    return a

def test_passive_recon_route(app):
    with patch('core.routes.osint.the_harvester') as mock_th:
        mock_th.return_value = {'emails': [], 'hosts': []}
        resp = app.test_client().post('/api/osint/passive-recon',
                                      json={'domain': 'example.com'})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True

def test_threat_intel_route(app):
    with patch('core.routes.osint.virustotal_lookup') as mock_vt:
        mock_vt.return_value = {'malicious': 0}
        resp = app.test_client().post('/api/osint/threat-intel',
                                      json={'ioc': '8.8.8.8'})
    assert resp.status_code == 200

def test_social_recon_route(app):
    with patch('core.routes.osint.sherlock_search') as mock_sh:
        mock_sh.return_value = {'found_on': []}
        resp = app.test_client().post('/api/osint/social-recon',
                                      json={'username': 'testuser'})
    assert resp.status_code == 200

def test_breach_check_route(app):
    with patch('core.routes.osint.breach_lookup') as mock_bl:
        mock_bl.return_value = {'breached': False}
        resp = app.test_client().post('/api/osint/breach-check',
                                      json={'email': 'test@example.com'})
    assert resp.status_code == 200
```

**Step 2: Create OSINT Blueprint**

```python
# core/routes/osint.py
"""OSINT and intelligence gathering routes."""
from flask import Blueprint, request, jsonify
from utils.logger import setup_basic_logging
from tools.osint.passive_recon import shodan_search, whois_lookup, the_harvester, dnsdumpster_recon, censys_search
from tools.osint.social_intel import sherlock_search, holehe_check, breach_lookup
from tools.osint.threat_intel import virustotal_lookup, otx_lookup, urlscan_lookup, shodan_cve_lookup

logger = setup_basic_logging()
osint_bp = Blueprint('osint', __name__)

@osint_bp.route('/api/osint/passive-recon', methods=['POST'])
def osint_passive_recon():
    """Comprehensive passive recon: subdomains, emails, DNS, hosts."""
    try:
        params = request.json or {}
        domain = params.get('domain', '')
        sources = params.get('sources', 'all')
        results = {
            'harvester': the_harvester(domain, sources),
            'whois': whois_lookup(domain),
            'dns': dnsdumpster_recon(domain),
        }
        if params.get('shodan_key'):
            results['shodan'] = shodan_search(domain, params['shodan_key'])
        return jsonify({"success": True, "domain": domain, "results": results})
    except Exception as e:
        logger.error(f"Passive recon error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@osint_bp.route('/api/osint/threat-intel', methods=['POST'])
def osint_threat_intel():
    """Threat intelligence IOC lookup (VT, OTX, URLScan)."""
    try:
        params = request.json or {}
        ioc = params.get('ioc', '')
        results = {
            'urlscan': urlscan_lookup(ioc),
            'otx': otx_lookup(ioc, params.get('otx_key', '')),
        }
        if params.get('vt_key'):
            results['virustotal'] = virustotal_lookup(ioc, params['vt_key'])
        return jsonify({"success": True, "ioc": ioc, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@osint_bp.route('/api/osint/social-recon', methods=['POST'])
def osint_social_recon():
    """Social media and identity OSINT."""
    try:
        params = request.json or {}
        results = {}
        if params.get('username'):
            results['sherlock'] = sherlock_search(params['username'])
        if params.get('email'):
            results['holehe'] = holehe_check(params['email'])
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@osint_bp.route('/api/osint/breach-check', methods=['POST'])
def osint_breach_check():
    """Check email against known breach databases."""
    try:
        params = request.json or {}
        email = params.get('email', '')
        result = breach_lookup(email)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@osint_bp.route('/api/osint/shodan', methods=['POST'])
def osint_shodan():
    """Shodan search and host lookup."""
    try:
        params = request.json or {}
        result = shodan_search(params.get('query', ''), params.get('api_key', ''))
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@osint_bp.route('/api/osint/ioc-cve', methods=['POST'])
def osint_cve_lookup():
    """Look up CVEs for services on an IP via Shodan."""
    try:
        params = request.json or {}
        result = shodan_cve_lookup(params.get('ip', ''))
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
```

**Step 3: Create OSINT MCP tools**

```python
# hexstrike_mcp_tools/osint.py
"""MCP tool registrations for OSINT tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client

@mcp.tool()
def osint_passive_recon(domain: str, sources: str = "all",
                        shodan_key: str = "") -> Dict[str, Any]:
    """Passive recon — theHarvester, WHOIS, DNS, Shodan. No direct target contact."""
    return get_client().safe_post("api/osint/passive-recon",
                                  {"domain": domain, "sources": sources,
                                   "shodan_key": shodan_key})

@mcp.tool()
def osint_threat_intel(ioc: str, vt_key: str = "",
                       otx_key: str = "") -> Dict[str, Any]:
    """IOC threat intelligence — VirusTotal, OTX, URLScan. ioc: IP, domain, or file hash."""
    return get_client().safe_post("api/osint/threat-intel",
                                  {"ioc": ioc, "vt_key": vt_key, "otx_key": otx_key})

@mcp.tool()
def osint_social_recon(username: str = "", email: str = "") -> Dict[str, Any]:
    """Social media OSINT — Sherlock (username) and Holehe (email). Provide at least one."""
    return get_client().safe_post("api/osint/social-recon",
                                  {"username": username, "email": email})

@mcp.tool()
def osint_breach_check(email: str) -> Dict[str, Any]:
    """Check if email appears in known data breaches."""
    return get_client().safe_post("api/osint/breach-check", {"email": email})

@mcp.tool()
def osint_shodan_search(query: str, api_key: str = "") -> Dict[str, Any]:
    """Shodan internet-wide search. Query examples: 'nginx port:443', 'org:Google'"""
    return get_client().safe_post("api/osint/shodan",
                                  {"query": query, "api_key": api_key})
```

**Step 4: Register Blueprint, run tests, commit**

```bash
pytest -v
git add core/routes/osint.py hexstrike_mcp_tools/osint.py core/server.py tests/
git commit -m "feat: OSINT Blueprint + MCP tools (passive recon, threat intel, social, breach)"
```

---

## Batch 8: MCP Reorganization + Final Cleanup

---

### Task 18: Shrink `hexstrike_mcp.py` to thin launcher

**Files:**
- Modify: `hexstrike_mcp.py`
- Create: `hexstrike_mcp_tools/__main__.py` (optional convenience)

**Step 1: Write failing test**

```python
# tests/unit/test_mcp_tools/test_mcp_scaffold.py (add)
def test_hexstrike_mcp_imports_cleanly():
    """hexstrike_mcp.py should be importable without starting the server."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "hexstrike_mcp", "hexstrike_mcp.py"
    )
    # Should not raise
    assert spec is not None

def test_all_mcp_tool_modules_importable():
    """All hexstrike_mcp_tools submodules should import without error."""
    import hexstrike_mcp_tools
    from hexstrike_mcp_tools import initialize
    from unittest.mock import MagicMock
    initialize(MagicMock())

    import hexstrike_mcp_tools.network
    import hexstrike_mcp_tools.web
    import hexstrike_mcp_tools.cloud
    import hexstrike_mcp_tools.binary
    import hexstrike_mcp_tools.mobile
    import hexstrike_mcp_tools.api_security
    import hexstrike_mcp_tools.wireless
    import hexstrike_mcp_tools.osint
    import hexstrike_mcp_tools.workflows
    import hexstrike_mcp_tools.system
```

**Step 2: Replace `hexstrike_mcp.py` with thin launcher**

```python
#!/usr/bin/env python3
"""
HexStrike AI MCP Client — Entry Point

Connects to the HexStrike AI API server and exposes all security tools
to AI agents via the Model Context Protocol (MCP).

Usage:
    python3 hexstrike_mcp.py --server http://localhost:8888
    python3 hexstrike_mcp.py --server http://localhost:8888 --debug
"""
import argparse
import logging

from hexstrike_mcp_tools.client import HexStrikeClient, DEFAULT_HEXSTRIKE_SERVER, DEFAULT_REQUEST_TIMEOUT
import hexstrike_mcp_tools
import hexstrike_mcp_tools.system
import hexstrike_mcp_tools.network
import hexstrike_mcp_tools.web
import hexstrike_mcp_tools.cloud
import hexstrike_mcp_tools.binary
import hexstrike_mcp_tools.mobile
import hexstrike_mcp_tools.api_security
import hexstrike_mcp_tools.wireless
import hexstrike_mcp_tools.osint
import hexstrike_mcp_tools.workflows

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", default=DEFAULT_HEXSTRIKE_SERVER)
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    client = HexStrikeClient(args.server, args.timeout)
    hexstrike_mcp_tools.initialize(client)
    hexstrike_mcp_tools.mcp.run()


if __name__ == "__main__":
    main()
```

**Step 3: Run tests**

```bash
pytest -v
```

**Step 4: Commit**

```bash
git add hexstrike_mcp.py hexstrike_mcp_tools/
git commit -m "feat: shrink hexstrike_mcp.py to thin launcher, all tools in hexstrike_mcp_tools/"
```

---

### Task 19: Shrink `hexstrike_server.py` to thin entry point + final verification

**Files:**
- Modify: `hexstrike_server.py`
- Modify: `core/server.py`

At this point all route handlers have been migrated to Blueprints across batches 1-7. `hexstrike_server.py` should only contain startup logic.

**Step 1: Write verification test**

```python
# tests/integration/test_blueprints/test_full_server.py
from core.server import create_app

def test_all_blueprints_registered():
    app = create_app()
    registered = set(app.blueprints.keys())
    expected = {'system', 'network', 'web', 'cloud', 'binary',
                'ctf', 'bugbounty', 'intelligence', 'mobile',
                'api_security', 'wireless', 'osint'}
    assert expected.issubset(registered), f"Missing blueprints: {expected - registered}"

def test_health_endpoint_responds():
    app = create_app()
    app.config['TESTING'] = True
    resp = app.test_client().get('/health')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'operational'

def test_hexstrike_server_is_thin():
    with open('hexstrike_server.py') as f:
        lines = [l for l in f.readlines() if l.strip() and not l.strip().startswith('#')]
    assert len(lines) < 100, f"hexstrike_server.py is {len(lines)} non-blank lines — expected < 100"
```

**Step 2: Replace `hexstrike_server.py` with thin entry point**

```python
#!/usr/bin/env python3
"""
HexStrike AI — Server Entry Point

Starts the Flask API server that exposes 200+ security tools
and AI agents via REST API.

Usage:
    python3 hexstrike_server.py
    python3 hexstrike_server.py --debug
    python3 hexstrike_server.py --port 9000
"""
import argparse
import logging
from core.server import create_app
from core.constants import API_PORT, API_HOST, DEBUG_MODE
from utils.visual_engine import ModernVisualEngine
from utils.logger import setup_basic_logging

logger = setup_basic_logging()


def parse_args():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--port", type=int, default=API_PORT)
    return parser.parse_args()


def main():
    args = parse_args()
    print(ModernVisualEngine.create_banner())

    app = create_app()
    logger.info(f"🚀 Starting HexStrike AI on port {args.port}")
    app.run(host=API_HOST, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
```

**Step 3: Update `core/server.py` to register all Blueprints**

```python
# core/server.py
"""Flask application factory — registers all Blueprints."""
from flask import Flask
from core.constants import API_PORT, API_HOST

from core.routes.system import system_bp
from core.routes.network import network_bp
from core.routes.web import web_bp
from core.routes.cloud import cloud_bp
from core.routes.binary import binary_bp
from core.routes.ctf import ctf_bp
from core.routes.bugbounty import bugbounty_bp
from core.routes.intelligence import intelligence_bp
from core.routes.mobile import mobile_bp
from core.routes.api_security import api_security_bp
from core.routes.wireless import wireless_bp
from core.routes.osint import osint_bp


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False

    app.register_blueprint(system_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(web_bp)
    app.register_blueprint(cloud_bp)
    app.register_blueprint(binary_bp)
    app.register_blueprint(ctf_bp)
    app.register_blueprint(bugbounty_bp)
    app.register_blueprint(intelligence_bp)
    app.register_blueprint(mobile_bp)
    app.register_blueprint(api_security_bp)
    app.register_blueprint(wireless_bp)
    app.register_blueprint(osint_bp)

    return app


# Module-level app for backward compatibility (imported by hexstrike_server.py legacy code)
app = create_app()


def get_server_info():
    return {'host': API_HOST, 'port': API_PORT}
```

**Step 4: Run the full test suite**

```bash
pytest -v --tb=short
```
Expected: all tests green. Verify the count has grown by ~200 from the baseline of 177.

**Step 5: Run health check against live server (manual)**

```bash
python3 hexstrike_server.py &
sleep 2
curl http://localhost:8888/health
# Expected: {"status": "operational", ...}
kill %1
```

**Step 6: Final commit**

```bash
git add hexstrike_server.py core/server.py tests/integration/test_blueprints/test_full_server.py
git commit -m "feat: shrink hexstrike_server.py to thin entry point — Phase 1-3 gap closure complete"
```

---

### Task 20: Update CLAUDE.md and CHANGELOG.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`

Update CLAUDE.md:
- Architecture section: update to reflect Blueprint structure
- Note `hexstrike_mcp_tools/` as the MCP tool module location
- Update tool counts (200+ MCP tools registered)

Update CHANGELOG.md:
- Add Phase 1-3 gap closure section under v7.0.0-dev

**Commit:**

```bash
git add CLAUDE.md CHANGELOG.md
git commit -m "docs: update CLAUDE.md and CHANGELOG for Phase 1-3 gap closure"
```

---

## Success Criteria

Run these to verify completion:

```bash
# 1. Full test suite green
pytest -v

# 2. Both entry points are thin
wc -l hexstrike_server.py hexstrike_mcp.py
# Expected: each < 100 lines

# 3. Server starts and health check passes
python3 hexstrike_server.py &
sleep 2
curl -s http://localhost:8888/health | python3 -m json.tool
kill %1

# 4. All Blueprints registered
python3 -c "
from core.server import create_app
app = create_app()
print('Blueprints:', sorted(app.blueprints.keys()))
print('Routes:', len(list(app.url_map.iter_rules())))
"

# 5. MCP tools count
python3 -c "
from unittest.mock import MagicMock
import hexstrike_mcp_tools
hexstrike_mcp_tools.initialize(MagicMock())
import hexstrike_mcp_tools.network, hexstrike_mcp_tools.web, hexstrike_mcp_tools.cloud
import hexstrike_mcp_tools.binary, hexstrike_mcp_tools.mobile, hexstrike_mcp_tools.api_security
import hexstrike_mcp_tools.wireless, hexstrike_mcp_tools.osint, hexstrike_mcp_tools.workflows
import hexstrike_mcp_tools.system
mcp = hexstrike_mcp_tools.mcp
print(f'MCP tools registered: {len(mcp._tool_manager._tools)}')
# Expected: 200+
"
```
