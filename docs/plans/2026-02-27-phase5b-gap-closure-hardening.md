# Phase 5b: Gap Closure & Hardening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close critical security gaps (API auth, rate limiting, input validation), clean up stubs and dead code, fill MCP tool coverage holes, and add unit tests for untested agents.

**Architecture:** Flask `@before_request` middleware for auth/rate limiting, `core/validation.py` for shared target validation, real subprocess calls replacing stub intelligence endpoints, 19 new MCP tool wrappers following existing `@mcp.tool()` + `safe_post()` pattern, and pytest unit tests with mocked externals.

**Tech Stack:** Flask, flask-limiter, pytest, requests (for payload tester), subprocess (for searchsploit)

---

## Batch A: Security Hardening (Tasks 1–8)

### Task 1: API Key Auth Middleware — Test

**Files:**
- Create: `tests/unit/test_auth_middleware.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_auth_middleware.py
"""Tests for API key authentication middleware."""
import os
import pytest
from core.server import create_app


@pytest.fixture
def app_with_auth(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_API_KEY", "test-secret-key-123")
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def app_no_auth(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)
    app = create_app()
    app.config["TESTING"] = True
    return app


def test_request_without_key_returns_401(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/api/telemetry")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error"] == "Missing or invalid API key"


def test_request_with_correct_key_returns_200(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/api/telemetry", headers={"X-API-Key": "test-secret-key-123"})
        assert resp.status_code == 200


def test_request_with_wrong_key_returns_401(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/api/telemetry", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401


def test_health_endpoint_bypasses_auth(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/health")
        assert resp.status_code == 200


def test_no_api_key_env_allows_all_requests(app_no_auth):
    """Dev mode: if HEXSTRIKE_API_KEY is not set, all requests pass through."""
    with app_no_auth.test_client() as c:
        resp = c.get("/api/telemetry")
        assert resp.status_code == 200
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_auth_middleware.py -v`
Expected: PASS on health and dev-mode tests (no middleware yet), FAIL on 401 tests

### Task 2: API Key Auth Middleware — Implementation

**Files:**
- Create: `core/auth.py`
- Modify: `core/server.py:13-60` (add auth registration in `create_app()`)

**Step 3: Write implementation**

```python
# core/auth.py
"""API key authentication middleware."""
import logging
import os

from flask import request, jsonify

logger = logging.getLogger(__name__)

# Endpoints that bypass auth (exact match)
_PUBLIC_ENDPOINTS = frozenset({"/health"})


def register_auth(app):
    """Register @before_request API key check on *app*.

    If HEXSTRIKE_API_KEY is not set, auth is disabled (dev mode).
    """
    api_key = os.environ.get("HEXSTRIKE_API_KEY")

    if not api_key:
        logger.warning("HEXSTRIKE_API_KEY not set — auth disabled (dev mode)")
        return

    @app.before_request
    def _check_api_key():
        if request.path in _PUBLIC_ENDPOINTS:
            return None
        supplied = request.headers.get("X-API-Key", "")
        if supplied != api_key:
            return jsonify({"success": False, "error": "Missing or invalid API key"}), 401
```

Add to `core/server.py` inside `create_app()`, after Blueprint registration:

```python
    from core.auth import register_auth
    register_auth(flask_app)
```

**Step 4: Run tests to verify all pass**

Run: `pytest tests/unit/test_auth_middleware.py -v`
Expected: 5 PASS

**Step 5: Commit**

```bash
git add core/auth.py tests/unit/test_auth_middleware.py core/server.py
git commit -m "feat(auth): add API key middleware with dev-mode bypass (Phase 5b, Tasks 1-2)"
```

---

### Task 3: Rate Limiting — Test

**Files:**
- Create: `tests/unit/test_rate_limiter.py`
- Modify: `requirements.txt` (add flask-limiter)

**Step 1: Add dependency**

Add to `requirements.txt`:
```
flask-limiter>=3.5.0
```

**Step 2: Write the failing tests**

```python
# tests/unit/test_rate_limiter.py
"""Tests for rate limiting middleware."""
import pytest
from core.server import create_app


@pytest.fixture
def app():
    a = create_app()
    a.config["TESTING"] = True
    return a


def test_rate_limit_returns_429_when_exceeded(app):
    with app.test_client() as c:
        # /api/command has 10/minute limit
        for _ in range(11):
            resp = c.post("/api/command", json={"command": "echo hi"})
        assert resp.status_code == 429


def test_health_not_rate_limited(app):
    with app.test_client() as c:
        for _ in range(200):
            resp = c.get("/health")
        assert resp.status_code == 200
```

**Step 3: Run tests to verify they fail**

Run: `pytest tests/unit/test_rate_limiter.py -v`
Expected: FAIL (no rate limiter registered yet)

### Task 4: Rate Limiting — Implementation

**Files:**
- Create: `core/rate_limit.py`
- Modify: `core/server.py` (register limiter in `create_app()`)

**Step 4: Write implementation**

```python
# core/rate_limit.py
"""Rate limiting middleware via flask-limiter."""
import logging

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)


def register_rate_limiter(app):
    """Register rate limits on *app*."""
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["60/minute"],
        storage_uri="memory://",
    )

    # Stricter limit on arbitrary command execution
    limiter.limit("10/minute")(app.view_functions.get("system.run_command"))

    # Exempt health endpoint
    limiter.exempt(app.view_functions.get("system.health_check"))

    logger.info("Rate limiter registered: 60/min default, 10/min for /api/command")
    return limiter
```

Add to `core/server.py` inside `create_app()`, after auth registration:

```python
    from core.rate_limit import register_rate_limiter
    register_rate_limiter(flask_app)
```

**Step 5: Run tests to verify all pass**

Run: `pytest tests/unit/test_rate_limiter.py -v`
Expected: 2 PASS

**Step 6: Commit**

```bash
git add core/rate_limit.py tests/unit/test_rate_limiter.py core/server.py requirements.txt
git commit -m "feat(auth): add rate limiting — 60/min default, 10/min for /api/command (Phase 5b, Tasks 3-4)"
```

---

### Task 5: Input Validation — Test

**Files:**
- Create: `core/validation.py`
- Create: `tests/unit/test_validation.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_validation.py
"""Tests for target input validation."""
from core.validation import is_valid_target


def test_valid_ipv4():
    assert is_valid_target("192.168.1.1") is True

def test_valid_ipv6():
    assert is_valid_target("::1") is True

def test_valid_domain():
    assert is_valid_target("example.com") is True

def test_valid_subdomain():
    assert is_valid_target("sub.example.com") is True

def test_valid_cidr():
    assert is_valid_target("10.0.0.0/24") is True

def test_valid_url():
    assert is_valid_target("https://example.com/path") is True

def test_empty_string():
    assert is_valid_target("") is False

def test_shell_metachar_semicolon():
    assert is_valid_target("example.com; rm -rf /") is False

def test_shell_metachar_pipe():
    assert is_valid_target("example.com | cat /etc/passwd") is False

def test_shell_metachar_backtick():
    assert is_valid_target("`whoami`.example.com") is False

def test_shell_metachar_dollar():
    assert is_valid_target("$(whoami).example.com") is False

def test_newline_injection():
    assert is_valid_target("example.com\nid") is False
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_validation.py -v`
Expected: FAIL (module doesn't exist)

### Task 6: Input Validation — Implementation

**Step 3: Write implementation**

```python
# core/validation.py
"""Shared input validation for target parameters."""
from __future__ import annotations

import ipaddress
import re

# Shell metacharacters that should never appear in a target string
_SHELL_METACHARS = re.compile(r"[;|&`$\n\r]")

# Loose domain regex: labels separated by dots, optional trailing port
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?::\d{1,5})?$"
)

# URL with scheme
_URL_RE = re.compile(r"^https?://\S+$")


def is_valid_target(target: str) -> bool:
    """Return True if *target* looks like a valid IP, domain, CIDR, or URL.

    Rejects empty strings and strings containing shell metacharacters.
    """
    if not target or not target.strip():
        return False

    target = target.strip()

    if _SHELL_METACHARS.search(target):
        return False

    # URL
    if _URL_RE.match(target):
        return True

    # CIDR
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass

    # IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Domain
    if _DOMAIN_RE.match(target):
        return True

    return False
```

**Step 4: Run tests to verify all pass**

Run: `pytest tests/unit/test_validation.py -v`
Expected: 13 PASS

**Step 5: Commit**

```bash
git add core/validation.py tests/unit/test_validation.py
git commit -m "feat(auth): add target input validation utility (Phase 5b, Tasks 5-6)"
```

---

### Task 7: Wire Validation Into Routes

**Files:**
- Modify: `core/routes/network.py` (add validation to routes that take `target`)
- Modify: `core/routes/web.py` (same)

**Step 1: Add validation import and check to the first route handler in each Blueprint**

In `core/routes/network.py`, add near the top (after existing imports):
```python
from core.validation import is_valid_target
```

Then in each route handler that reads `target`, add after the empty-check:
```python
    if not is_valid_target(target):
        return jsonify({"success": False, "error": "Invalid target format"}), 400
```

Apply to: `network.py` and `web.py` route handlers that construct subprocess commands from `target`.

Do NOT apply to: intelligence routes (which take software names, not network targets), browser routes (which take URLs and already validate scheme).

**Step 2: Run full test suite**

Run: `pytest tests/ -q`
Expected: All pass (existing route tests use valid targets like "192.168.1.1" and "example.com")

**Step 3: Commit**

```bash
git add core/routes/network.py core/routes/web.py
git commit -m "feat(auth): wire target validation into network and web routes (Phase 5b, Task 7)"
```

---

### Task 8: MCP Client Auth Header

**Files:**
- Modify: `hexstrike_mcp_tools/client.py:21-31` (add API key header to session)
- Create: `tests/unit/test_mcp_client_auth.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_mcp_client_auth.py
"""Tests for MCP client API key header."""
import os
from unittest.mock import patch, MagicMock


def test_client_sends_api_key_header(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_API_KEY", "my-secret")
    # Prevent actual connection attempt
    with patch("hexstrike_mcp_tools.client.requests.Session") as MockSession:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_resp.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_resp
        mock_session.post.return_value = mock_resp
        MockSession.return_value = mock_session

        from importlib import reload
        import hexstrike_mcp_tools.client as client_mod
        reload(client_mod)

        c = client_mod.HexStrikeClient("http://127.0.0.1:8888")
        # Verify the session has the API key header
        mock_session.headers.update.assert_any_call({"X-API-Key": "my-secret"})


def test_client_no_api_key_no_header(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)
    with patch("hexstrike_mcp_tools.client.requests.Session") as MockSession:
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "ok"}
        mock_resp.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_resp
        MockSession.return_value = mock_session

        from importlib import reload
        import hexstrike_mcp_tools.client as client_mod
        reload(client_mod)

        c = client_mod.HexStrikeClient("http://127.0.0.1:8888")
        # No API key header call expected
        if mock_session.headers.update.called:
            for call in mock_session.headers.update.call_args_list:
                assert "X-API-Key" not in call[0][0]
```

**Step 2: Modify `hexstrike_mcp_tools/client.py`**

In `__init__`, after `self.session = requests.Session()`, add:

```python
        # Wire API key if configured
        api_key = os.environ.get("HEXSTRIKE_API_KEY")
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})
```

Add `import os` to the imports.

**Step 3: Run tests**

Run: `pytest tests/unit/test_mcp_client_auth.py tests/unit/test_auth_middleware.py -v`
Expected: All PASS

**Step 4: Commit**

```bash
git add hexstrike_mcp_tools/client.py tests/unit/test_mcp_client_auth.py
git commit -m "feat(auth): wire API key header into MCP client session (Phase 5b, Task 8)"
```

---

## Batch B: Stubs & Dead Code Cleanup (Tasks 9–17)

### Task 9: Exploit Generator — Real searchsploit

**Files:**
- Modify: `core/routes/intelligence.py:58-72` (replace `_SimpleExploitGenerator`)
- Create: `tests/unit/test_routes/test_intelligence_routes.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_routes/test_intelligence_routes.py
"""Tests for intelligence Blueprint routes."""
import json
from unittest.mock import patch, MagicMock
import pytest
from core.server import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestExploitGenerator:
    def test_exploit_lookup_with_searchsploit(self, client):
        fake_output = json.dumps({
            "RESULTS_EXPLOIT": [
                {"Title": "Apache 2.4.49 - RCE", "EDB-ID": "50383", "Path": "/usr/share/exploitdb/exploits/linux/remote/50383.py"}
            ]
        })
        with patch("core.routes.intelligence.subprocess") as mock_sub:
            mock_sub.run.return_value = MagicMock(
                returncode=0, stdout=fake_output, stderr=""
            )
            mock_sub.TimeoutExpired = TimeoutError
            resp = client.post("/api/intelligence/generate-exploit", json={
                "cve_data": {"cve_id": "CVE-2021-41773"},
                "target_info": {"exploit_type": "poc"},
            })
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert len(data["exploits"]) >= 1
            assert "50383" in data["exploits"][0]["edb_id"]

    def test_exploit_lookup_searchsploit_missing(self, client):
        with patch("core.routes.intelligence.shutil") as mock_shutil:
            mock_shutil.which.return_value = None
            resp = client.post("/api/intelligence/generate-exploit", json={
                "cve_data": {"cve_id": "CVE-2021-41773"},
                "target_info": {},
            })
            data = resp.get_json()
            assert data["success"] is False
            assert "searchsploit" in data["error"]
```

**Step 2: Replace `_SimpleExploitGenerator`**

Replace the class body in `core/routes/intelligence.py:58-72` with a real `searchsploit` subprocess call:

```python
import shutil
import subprocess

class _SimpleExploitGenerator:
    """Exploit lookup via searchsploit (exploitdb)."""

    def generate_exploit_from_cve(
        self, cve_data: Dict[str, Any], target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        cve_id = cve_data.get("cve_id", "")
        if not cve_id:
            return {"success": False, "error": "cve_id is required"}

        if not shutil.which("searchsploit"):
            return {"success": False, "error": "searchsploit not installed"}

        try:
            result = subprocess.run(
                ["searchsploit", "--cve", cve_id, "--json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return {"success": True, "exploits": [], "note": "No exploits found"}

            import json as _json
            data = _json.loads(result.stdout)
            exploits = [
                {
                    "edb_id": e.get("EDB-ID", ""),
                    "title": e.get("Title", ""),
                    "path": e.get("Path", ""),
                }
                for e in data.get("RESULTS_EXPLOIT", [])
            ]
            return {"success": True, "exploits": exploits, "cve_id": cve_id}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "searchsploit timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
```

**Step 3: Run tests**

Run: `pytest tests/unit/test_routes/test_intelligence_routes.py -v`
Expected: 2 PASS

**Step 4: Commit**

```bash
git add core/routes/intelligence.py tests/unit/test_routes/test_intelligence_routes.py
git commit -m "feat(intel): wire searchsploit for real exploit lookup (Phase 5b, Task 9)"
```

---

### Task 10: Payload Tester — Real HTTP Requests

**Files:**
- Modify: `core/routes/intelligence.py:810-848` (replace `ai_test_payload`)
- Add tests to: `tests/unit/test_routes/test_intelligence_routes.py`

**Step 1: Write the failing tests**

Add to `test_intelligence_routes.py`:

```python
class TestPayloadTester:
    def test_payload_test_sends_real_request(self, client):
        with patch("core.routes.intelligence.requests") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.text = "<html>alert(1)</html>"
            mock_req.request.return_value = mock_resp
            mock_req.RequestException = Exception

            resp = client.post("/api/ai/test_payload", json={
                "payload": "<script>alert(1)</script>",
                "target_url": "http://testsite.com/search?q=",
                "method": "GET",
            })
            data = resp.get_json()
            assert data["success"] is True
            assert data["test_result"]["status_code"] == 200
            assert data["test_result"]["reflection_detected"] is True

    def test_payload_test_detects_waf(self, client):
        with patch("core.routes.intelligence.requests") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.headers = {"CF-Ray": "abc123", "Server": "cloudflare"}
            mock_resp.text = "Access denied"
            mock_req.request.return_value = mock_resp
            mock_req.RequestException = Exception

            resp = client.post("/api/ai/test_payload", json={
                "payload": "' OR 1=1--",
                "target_url": "http://testsite.com/login",
                "method": "POST",
            })
            data = resp.get_json()
            assert data["test_result"]["waf_detected"] is True
```

**Step 2: Replace `ai_test_payload` route body**

Replace lines 810-848 with a real HTTP request implementation that:
- Sends `requests.request(method, target_url, params/data containing payload, timeout=10)`
- Captures status_code, first 2KB of response body, response headers
- Checks if payload string appears in response body (`reflection_detected`)
- Checks for WAF headers: CF-Ray, X-WAF, Server: cloudflare/akamai/imperva (`waf_detected`)
- Returns structured result with all findings

**Step 3: Run tests and commit**

Run: `pytest tests/unit/test_routes/test_intelligence_routes.py -v`

```bash
git add core/routes/intelligence.py tests/unit/test_routes/test_intelligence_routes.py
git commit -m "feat(intel): wire real HTTP requests for payload testing (Phase 5b, Task 10)"
```

---

### Task 11: Remove Zero-Day Research Endpoint

**Files:**
- Modify: `core/routes/intelligence.py:648-776` (delete `zero_day_research` route)

**Step 1: Delete the `zero_day_research` function**

Remove the entire route handler from line 648 (`@intelligence_bp.route("/api/vuln-intel/zero-day-research"...`) through line 776 (end of function).

**Step 2: Run full test suite to verify no regressions**

Run: `pytest tests/ -q`
Expected: All pass (no existing test calls this endpoint)

**Step 3: Commit**

```bash
git add core/routes/intelligence.py
git commit -m "fix(intel): remove fake zero-day research endpoint (Phase 5b, Task 11)"
```

---

### Task 12: Fix Vulnerability Correlator

**Files:**
- Modify: `core/routes/intelligence.py:79-109` (`_SimpleVulnerabilityCorrelator`)

**Step 1: Replace hardcoded data with NVD-based lookup**

Wire `_SimpleVulnerabilityCorrelator.find_attack_chains()` to use `cve_intelligence.py` for real CVE data lookup by software keyword. If `CVEIntelligenceManager` is not available, return `{"success": False, "error": "CVE intelligence not available"}` instead of fake data.

**Step 2: Run tests and commit**

```bash
git add core/routes/intelligence.py
git commit -m "feat(intel): wire vulnerability correlator to NVD API (Phase 5b, Task 12)"
```

---

### Task 13: Proxy Provider — Real Implementation

**Files:**
- Modify: `agents/proxy_provider.py`
- Create: `tests/unit/test_proxy_provider_v2.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_proxy_provider_v2.py
"""Tests for round-robin proxy provider."""
from agents.proxy_provider import ProxyProvider


def test_empty_proxy_list():
    p = ProxyProvider()
    assert p.get_proxy() is None


def test_round_robin_rotation():
    proxies = [
        {"http": "http://proxy1:8080", "https": "http://proxy1:8080"},
        {"http": "http://proxy2:8080", "https": "http://proxy2:8080"},
    ]
    p = ProxyProvider(proxies=proxies)
    assert p.get_proxy() == proxies[0]
    p.rotate()
    assert p.get_proxy() == proxies[1]
    p.rotate()
    assert p.get_proxy() == proxies[0]  # wraps around


def test_from_env(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_PROXIES", "http://p1:8080,http://p2:8080")
    p = ProxyProvider.from_env()
    assert p.get_proxy() is not None
    assert "p1" in p.get_proxy()["http"]


def test_from_env_empty(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_PROXIES", raising=False)
    p = ProxyProvider.from_env()
    assert p.get_proxy() is None
```

**Step 2: Implement**

```python
# agents/proxy_provider.py
"""ProxyProvider: round-robin proxy rotation."""
from __future__ import annotations

import os
from typing import List, Optional


class ProxyProvider:
    """Rotate through a list of proxy dicts in round-robin order."""

    def __init__(self, proxies: Optional[List[dict]] = None):
        self._proxies = proxies or []
        self._index = 0

    def get_proxy(self) -> Optional[dict]:
        if not self._proxies:
            return None
        return self._proxies[self._index % len(self._proxies)]

    def rotate(self) -> None:
        if self._proxies:
            self._index = (self._index + 1) % len(self._proxies)

    @classmethod
    def from_env(cls) -> "ProxyProvider":
        raw = os.environ.get("HEXSTRIKE_PROXIES", "")
        if not raw.strip():
            return cls()
        urls = [u.strip() for u in raw.split(",") if u.strip()]
        proxies = [{"http": u, "https": u} for u in urls]
        return cls(proxies=proxies)
```

**Step 3: Run tests and commit**

Run: `pytest tests/unit/test_proxy_provider_v2.py -v`

```bash
git add agents/proxy_provider.py tests/unit/test_proxy_provider_v2.py
# Delete old test if it conflicts
git add tests/unit/test_proxy_provider.py
git commit -m "feat(proxy): implement round-robin ProxyProvider (Phase 5b, Task 13)"
```

---

### Task 14: Decision Engine — Remove Dead Code

**Files:**
- Modify: `agents/decision_engine.py:446-456`

**Step 1: Remove the broken `_use_advanced_optimizer` code path**

Replace lines 446-456:

```python
    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Parameter optimization per tool."""
        if context is None:
            context = {}

        optimized_params = {}

        if tool == "nmap":
```

(Remove the `_use_advanced_optimizer` check and `parameter_optimizer` reference entirely.)

Also remove the `engine._use_advanced_optimizer = False` line from `core/routes/intelligence.py:42` since the attribute no longer exists.

**Step 2: Run tests and commit**

Run: `pytest tests/ -q`

```bash
git add agents/decision_engine.py core/routes/intelligence.py
git commit -m "fix: remove broken parameter_optimizer reference from decision engine (Phase 5b, Task 14)"
```

---

### Task 15: File Manager — Audit & Cleanup

**Files:**
- Modify: `managers/file_manager.py`

**Step 1: Audit orphaned routes**

Read `managers/file_manager.py` and identify all `@app.route(...)` decorators. These reference a dead `app` object that doesn't exist in the Blueprint architecture.

**Step 2: Delete orphaned route functions**

Remove all functions decorated with `@app.route(...)` since they are dead code. Keep the utility methods (file operations, artifact handling) that are imported and used elsewhere.

If NO functions are used elsewhere, note that in the commit and consider removing the entire file in a future cleanup.

**Step 3: Run tests and commit**

Run: `pytest tests/ -q`

```bash
git add managers/file_manager.py
git commit -m "fix: remove orphaned @app.route decorators from file_manager.py (Phase 5b, Task 15)"
```

---

### Task 16: Wire Tool `__init__.py` Files

**Files:**
- Modify: `tools/network/__init__.py`
- Modify: `tools/web/__init__.py`
- Modify: `tools/binary/__init__.py`
- Modify: `tools/cloud/__init__.py`

**Step 1: Add imports to each `__init__.py`**

For each category, inspect the submodules and import their public functions. Example for `tools/network/__init__.py`:

```python
# tools/network/__init__.py
"""Network security tools."""
try:
    from tools.network.nmap_tools import *
except ImportError:
    pass
try:
    from tools.network.recon_tools import *
except ImportError:
    pass
# ... repeat for each submodule in the directory
```

Use `try/except ImportError` guards so missing optional dependencies don't break the package.

Repeat for web, binary, cloud.

**Step 2: Run tests and commit**

Run: `pytest tests/ -q`

```bash
git add tools/network/__init__.py tools/web/__init__.py tools/binary/__init__.py tools/cloud/__init__.py
git commit -m "feat: wire tool __init__.py exports for network, web, binary, cloud (Phase 5b, Task 16)"
```

---

### Task 17: Batch B Verification

**Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: All pass, no regressions

**Step 2: Verify stubs are gone**

```bash
python3 -c "
from core.routes.intelligence import _exploit_generator
result = _exploit_generator.generate_exploit_from_cve({'cve_id': 'CVE-2021-41773'}, {})
print(result)
# Should NOT contain 'Placeholder PoC'
assert 'Placeholder' not in str(result), 'Stub still present!'
print('OK: exploit generator is real')
"
```

---

## Batch C: MCP Tool Gap Closure (Tasks 18–22)

### Task 18: Network MCP Tools (9 tools)

**Files:**
- Modify: `hexstrike_mcp_tools/network.py` (append 9 new tool functions)
- Create: `tests/unit/test_mcp_tools/test_network_mcp_gap.py`

**Step 1: Write tests**

```python
# tests/unit/test_mcp_tools/test_network_mcp_gap.py
"""Tests for new network MCP tool wrappers."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize


def setup_mock():
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)
    return mock


def test_nmap_advanced_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import nmap_advanced_scan
    nmap_advanced_scan("10.0.0.1")
    m.safe_post.assert_called()
    assert "/api/tools/nmap-advanced" in m.safe_post.call_args[0][0]


def test_fierce_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import fierce_scan
    fierce_scan("example.com")
    assert "/api/tools/fierce" in m.safe_post.call_args[0][0]


def test_autorecon_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import autorecon_scan
    autorecon_scan("10.0.0.1")
    assert "/api/tools/autorecon" in m.safe_post.call_args[0][0]


def test_nbtscan_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import nbtscan_scan
    nbtscan_scan("10.0.0.0/24")
    assert "/api/tools/nbtscan" in m.safe_post.call_args[0][0]


def test_scapy_probe():
    m = setup_mock()
    from hexstrike_mcp_tools.network import scapy_probe
    scapy_probe("10.0.0.1")
    assert "/api/tools/network/scapy" in m.safe_post.call_args[0][0]


def test_ipv6_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import ipv6_scan
    ipv6_scan("::1")
    assert "/api/tools/network/ipv6-toolkit" in m.safe_post.call_args[0][0]


def test_udp_proto_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import udp_proto_scan
    udp_proto_scan("10.0.0.1")
    assert "/api/tools/network/udp-proto-scanner" in m.safe_post.call_args[0][0]


def test_cisco_torch_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import cisco_torch_scan
    cisco_torch_scan("10.0.0.1")
    assert "/api/tools/network/cisco-torch" in m.safe_post.call_args[0][0]


def test_enum4linux_ng_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import enum4linux_ng_scan
    enum4linux_ng_scan("10.0.0.1")
    assert "/api/tools/enum4linux-ng" in m.safe_post.call_args[0][0]
```

**Step 2: Implement 9 MCP tool wrappers**

Append to `hexstrike_mcp_tools/network.py`, following the existing pattern:

```python
@mcp.tool()
def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "",
                       timing: str = "T4", nse_scripts: str = "",
                       os_detection: bool = False, version_detection: bool = False,
                       aggressive: bool = False, stealth: bool = False) -> str:
    """Advanced nmap scan with NSE scripts, timing, OS/version detection."""
    return get_client().safe_post("/api/tools/nmap-advanced", {
        "target": target, "scan_type": scan_type, "ports": ports,
        "timing": timing, "nse_scripts": nse_scripts,
        "os_detection": os_detection, "version_detection": version_detection,
        "aggressive": aggressive, "stealth": stealth,
    })
```

Repeat for each of the 9 tools, matching the route params from `core/routes/network.py`.

**Step 3: Run tests and commit**

Run: `pytest tests/unit/test_mcp_tools/test_network_mcp_gap.py -v`

```bash
git add hexstrike_mcp_tools/network.py tests/unit/test_mcp_tools/test_network_mcp_gap.py
git commit -m "feat(mcp): add 9 missing network MCP tool wrappers (Phase 5b, Task 18)"
```

---

### Task 19: Binary MCP Tools (4 tools)

**Files:**
- Modify: `hexstrike_mcp_tools/binary.py`
- Create: `tests/unit/test_mcp_tools/test_binary_mcp_gap.py`

Same pattern as Task 18. Add 4 tools: `rizin_analyze`, `yara_scan`, `floss_analyze`, `forensics_analyze`.

Match route params from `core/routes/binary.py:387-540`.

**Commit:**

```bash
git commit -m "feat(mcp): add 4 missing binary MCP tool wrappers (Phase 5b, Task 19)"
```

---

### Task 20: Cloud MCP Tools (3 tools)

**Files:**
- Modify: `hexstrike_mcp_tools/cloud.py`
- Create: `tests/unit/test_mcp_tools/test_cloud_mcp_gap.py`

Add 3 tools: `kubescape_scan`, `container_escape_check`, `rbac_audit`.

Match route params from `core/routes/cloud.py:324-430`.

**Commit:**

```bash
git commit -m "feat(mcp): add 3 missing cloud MCP tool wrappers (Phase 5b, Task 20)"
```

---

### Task 21: System + Workflow MCP Tools (3 tools)

**Files:**
- Modify: `hexstrike_mcp_tools/system.py`
- Modify: `hexstrike_mcp_tools/workflows.py`
- Create: `tests/unit/test_mcp_tools/test_system_mcp_gap.py`

Add to system.py: `get_telemetry` (GET), `clear_cache` (POST).
Add to workflows.py: `optimize_tool_parameters` (POST).

Note: `get_telemetry` and `clear_cache` use GET/POST — use `get_client().safe_get()` for GET routes.

**Commit:**

```bash
git commit -m "feat(mcp): add system + workflow MCP tool wrappers (Phase 5b, Task 21)"
```

---

### Task 22: MCP Gap Verification

**Step 1: Run all MCP tests**

Run: `pytest tests/unit/test_mcp_tools/ -v`

**Step 2: Count total MCP tools**

```bash
python3 -c "
import hexstrike_mcp_tools
from hexstrike_mcp_tools import mcp
tools = [t for t in dir(mcp) if not t.startswith('_')]
print(f'Total MCP tools registered: check hexstrike_mcp.py imports')
"
```

**Step 3: Commit verification**

```bash
git commit --allow-empty -m "chore: Batch C complete — 19 MCP tool wrappers added (Phase 5b)"
```

---

## Batch D: Test Coverage (Tasks 23–30)

### Task 23: Decision Engine Tests

**Files:**
- Create: `tests/unit/test_decision_engine.py`

**Step 1: Write tests**

```python
# tests/unit/test_decision_engine.py
"""Tests for IntelligentDecisionEngine."""
from unittest.mock import patch
from agents.decision_engine import IntelligentDecisionEngine


@pytest.fixture
def engine():
    return IntelligentDecisionEngine()


def test_analyze_target_ip(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "93.184.216.34"
        profile = engine.analyze_target("93.184.216.34")
        assert profile is not None
        assert hasattr(profile, "to_dict")


def test_analyze_target_domain(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "93.184.216.34"
        profile = engine.analyze_target("example.com")
        assert profile is not None


def test_select_optimal_tools(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "93.184.216.34"
        profile = engine.analyze_target("example.com")
        tools = engine.select_optimal_tools(profile)
        assert isinstance(tools, list)
        assert len(tools) > 0


def test_optimize_parameters_nmap(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "10.0.0.1"
        profile = engine.analyze_target("10.0.0.1")
        params = engine.optimize_parameters("nmap", profile)
        assert isinstance(params, dict)


def test_no_name_error_on_optimize(engine):
    """Verify the broken parameter_optimizer reference is gone."""
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "10.0.0.1"
        profile = engine.analyze_target("10.0.0.1")
        # This should NOT raise NameError
        params = engine.optimize_parameters("nuclei", profile)
        assert isinstance(params, dict)
```

Add `import pytest` at top.

**Commit:**

```bash
git commit -m "test: add unit tests for IntelligentDecisionEngine (Phase 5b, Task 23)"
```

---

### Task 24: Bug Bounty Manager Tests

**Files:**
- Create: `tests/unit/test_bugbounty_manager.py`

Test that workflow methods return dicts with expected keys. Mock any external calls.

**Commit:**

```bash
git commit -m "test: add unit tests for BugBountyWorkflowManager (Phase 5b, Task 24)"
```

---

### Task 25: CTF Manager Tests

**Files:**
- Create: `tests/unit/test_ctf_manager.py`

Test plan structure per challenge type. Mock any external calls.

**Commit:**

```bash
git commit -m "test: add unit tests for CTFWorkflowManager (Phase 5b, Task 25)"
```

---

### Task 26: CVE Intelligence Tests

**Files:**
- Create: `tests/unit/test_cve_intelligence.py`

Mock NVD API responses. Test `fetch_latest_cves()`, `analyze_cve_exploitability()`, `create_summary_report()`.

**Commit:**

```bash
git commit -m "test: add unit tests for CVEIntelligenceManager (Phase 5b, Task 26)"
```

---

### Task 27: Browser Agent Tests

**Files:**
- Create: `tests/unit/test_browser_agent.py`

Mock webdriver. Test init, navigate, screenshot, DOM extraction. Follow same pattern as existing `test_stealth_browser_agent.py`.

**Commit:**

```bash
git commit -m "test: add unit tests for BrowserAgent (Phase 5b, Task 27)"
```

---

### Task 28: Auth + Rate Limit Integration Tests

**Files:**
- Expand: `tests/unit/test_auth_middleware.py` and `tests/unit/test_rate_limiter.py`

Add edge cases: multiple keys, empty header, key in query param (should fail), rate limit reset timing.

**Commit:**

```bash
git commit -m "test: expand auth and rate limiter edge case tests (Phase 5b, Task 28)"
```

---

### Task 29: Full Suite Verification

**Step 1: Run entire test suite**

Run: `pytest tests/ -v --tb=short`
Expected: ~670-690 tests, all PASS

**Step 2: Quick coverage check**

Run: `pytest tests/ --cov=agents --cov=core --cov-report=term-missing | tail -30`

---

### Task 30: Final Documentation Update

**Files:**
- Modify: `CHANGELOG.md` (add Phase 5b section)
- Modify: `CLAUDE.md` (update architecture, test counts, new files)

**Step 1: Add Phase 5b section to CHANGELOG.md**

Add at top of changelog: Phase 5b summary with all new files, changes, and test counts.

**Step 2: Update CLAUDE.md**

- Add `core/auth.py`, `core/rate_limit.py`, `core/validation.py` to Core Components
- Update MCP tool counts
- Update test counts
- Note security hardening (API key auth, rate limiting)

**Step 3: Commit**

```bash
git add CHANGELOG.md CLAUDE.md
git commit -m "docs: Phase 5b complete — CHANGELOG and CLAUDE.md updated"
```

---

## Summary

| Batch | Tasks | New Files | Modified Files | New Tests |
|-------|-------|-----------|----------------|-----------|
| A: Security | 1–8 | 4 (`auth.py`, `rate_limit.py`, `validation.py`, test files) | 4 (`server.py`, `client.py`, `network.py`, `web.py`) | ~20 |
| B: Stubs | 9–17 | 2 (test files) | 6 (`intelligence.py`, `proxy_provider.py`, `decision_engine.py`, `file_manager.py`, 4 `__init__.py`) | ~10 |
| C: MCP | 18–22 | 4 (test files) | 4 (`network.py`, `binary.py`, `cloud.py`, `system.py`, `workflows.py`) | ~20 |
| D: Tests | 23–30 | 5 (test files) | 2 (`CHANGELOG.md`, `CLAUDE.md`) | ~30 |
| **Total** | **30** | **~15** | **~16** | **~80** |

**Estimated final test count:** 605 + ~80 = ~685 tests
