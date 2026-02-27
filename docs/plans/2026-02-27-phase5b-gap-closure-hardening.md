# Phase 5b: Gap Closure & Hardening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close critical security gaps (API auth, rate limiting, input validation), clean up stubs and dead code, fill MCP tool coverage holes, and add unit tests for untested agents.

**Architecture:** Flask `@before_request` middleware for auth/rate limiting, `core/validation.py` for shared target/domain/args validation, SSRF-safe payload tester, real subprocess calls replacing stub intelligence endpoints, 12 new MCP tool wrappers following existing `@mcp.tool()` + `safe_post()` pattern, and pytest unit tests with mocked externals.

**Tech Stack:** Flask, flask-limiter, pytest, requests (for payload tester), subprocess (for searchsploit)

**Tasks:** 28 (originally 30; 2 removed after Codex review verified binary/cloud MCP tools already exist)

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
def app(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)  # isolate from auth
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
    cmd_view = app.view_functions.get("system.run_command")
    if cmd_view is not None:
        limiter.limit("10/minute")(cmd_view)
    else:
        logger.warning("system.run_command endpoint not found — skipping rate limit")

    # Exempt health endpoint
    health_view = app.view_functions.get("system.health_check")
    if health_view is not None:
        limiter.exempt(health_view)
    else:
        logger.warning("system.health_check endpoint not found — skipping exemption")

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
from core.validation import is_valid_target, is_valid_domain, sanitize_additional_args


# --- is_valid_target (IP / domain / CIDR / URL) ---

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

def test_valid_url_with_query_params():
    """URLs with & in query strings must pass (not rejected as shell metachars)."""
    assert is_valid_target("https://example.com/page?a=1&b=2") is True

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


# --- is_valid_domain (domain / subdomain only, no IP/CIDR) ---

def test_domain_valid():
    assert is_valid_domain("example.com") is True

def test_domain_subdomain():
    assert is_valid_domain("sub.example.com") is True

def test_domain_rejects_ip():
    assert is_valid_domain("192.168.1.1") is False

def test_domain_rejects_shell():
    assert is_valid_domain("example.com; id") is False

def test_domain_rejects_empty():
    assert is_valid_domain("") is False


# --- sanitize_additional_args ---

def test_sanitize_args_safe():
    assert sanitize_additional_args("-p 80 --open") == "-p 80 --open"

def test_sanitize_args_rejects_semicolon():
    assert sanitize_additional_args("-p 80; rm -rf /") is None

def test_sanitize_args_rejects_pipe():
    assert sanitize_additional_args("-p 80 | cat /etc/passwd") is None

def test_sanitize_args_rejects_backtick():
    assert sanitize_additional_args("`whoami`") is None

def test_sanitize_args_empty():
    assert sanitize_additional_args("") == ""
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_validation.py -v`
Expected: FAIL (module doesn't exist)

### Task 6: Input Validation — Implementation

**Step 3: Write implementation**

```python
# core/validation.py
"""Shared input validation for target parameters.

Provides validators for different field categories:
- is_valid_target(): IPs, domains, CIDRs, URLs (for `target`, `host`, `target_network`)
- is_valid_domain(): Domain/subdomain only (for `domain` params)
- sanitize_additional_args(): Reject shell metacharacters in free-form args
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

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
    URLs are checked FIRST (before metachar rejection) because URL query
    strings legitimately contain & and = which are shell metachars.
    Use for: target, host, target_network, url params.
    """
    if not target or not target.strip():
        return False

    target = target.strip()

    # URL — check first because query params may contain & = etc.
    if _URL_RE.match(target):
        return True

    # Non-URL targets: reject shell metacharacters
    if _SHELL_METACHARS.search(target):
        return False

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


def is_valid_domain(domain: str) -> bool:
    """Return True if *domain* is a valid domain/subdomain (no IPs, no CIDRs).

    Use for: domain params in bugbounty, osint routes.
    """
    if not domain or not domain.strip():
        return False
    domain = domain.strip()
    if _SHELL_METACHARS.search(domain):
        return False
    return bool(_DOMAIN_RE.match(domain))


def sanitize_additional_args(args: str) -> Optional[str]:
    """Return *args* if safe (no shell metacharacters), else None.

    Use for: additional_args, flags, nse_scripts params.
    Empty string is considered safe.
    """
    if not args:
        return args  # "" or None pass through
    if _SHELL_METACHARS.search(args):
        return None
    return args
```

**Step 4: Run tests to verify all pass**

Run: `pytest tests/unit/test_validation.py -v`
Expected: 19 PASS

**Step 5: Commit**

```bash
git add core/validation.py tests/unit/test_validation.py
git commit -m "feat(auth): add target input validation utility (Phase 5b, Tasks 5-6)"
```

---

### Task 7: Wire Validation Into Routes

**Files:**
- Modify: `core/routes/network.py` (validate `target`, `host`, `target_network`, `additional_args`)
- Modify: `core/routes/web.py` (validate `target`, `url`, `domain`, `additional_args`)
- Modify: `core/routes/cloud.py` (validate `target`)
- Modify: `core/routes/osint.py` (validate `target`, `domain`)

**Step 1: Add validation imports**

In each Blueprint file, add near the top (after existing imports):
```python
from core.validation import is_valid_target, is_valid_domain, sanitize_additional_args
```

**Step 2: Wire validators by field type**

For `target`, `host`, `target_network` params (IP/domain/CIDR/URL):
```python
    if not is_valid_target(target):
        return jsonify({"success": False, "error": "Invalid target format"}), 400
```

For `domain` params (domain only, e.g. bugbounty/osint):
```python
    if not is_valid_domain(domain):
        return jsonify({"success": False, "error": "Invalid domain format"}), 400
```

For `additional_args`, `flags`, `nse_scripts` params:
```python
    additional_args = sanitize_additional_args(additional_args)
    if additional_args is None:
        return jsonify({"success": False, "error": "Invalid characters in arguments"}), 400
```

Apply to route handlers in: `network.py`, `web.py`, `cloud.py`, `osint.py`.
Do NOT apply to: intelligence routes (software names), browser routes (already validate scheme).

**Step 3: Run full test suite**

Run: `pytest tests/ -q`
Expected: All pass (existing route tests use valid targets like "192.168.1.1" and "example.com")

**Step 4: Commit**

```bash
git add core/routes/network.py core/routes/web.py core/routes/cloud.py core/routes/osint.py
git commit -m "feat(auth): wire target/domain/args validation into route handlers (Phase 5b, Task 7)"
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

## Batch B: Stubs & Dead Code Cleanup (Tasks 9–18)

### Task 9: Exploit Generator — Real searchsploit

**Files:**
- Modify: `core/routes/intelligence.py:58-72` (replace `_SimpleExploitGenerator`)
- Create: `tests/unit/test_routes/test_intelligence_routes.py`

> **Note:** The real route is `/api/vuln-intel/exploit-generate` (intelligence.py:409).
> The route wraps `_exploit_generator.generate_exploit_from_cve()` and nests its result
> under `data["exploit_generation"]`, not top-level `data["exploits"]`.
> We must also mock `_get_cve_intelligence()` since the route calls it first.

**Step 1: Write the failing test**

```python
# tests/unit/test_routes/test_intelligence_routes.py
"""Tests for intelligence Blueprint routes."""
import json
from unittest.mock import patch, MagicMock
import pytest
from core.server import create_app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestExploitGenerator:
    def test_exploit_lookup_with_searchsploit(self, client):
        fake_searchsploit = {
            "success": True,
            "exploits": [
                {"edb_id": "50383", "title": "Apache 2.4.49 - RCE", "path": "/exploits/50383.py"}
            ],
            "cve_id": "CVE-2021-41773",
        }
        fake_cve_analysis = {
            "success": True,
            "exploitability_level": "HIGH",
            "exploitability_score": 9.0,
        }
        fake_existing = {"exploits": []}

        with patch("core.routes.intelligence._get_cve_intelligence") as mock_cve, \
             patch("core.routes.intelligence._exploit_generator") as mock_gen:
            mock_cve_inst = MagicMock()
            mock_cve_inst.analyze_cve_exploitability.return_value = fake_cve_analysis
            mock_cve_inst.search_existing_exploits.return_value = fake_existing
            mock_cve.return_value = mock_cve_inst

            mock_gen.generate_exploit_from_cve.return_value = fake_searchsploit

            resp = client.post("/api/vuln-intel/exploit-generate", json={
                "cve_id": "CVE-2021-41773",
                "exploit_type": "poc",
            })
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            # Response nests under "exploit_generation"
            gen = data["exploit_generation"]
            assert len(gen["exploits"]) >= 1
            assert "50383" in gen["exploits"][0]["edb_id"]

    def test_exploit_lookup_searchsploit_missing(self, client):
        """When searchsploit is not installed, _exploit_generator returns error."""
        fake_cve_analysis = {"success": True, "exploitability_level": "MEDIUM"}

        with patch("core.routes.intelligence._get_cve_intelligence") as mock_cve, \
             patch("core.routes.intelligence._exploit_generator") as mock_gen:
            mock_cve_inst = MagicMock()
            mock_cve_inst.analyze_cve_exploitability.return_value = fake_cve_analysis
            mock_cve_inst.search_existing_exploits.return_value = {"exploits": []}
            mock_cve.return_value = mock_cve_inst

            mock_gen.generate_exploit_from_cve.return_value = {
                "success": False, "error": "searchsploit not installed"
            }

            resp = client.post("/api/vuln-intel/exploit-generate", json={
                "cve_id": "CVE-2021-41773",
            })
            data = resp.get_json()
            assert data["success"] is True  # route still succeeds
            assert data["exploit_generation"]["success"] is False
            assert "searchsploit" in data["exploit_generation"]["error"]
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

### Task 10: Payload Tester — Real HTTP Requests (with SSRF Guard)

**Files:**
- Modify: `core/routes/intelligence.py:810-848` (replace `ai_test_payload`)
- Add tests to: `tests/unit/test_routes/test_intelligence_routes.py`

> **SECURITY:** This endpoint sends server-side HTTP requests to arbitrary URLs —
> it is an SSRF primitive. Must block private/loopback/link-local/metadata IPs.
> **Accepted risk:** DNS rebinding (resolve-then-request TOCTOU) is not mitigated.
> This is a local pentesting tool behind API key auth, not a public web app.
> IP pinning would add significant complexity for minimal threat reduction.

**Step 1: Write the failing tests**

Add to `test_intelligence_routes.py`:

```python
import socket


class TestPayloadTester:
    def test_payload_test_sends_real_request(self, client):
        with patch("core.routes.intelligence.requests") as mock_req, \
             patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 80))
            ]
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.text = "<html><script>alert(1)</script></html>"
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
        with patch("core.routes.intelligence.requests") as mock_req, \
             patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 443))
            ]
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

    def test_payload_test_blocks_private_ip(self, client):
        """SSRF guard: block requests to private/loopback/link-local addresses."""
        with patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 80))
            ]
            resp = client.post("/api/ai/test_payload", json={
                "payload": "test",
                "target_url": "http://localhost/admin",
                "method": "GET",
            })
            data = resp.get_json()
            assert data["success"] is False
            assert "private" in data["error"].lower() or "blocked" in data["error"].lower()

    def test_payload_test_blocks_metadata_ip(self, client):
        """SSRF guard: block cloud metadata endpoint."""
        with patch("core.routes.intelligence.socket") as mock_socket:
            mock_socket.getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('169.254.169.254', 80))
            ]
            resp = client.post("/api/ai/test_payload", json={
                "payload": "test",
                "target_url": "http://169.254.169.254/latest/meta-data/",
                "method": "GET",
            })
            data = resp.get_json()
            assert data["success"] is False
```

**Step 2: Implement SSRF-safe `ai_test_payload` route**

Replace lines 810-848 with:

```python
import socket
import ipaddress

def _is_safe_url(url: str) -> bool:
    """Resolve URL hostname and reject private/loopback/link-local/metadata IPs."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        addrs = socket.getaddrinfo(hostname, parsed.port or 80)
    except socket.gaierror:
        return False
    for family, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
        # Block cloud metadata
        if str(ip) == "169.254.169.254":
            return False
    return True
```

The route handler:
- Calls `_is_safe_url(target_url)` before making any request; returns 400 if blocked
- Sends `requests.request(method, target_url, params/data containing payload, timeout=10, allow_redirects=False)`
- Captures status_code, first 2KB of response body, response headers
- Checks if payload string appears in response body (`reflection_detected`)
- Checks for WAF headers: CF-Ray, X-WAF, Server: cloudflare/akamai/imperva (`waf_detected`)
- Returns structured result with all findings

**Step 3: Run tests and commit**

Run: `pytest tests/unit/test_routes/test_intelligence_routes.py -v`

```bash
git add core/routes/intelligence.py tests/unit/test_routes/test_intelligence_routes.py
git commit -m "feat(intel): wire real HTTP payload tester with SSRF guard (Phase 5b, Task 10)"
```

---

### Task 11: Remove Zero-Day Research Endpoint (Coordinated)

> **Codex finding:** This endpoint has existing tests and an MCP wrapper that must be
> removed simultaneously to avoid broken tests. Files to coordinate:
> - `core/routes/intelligence.py:648-776` — the route handler
> - `tests/unit/test_routes/test_workflow_routes.py:356-366` — 2 route tests
> - `hexstrike_mcp_tools/workflows.py:186-194` — MCP wrapper (`zero_day_research`)
> - `tests/unit/test_mcp_tools/test_workflow_mcp.py:177-182` — 1 MCP test

**Files:**
- Modify: `core/routes/intelligence.py` (delete `zero_day_research` route)
- Modify: `tests/unit/test_routes/test_workflow_routes.py` (delete `test_zero_day_research_*`)
- Modify: `hexstrike_mcp_tools/workflows.py` (delete `zero_day_research` MCP tool)
- Modify: `tests/unit/test_mcp_tools/test_workflow_mcp.py` (delete `test_zero_day_research_calls_api`)

**Step 1: Delete all four pieces simultaneously**

1. In `core/routes/intelligence.py`: Remove the entire `zero_day_research` route handler (lines 648-776).
2. In `hexstrike_mcp_tools/workflows.py`: Remove the `zero_day_research` MCP tool (lines 186-194).
3. In `tests/unit/test_routes/test_workflow_routes.py`: Remove `test_zero_day_research_missing_software` and `test_zero_day_research_success` (lines 356-366).
4. In `tests/unit/test_mcp_tools/test_workflow_mcp.py`: Remove `test_zero_day_research_calls_api` (lines 177-182).

**Step 2: Run full test suite to verify no regressions**

Run: `pytest tests/ -q`
Expected: All pass (removed the tests along with the code)

**Step 3: Commit**

```bash
git add core/routes/intelligence.py hexstrike_mcp_tools/workflows.py \
  tests/unit/test_routes/test_workflow_routes.py tests/unit/test_mcp_tools/test_workflow_mcp.py
git commit -m "fix(intel): remove fake zero-day research endpoint + tests + MCP wrapper (Phase 5b, Task 11)"
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

> **Safety check (Codex finding):** Before deleting any functions, verify they are
> truly unused by grepping for imports across the codebase.

**Step 1: Audit orphaned routes**

Read `managers/file_manager.py` and identify all `@app.route(...)` decorators. These reference a dead `app` object that doesn't exist in the Blueprint architecture.

**Step 2: Verify no imports exist**

Before deleting, run (with explicit search root `.`):
```bash
rg -n "from managers\.file_manager import|from managers import file_manager|managers\.file_manager" . -g '*.py' | rg -v 'managers/file_manager.py|__pycache__'
```

If any non-test file imports specific functions from `file_manager.py`, keep those functions. Only delete functions that are both `@app.route`-decorated AND not imported elsewhere.

**Step 3: Delete orphaned route functions**

Remove all functions decorated with `@app.route(...)` that are confirmed unused. Keep utility methods (file operations, artifact handling) that are imported elsewhere.

**Step 4: Run tests and commit**

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

### Task 17: Pre-flight Import Fixes

> **Codex finding:** `decision_engine.py` and `cve_intelligence.py` have missing imports
> that will cause NameError/ImportError at runtime. Fix before writing tests (Batch D).

**Files:**
- Modify: `agents/decision_engine.py` (add `import urllib.parse` and `import socket`)
- Modify: `agents/cve_intelligence.py` (add `from datetime import datetime, timedelta`, add `from utils.visual_engine import ModernVisualEngine`)

**Step 1: Fix `decision_engine.py` imports**

At line 8, after `import re`, add:
```python
import socket
import urllib.parse
```

These are used by `_determine_target_type()` (urlparse) and `analyze_target()` (socket.gethostbyname).

**Step 2: Fix `cve_intelligence.py` imports**

Change line 10 from `from datetime import datetime` to:
```python
from datetime import datetime, timedelta
```

And add after the logging import:
```python
from utils.visual_engine import ModernVisualEngine
```

**Step 3: Run smoke test (exercises the fixed imports)**

```bash
python3 -c "
import socket
from unittest.mock import patch, MagicMock

# Verify decision_engine uses socket and urllib.parse
from agents.decision_engine import IntelligentDecisionEngine
engine = IntelligentDecisionEngine()
with patch('agents.decision_engine.socket') as mock_sock:
    mock_sock.gethostbyname.return_value = '93.184.216.34'
    profile = engine.analyze_target('example.com')
    assert profile is not None, 'analyze_target failed'
print('decision_engine: OK (socket + urllib.parse used)')

# Verify cve_intelligence uses timedelta and ModernVisualEngine
from agents.cve_intelligence import CVEIntelligenceManager
cve = CVEIntelligenceManager()
report = cve.create_summary_report({'vulnerabilities': [], 'target': 'test', 'tools_used': []})
assert isinstance(report, str), 'create_summary_report failed'
print('cve_intelligence: OK (timedelta + ModernVisualEngine used)')
"
```

**Step 4: Commit**

```bash
git add agents/decision_engine.py agents/cve_intelligence.py
git commit -m "fix: add missing imports to decision_engine and cve_intelligence (Phase 5b, Task 17)"
```

---

### Task 18: Batch B Verification

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

## Batch C: MCP Tool Gap Closure (Tasks 19–21)

### Task 19: Network MCP Tools (9 tools)

**Files:**
- Modify: `hexstrike_mcp_tools/network.py` (append 9 new tool functions)
- Create: `tests/unit/test_mcp_tools/test_network_mcp_gap.py`

> **Convention:** Existing MCP tools use NO leading slash (e.g. `"api/tools/nmap"`).
> All new tools MUST follow this convention.

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
    assert "api/tools/nmap-advanced" in m.safe_post.call_args[0][0]


def test_fierce_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import fierce_scan
    fierce_scan("example.com")
    assert "api/tools/fierce" in m.safe_post.call_args[0][0]


def test_autorecon_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import autorecon_scan
    autorecon_scan("10.0.0.1")
    assert "api/tools/autorecon" in m.safe_post.call_args[0][0]


def test_nbtscan_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import nbtscan_scan
    nbtscan_scan("10.0.0.0/24")
    assert "api/tools/nbtscan" in m.safe_post.call_args[0][0]


def test_scapy_probe():
    m = setup_mock()
    from hexstrike_mcp_tools.network import scapy_probe
    scapy_probe("10.0.0.1")
    assert "api/tools/network/scapy" in m.safe_post.call_args[0][0]


def test_ipv6_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import ipv6_scan
    ipv6_scan("::1")
    assert "api/tools/network/ipv6-toolkit" in m.safe_post.call_args[0][0]


def test_udp_proto_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import udp_proto_scan
    udp_proto_scan("10.0.0.1")
    assert "api/tools/network/udp-proto-scanner" in m.safe_post.call_args[0][0]


def test_cisco_torch_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import cisco_torch_scan
    cisco_torch_scan("10.0.0.1")
    assert "api/tools/network/cisco-torch" in m.safe_post.call_args[0][0]


def test_enum4linux_ng_scan():
    m = setup_mock()
    from hexstrike_mcp_tools.network import enum4linux_ng_scan
    enum4linux_ng_scan("10.0.0.1")
    assert "api/tools/enum4linux-ng" in m.safe_post.call_args[0][0]
```

**Step 2: Implement 9 MCP tool wrappers**

Append to `hexstrike_mcp_tools/network.py`, following the existing no-leading-slash pattern:

```python
@mcp.tool()
def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "",
                       timing: str = "T4", nse_scripts: str = "",
                       os_detection: bool = False, version_detection: bool = False,
                       aggressive: bool = False, stealth: bool = False) -> str:
    """Advanced nmap scan with NSE scripts, timing, OS/version detection."""
    return get_client().safe_post("api/tools/nmap-advanced", {
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
git commit -m "feat(mcp): add 9 missing network MCP tool wrappers (Phase 5b, Task 19)"
```

---

### ~~Binary & Cloud MCP Tools — REMOVED from original 30-task draft~~

> **Codex finding (verified):** These MCP tools already exist:
> - `hexstrike_mcp_tools/binary.py`: `yara_malware_scan` (line 70), `floss_string_extract` (line 78),
>   `rizin_analyze` (line 84), `forensics_analyze` (line 92)
> - `hexstrike_mcp_tools/cloud.py`: `kubescape_assessment` (line 61), `container_escape_check` (line 69),
>   `kubernetes_rbac_audit` (line 77)
>
> No action needed. These tasks have been removed from the plan.

---

### Task 20: System + Workflow MCP Tools (3 tools)

**Files:**
- Modify: `hexstrike_mcp_tools/system.py`
- Modify: `hexstrike_mcp_tools/workflows.py`
- Create: `tests/unit/test_mcp_tools/test_system_mcp_gap.py`

Add to system.py: `get_telemetry` (GET), `clear_cache` (POST).
Add to workflows.py: `optimize_tool_parameters` (POST).

Note: `get_telemetry` and `clear_cache` use GET/POST — use `get_client().safe_get()` for GET routes.
Follow no-leading-slash convention (e.g. `"api/telemetry"` not `"/api/telemetry"`).

**Commit:**

```bash
git commit -m "feat(mcp): add system + workflow MCP tool wrappers (Phase 5b, Task 20)"
```

---

### Task 21: MCP Gap Verification

**Step 1: Run all MCP tests**

Run: `pytest tests/unit/test_mcp_tools/ -v`

**Step 2: Count total MCP tools**

Use `grep` to count total registered tools across all files:

```bash
grep -ho "@mcp.tool()" hexstrike_mcp_tools/*.py | wc -l
```

Expected: previous count (103) + 12 (9 network + 3 system/workflow) = ~115 total

**Step 3: Commit verification**

```bash
git commit --allow-empty -m "chore: Batch C complete — 12 MCP tool wrappers added (Phase 5b)"
```

---

## Batch D: Test Coverage (Tasks 22–28)

> **Prerequisite:** Task 17 (pre-flight import fixes) MUST be completed before these tests.
> Without it, `decision_engine.py` and `cve_intelligence.py` will fail to import.

### Task 22: Decision Engine Tests

**Files:**
- Create: `tests/unit/test_decision_engine.py`

**Step 1: Write tests**

```python
# tests/unit/test_decision_engine.py
"""Tests for IntelligentDecisionEngine."""
import pytest
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

**Commit:**

```bash
git commit -m "test: add unit tests for IntelligentDecisionEngine (Phase 5b, Task 22)"
```

---

### Task 23: Bug Bounty Manager Tests

**Files:**
- Create: `tests/unit/test_bugbounty_manager.py`

Test that workflow methods return dicts with expected keys. Mock any external calls.

**Commit:**

```bash
git commit -m "test: add unit tests for BugBountyWorkflowManager (Phase 5b, Task 23)"
```

---

### Task 24: CTF Manager Tests

**Files:**
- Create: `tests/unit/test_ctf_manager.py`

Test plan structure per challenge type. Mock any external calls.

**Commit:**

```bash
git commit -m "test: add unit tests for CTFWorkflowManager (Phase 5b, Task 24)"
```

---

### Task 25: CVE Intelligence Tests

**Files:**
- Create: `tests/unit/test_cve_intelligence.py`

Mock NVD API responses. Test `fetch_latest_cves()`, `analyze_cve_exploitability()`, `create_summary_report()`.

**Commit:**

```bash
git commit -m "test: add unit tests for CVEIntelligenceManager (Phase 5b, Task 25)"
```

---

### Task 26: Browser Agent Tests

**Files:**
- Create: `tests/unit/test_browser_agent.py`

Mock webdriver. Test init, navigate, screenshot, DOM extraction. Follow same pattern as existing `test_stealth_browser_agent.py`.

**Commit:**

```bash
git commit -m "test: add unit tests for BrowserAgent (Phase 5b, Task 26)"
```

---

### Task 27: Auth + Rate Limit Integration Tests

**Files:**
- Expand: `tests/unit/test_auth_middleware.py` and `tests/unit/test_rate_limiter.py`

Add edge cases: multiple keys, empty header, key in query param (should fail), rate limit reset timing.

**Commit:**

```bash
git commit -m "test: expand auth and rate limiter edge case tests (Phase 5b, Task 27)"
```

---

### Task 28: Full Suite Verification + Documentation

**Step 1: Run entire test suite**

Run: `pytest tests/ -v --tb=short`
Expected: ~680+ tests, all PASS

**Step 2: Quick coverage check**

Run: `pytest tests/ --cov=agents --cov=core --cov-report=term-missing | tail -30`

**Step 3: Update CHANGELOG.md**

Add Phase 5b section at top with summary of all new files, changes, and test counts.

**Step 4: Update CLAUDE.md**

- Add `core/auth.py`, `core/rate_limit.py`, `core/validation.py` to Core Components
- Update MCP tool counts
- Update test counts
- Note security hardening (API key auth, rate limiting, SSRF protection)

**Step 5: Commit**

```bash
git add CHANGELOG.md CLAUDE.md
git commit -m "docs: Phase 5b complete — CHANGELOG and CLAUDE.md updated"
```

---

## Summary

| Batch | Tasks | New Files | Modified Files | New Tests |
|-------|-------|-----------|----------------|-----------|
| A: Security | 1–8 | 4 (`auth.py`, `rate_limit.py`, `validation.py`, test files) | 6 (`server.py`, `client.py`, `network.py`, `web.py`, `cloud.py`, `osint.py`) | ~26 |
| B: Stubs | 9–18 | 2 (test files) | 10 (`intelligence.py`, `proxy_provider.py`, `decision_engine.py`, `cve_intelligence.py`, `file_manager.py`, `workflows.py`, 4 `__init__.py`) | ~12 |
| C: MCP | 19–21 | 2 (test files) | 3 (`network.py`, `system.py`, `workflows.py`) | ~12 |
| D: Tests | 22–28 | 5 (test files) | 2 (`CHANGELOG.md`, `CLAUDE.md`) | ~30 |
| **Total** | **28** | **~13** | **~21** | **~80** |

**Estimated final test count:** 605 + ~80 - 3 (removed zero-day tests) = ~682 tests

### Revision Log

**Round 1 (Codex review):** 10 findings addressed:
1. Task 11: Coordinated zero-day removal with tests + MCP wrapper (was orphan delete)
2. Task 9: Fixed route `/api/vuln-intel/exploit-generate`, response shape `exploit_generation`, dual mocking
3. Task 10: Added SSRF guards (`_is_safe_url()`, block private/loopback/metadata IPs, disable redirects)
4. Tasks 5-7: Expanded validation to `domain`, `url`, `host`, `additional_args` (was `target` only)
5. Tasks 3-4: Added None-guard on `view_functions.get()`, explicit env unset in fixture
6. Task 17 (NEW): Pre-flight import fixes for `decision_engine.py` and `cve_intelligence.py`
7. Tasks 19/20 (REMOVED): Binary + cloud MCP tools already exist in codebase
8. Task 19: Fixed leading-slash convention to match existing `"api/..."` pattern
9. Task 21: Fixed MCP tool count to use `grep @mcp.tool()` instead of `dir(mcp)`
10. Task 15: Added grep-for-imports safety check before deletion

**Round 2 (Codex review):** 10 findings addressed:
1. Task 15: Fixed grep command to use `rg` with explicit root `.` (was missing search path)
2. Task 21: Fixed MCP count command to use `grep -ho ... | wc -l` for total (was `tail -1`)
3. Task 10: Documented DNS rebinding as accepted risk (local tool behind auth, low threat)
4. Tasks 5-6: Moved URL check before metachar rejection (URLs with `&` in query params were wrongly rejected); added test for `?a=1&b=2`
5. Task 10: Fixed reflection test mock body to include exact payload string
6. Renamed removed-task section to avoid numbering conflict with active tasks
7. Corrected Batch B modified-file count from 8 to 10 in summary table
8. Aligned Task 28 expected test count with summary estimate (~680+)
9. Task 17: Enhanced smoke test to exercise `analyze_target()` and `create_summary_report()` (not just imports)
10. Tasks 3-4: Replaced hard asserts with graceful `if None: log + skip` guards in rate limiter
