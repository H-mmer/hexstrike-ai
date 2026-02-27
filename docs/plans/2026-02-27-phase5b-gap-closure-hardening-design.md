# Phase 5b Design: Gap Closure & Hardening

**Date:** 2026-02-27
**Branch:** v7.0-dev (continuing from Phase 5)
**Status:** Design approved, pending implementation plan

## Context

A code-explorer audit of the codebase after Phase 5 completion identified critical
gaps across security, code quality, MCP coverage, and test coverage. Phase 5b
addresses these gaps before moving to Phase 6 (Native Desktop Client & MCP Bypass).

## Scope

Four categories, executed in security-first order:

1. **Security hardening** — API key auth, rate limiting, input validation
2. **Stubs & dead code cleanup** — hollow intelligence endpoints, proxy provider, orphaned routes, broken references
3. **MCP tool gap closure** — ~19 missing MCP wrappers for existing routes
4. **Test coverage** — unit tests for 6 untested agent/manager modules + new route tests

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Auth mechanism | API key (X-API-Key header) | Single-user local tool; JWT deferred to Phase 6 desktop app |
| /api/command endpoint | Keep, behind auth | Operator already has shell access; auth prevents network RCE |
| Intelligence stubs | Real searchsploit + real payload tester | Wire actual tools instead of fake data |
| Zero-day research endpoint | Remove | Cannot deliver on its promise; misleads users |
| Proxy provider | Implement basic round-robin | Interface already wired into StealthBrowserAgent |
| File manager orphaned routes | Decompose into Blueprint or delete | Dead `app` object references must go |
| Execution order | Auth → Stubs → MCP → Tests | Clean dependency chain; each batch improves foundation for next |

## Batch A: Security Hardening

### API Key Middleware
- Flask `@before_request` hook in `core/server.py`
- Read key from `HEXSTRIKE_API_KEY` environment variable
- Check `X-API-Key` request header against stored key
- Bypass `/health` endpoint only (needed for monitoring)
- Return 401 Unauthorized with JSON error body on mismatch
- If `HEXSTRIKE_API_KEY` is not set, log a warning but allow all requests (dev mode)

### Rate Limiting
- Add `flask-limiter` to requirements.txt
- Default: 60 requests/minute per IP for scan endpoints
- Stricter: 10 requests/minute for `/api/command`
- Relaxed: 120 requests/minute for read-only endpoints (`/health`, `/api/cache/stats`, `/api/tasks/*`)
- Return 429 Too Many Requests with retry-after header

### Input Validation
- Validate `target` parameters: must be valid IPv4, IPv6, domain, CIDR, or URL
- Reject empty targets (some routes already do this; make it consistent)
- Add a shared `validate_target(target: str) -> bool` utility in `core/validation.py`
- Apply in all route handlers that pass target to subprocess

### MCP Client Auth
- `HexStrikeClient` reads `HEXSTRIKE_API_KEY` from env var
- Sends `X-API-Key` header on all `safe_post` and `requests.get` calls
- No code changes needed in individual MCP tool modules (header added centrally)

## Batch B: Stubs & Dead Code Cleanup

### Intelligence Endpoints (`core/routes/intelligence.py`)

**Exploit Generator (real implementation):**
- Replace `_SimpleExploitGenerator.generate_exploit_from_cve()` with subprocess call to `searchsploit --cve <CVE-ID> --json`
- Parse JSON output, return real exploit references (EDB-ID, title, path)
- Graceful fallback if searchsploit not installed: return `{"success": false, "error": "searchsploit not installed"}`

**Payload Tester (real implementation):**
- `ai_test_payload` route sends actual HTTP request to target URL with payload
- Supports GET and POST methods (from request param)
- Captures: response status, headers, body snippet (first 2KB)
- Checks for: payload reflection in response, WAF headers (X-WAF, CF-Ray, etc.), error signatures
- Timeout: 10 seconds, response body capped at 2KB
- Returns structured result with reflection_detected, waf_detected, status_code

**Zero-Day Research (remove):**
- Delete `zero_day_research` route handler
- Remove associated fake vulnerability ID generator

**Vulnerability Correlator (fix):**
- Replace hardcoded `success_probability: 0.5` with actual CVE severity scoring
- Use `cve_intelligence.py`'s NVD API integration to fetch real CVSS scores

### Proxy Provider (`agents/proxy_provider.py`)
- Constructor accepts list of proxy dicts: `[{"http": "...", "https": "..."}]`
- `get_proxy()` returns next proxy in round-robin order
- `rotate()` advances index and optionally marks current proxy as failed
- Load proxy list from `HEXSTRIKE_PROXIES` env var (comma-separated URLs) or empty list
- Empty list preserves current no-op behavior (no breaking change)

### File Manager (`managers/file_manager.py`)
- Audit which routes on dead `app` object are unique vs duplicated
- Move unique functionality into `files_bp` Blueprint registered in `core/server.py`
- Delete routes that duplicate existing Blueprint endpoints
- If no unique routes remain, delete the orphaned route code entirely

### Tool Init Files
- `tools/network/__init__.py` — import public functions from submodules
- `tools/web/__init__.py` — same
- `tools/binary/__init__.py` — same
- `tools/cloud/__init__.py` — same
- Enables cleaner imports: `from tools.network import nmap_scan`

### Decision Engine Fixes (`agents/decision_engine.py`)
- Remove broken `parameter_optimizer` reference (silent NameError catch)
- Remove dead `_use_advanced_optimizer` flag
- Clean up `optimize_parameters()` to use local lookup directly

## Batch C: MCP Tool Gap Closure

19 new MCP tool wrappers following existing `@mcp.tool()` + `get_client().safe_post()` pattern:

### Network (9 tools in `hexstrike_mcp_tools/network.py`)
- `nmap_advanced_scan` → POST /api/tools/nmap-advanced
- `fierce_scan` → POST /api/tools/fierce
- `autorecon_scan` → POST /api/tools/autorecon
- `nbtscan_scan` → POST /api/tools/nbtscan
- `scapy_probe` → POST /api/tools/network/scapy
- `ipv6_scan` → POST /api/tools/network/ipv6-toolkit
- `udp_proto_scan` → POST /api/tools/network/udp-proto-scanner
- `cisco_torch_scan` → POST /api/tools/network/cisco-torch
- `enum4linux_ng_scan` → POST /api/tools/enum4linux-ng

### Binary (4 tools in `hexstrike_mcp_tools/binary.py`)
- `rizin_analyze` → POST /api/tools/binary/rizin
- `yara_scan` → POST /api/tools/binary/yara
- `floss_analyze` → POST /api/tools/binary/floss
- `forensics_analyze` → POST /api/tools/binary/forensics

### Cloud (3 tools in `hexstrike_mcp_tools/cloud.py`)
- `kubescape_scan` → POST /api/tools/cloud/kubescape
- `container_escape_check` → POST /api/tools/cloud/container-escape
- `rbac_audit` → POST /api/tools/cloud/rbac-audit

### System (2 tools in `hexstrike_mcp_tools/system.py`)
- `get_telemetry` → GET /api/telemetry
- `clear_cache` → GET /api/cache/clear

### Workflows (1 tool in `hexstrike_mcp_tools/workflows.py`)
- `optimize_tool_parameters` → POST /api/intelligence/optimize-parameters

## Batch D: Test Coverage

### Agent Tests (~40-50 tests)
- `tests/unit/test_decision_engine.py` — analyze_target, select_optimal_tools, optimize_parameters, no NameError
- `tests/unit/test_bugbounty_manager.py` — workflow plan structure, tool selection per target type
- `tests/unit/test_ctf_manager.py` — plan structure per challenge type (crypto, pwn, web, forensics)
- `tests/unit/test_cve_intelligence.py` — mocked NVD API responses, summary report format
- `tests/unit/test_browser_agent.py` — mocked webdriver init, navigation, screenshot, DOM

### Route Tests (~15-20 tests)
- `tests/unit/test_routes/test_intelligence_routes.py` — real searchsploit (mocked subprocess), payload tester (mocked requests)

### Security Tests (~10-15 tests)
- `tests/unit/test_auth_middleware.py` — 401 without key, 200 with key, /health bypass, dev mode (no key set)
- `tests/unit/test_rate_limiter.py` — 429 on exceeded rate, retry-after header, different limits per endpoint

### Estimated Total
- ~65-85 new tests
- Project total: 605 → ~670-690

## Dependencies

### New packages
- `flask-limiter` — rate limiting middleware

### Existing tools used
- `searchsploit` (from exploitdb) — already in tool registry
- `requests` — already in requirements.txt

## Out of Scope

- JWT authentication (deferred to Phase 6 desktop app)
- Pentest report generation (deferred to later phase)
- Findings database/persistence (deferred to later phase)
- LLM integration in decision engine (deferred — would be a Phase of its own)
- Webhook/notification system (deferred)
- SIEM integration (deferred)
- CI/CD pipeline (deferred to Phase 7 per v7 plan)
