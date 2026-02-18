# Phase 1-3 Gap Closure Design

**Date:** 2026-02-18
**Branch:** v7.0-dev
**Status:** Approved — ready for implementation planning

---

## Context

Phases 1-3 of the v7.0 development plan left a significant integration gap. The tool module
files were written but the server and MCP client were never decomposed:

| Phase | Modules Written | Server Routes Wired | MCP Tools Registered |
|-------|----------------|---------------------|----------------------|
| Phase 1 (agents/managers) | ✅ | ✅ | ✅ |
| Phase 2 (mobile/api/wireless) | ✅ | 6 of ~30 | ❌ 0 |
| Phase 3 (enhanced tools) | ✅ | 0 of ~20 | ❌ 0 |
| OSINT | ❌ empty | ❌ | ❌ |

`hexstrike_server.py` remains at 17,004 lines with 162 inline route handlers.
`hexstrike_mcp.py` remains at 5,470 lines with 151 MCP tools, none from Phases 2-3.
`mcp/` exists but contains only an empty `__init__.py`.

This phase closes all gaps and completes the decomposition originally planned in Phase 1.

---

## Goal

- **Decompose** `hexstrike_server.py` into Flask Blueprints under `core/routes/`
- **Wire** all existing Phase 2/3 tool modules to server routes
- **Register** all Phase 2/3 tools as MCP tools
- **Implement** OSINT tools from scratch
- **Reorganize** `hexstrike_mcp.py` into the `mcp/` module structure
- **Result:** Both monolith files shrink to thin entry points (~50-100 lines each)

---

## Target Architecture

### Server-side

```
core/
└── routes/
    ├── __init__.py
    ├── network.py        # Blueprint: recon, port scan, DNS
    ├── web.py            # Blueprint: web app testing
    ├── cloud.py          # Blueprint: cloud/container security
    ├── binary.py         # Blueprint: binary analysis, forensics
    ├── mobile.py         # Blueprint: APK, iOS, mobile exploit
    ├── api_security.py   # Blueprint: API discovery, fuzzing, auth
    ├── wireless.py       # Blueprint: WiFi, Bluetooth, RF
    ├── osint.py          # Blueprint: OSINT (new)
    ├── intelligence.py   # Blueprint: AI decision engine routes
    ├── bugbounty.py      # Blueprint: bug bounty workflows
    ├── ctf.py            # Blueprint: CTF workflows
    └── system.py         # Blueprint: health, cache, processes
```

`core/server.py` registers all Blueprints with the Flask app.
`hexstrike_server.py` becomes a thin entry point: imports `core/server.py`, parses args, calls `app.run()`.

### MCP-side

```
mcp/
├── __init__.py
├── client.py             # HexStrikeClient (extracted from hexstrike_mcp.py)
├── server.py             # FastMCP setup, imports all tool modules
└── tools/
    ├── network.py        # @mcp.tool() registrations — network
    ├── web.py            # @mcp.tool() registrations — web
    ├── cloud.py
    ├── binary.py
    ├── mobile.py
    ├── api_security.py
    ├── wireless.py
    ├── osint.py
    └── system.py
```

`hexstrike_mcp.py` becomes a thin launcher: imports `mcp/server.py`, parses args, starts server.

### OSINT tools (new)

```
tools/osint/
├── __init__.py
├── passive_recon.py      # shodan, censys, whois, theHarvester, dnsdumpster
├── social_intel.py       # sherlock, holehe, breach lookup, linkedin recon
└── threat_intel.py       # virustotal, otx, urlscan, shodan CVE lookup
```

---

## Approach: Sequential Category Blueprints (Option A)

One category at a time. For each batch:
1. Write tests (unit + integration) — TDD, tests first
2. Create `core/routes/<category>.py` Blueprint
3. Extract existing inline routes from `hexstrike_server.py`
4. Wire Phase 2/3 tool module implementations where applicable
5. Register MCP tools in `mcp/tools/<category>.py`
6. Register Blueprint with app, verify `pytest` still green
7. Commit

---

## Batch Sequence

### Batch 1 — Infrastructure (scaffolding + system routes)

**Goal:** Prove the Blueprint pattern end-to-end before touching real tool categories.

- Create `core/routes/` package and `__init__.py`
- Create `mcp/client.py` (extract `HexStrikeClient` from `hexstrike_mcp.py`)
- Create `mcp/server.py` scaffold (FastMCP setup, imports `mcp/tools/`)
- Create `core/routes/system.py` Blueprint — extract health, cache, process, error-handling routes (~25 routes)
- Write unit + integration tests for system routes
- Verify full test suite still green

**Routes moved:** ~25 (health, cache, processes, error-handling, telemetry)
**New routes:** 0
**MCP tools:** system-level tools migrated to `mcp/tools/system.py`

---

### Batch 2 — Network

- Create `core/routes/network.py` Blueprint
- Extract all network/recon route handlers from `hexstrike_server.py`
- Wire `tools/network/advanced_network.py` (Phase 3: scapy, zmap, naabu, IPv6 toolkit, VLAN hopper, cisco-torch, snmp-check, udp-proto-scanner)
- Create `mcp/tools/network.py` with all network MCP tool registrations
- Tests: unit (tool wrappers mocked) + integration (Blueprint via Flask test client)

**Routes moved:** ~35
**New routes:** ~8 (Phase 3 advanced network tools)
**MCP tools:** all network tools registered

---

### Batch 3 — Web

- Create `core/routes/web.py` Blueprint
- Extract all web route handlers from `hexstrike_server.py`
- Wire Phase 3 web modules:
  - `tools/web/js_analysis.py` (retire.js, linkfinder, jsluice, subjs, trufflehog, secretfinder)
  - `tools/web/injection_testing.py` (nosqlmap, ssrf-sheriff, xxeinjector, ldap/xpath/ssti/crlf scanners)
  - `tools/web/auth_testing.py` (csrf-scanner, session hijacking, cookie analyzer, saml-raider)
  - `tools/web/cms_scanners.py` (joomscan, droopescan, magescan)
  - `tools/web/cdn_tools.py` (cdn-scanner, cache-poisoner, cloudflare-bypass)
- Create `mcp/tools/web.py`
- Tests: unit + integration

**Routes moved:** ~40
**New routes:** ~20 (Phase 3 web tools)
**MCP tools:** all web tools registered

---

### Batch 4 — Cloud + Binary

**Cloud:**
- Create `core/routes/cloud.py` Blueprint
- Extract all cloud route handlers
- Wire `tools/cloud/cloud_native.py` (kubescape, popeye, rbac-police, kubesec, aws-vault, azure-scan, gcp-enum)
- Wire `tools/cloud/container_escape.py` (deepce, amicontained, cdk, peirates)
- Create `mcp/tools/cloud.py`

**Binary:**
- Create `core/routes/binary.py` Blueprint
- Extract all binary/forensics route handlers
- Wire `tools/binary/enhanced_binary.py` (rizin, cutter, pwndbg, unicorn, capstone)
- Wire `tools/binary/forensics.py` (autopsy-cli, plaso, dc3dd)
- Wire `tools/binary/malware_analysis.py` (yara, floss, hollows-hunter, pestudio)
- Create `mcp/tools/binary.py`

**Routes moved:** ~20
**New routes:** ~15 (Phase 3 cloud/binary tools)
**MCP tools:** all cloud + binary tools registered

---

### Batch 5 — CTF + BugBounty + Intelligence

- Create `core/routes/ctf.py`, `core/routes/bugbounty.py`, `core/routes/intelligence.py` Blueprints
- Extract workflow route handlers — agents already work, this is pure route migration
- Create corresponding `mcp/tools/` files
- No new tool implementations

**Routes moved:** ~25
**New routes:** 0
**MCP tools:** workflow tools migrated

---

### Batch 6 — Mobile + API + Wireless (Phase 2 completion)

**Mobile:**
- Create `core/routes/mobile.py` Blueprint
- Wire remaining mobile tools beyond the existing 2 routes:
  - `tools/mobile/mobile_exploit.py` (drozer, needle)
  - `tools/mobile/mobile_network.py` (mitmproxy-mobile, tcpdump-mobile)
- Create `mcp/tools/mobile.py` (currently 0 MCP tools → full registration)

**API Security:**
- Create `core/routes/api_security.py` Blueprint
- Wire remaining API tools beyond the existing 2 routes:
  - `tools/api/api_auth.py` (jwt-hack, oauth-scanner, api-key-brute, bearer-token-analyzer)
  - `tools/api/api_monitoring.py` (api-trace-analyzer, rate-limit-tester)
- Create `mcp/tools/api_security.py`

**Wireless:**
- Create `core/routes/wireless.py` Blueprint
- Wire `tools/wireless/rf_tools.py` (rtl-sdr, hackrf-tools, gqrx)
- Create `mcp/tools/wireless.py`

**Routes moved:** 6 (existing Phase 2 routes)
**New routes:** ~24 (remaining Phase 2 tools)
**MCP tools:** mobile + API + wireless fully registered for the first time

---

### Batch 7 — OSINT (new from scratch)

**Implement `tools/osint/`:**

`passive_recon.py`:
- `shodan_search(query, api_key)` — IP/service/banner lookup
- `censys_search(query, api_id, api_secret)` — certificate and host enum
- `whois_lookup(domain)` — registration and DNS intel
- `the_harvester(domain, sources)` — emails, subdomains, hosts
- `dnsdumpster(domain)` — DNS recon and map

`social_intel.py`:
- `sherlock_search(username)` — username across 300+ platforms
- `holehe_check(email)` — email→service registration lookup
- `breach_lookup(email)` — breach data check
- `linkedin_recon(company)` — employee enumeration

`threat_intel.py`:
- `virustotal_lookup(ioc)` — IP/domain/hash reputation
- `otx_lookup(ioc)` — AlienVault OTX threat context
- `urlscan_lookup(url)` — passive URL scanning history
- `shodan_cve_lookup(ip)` — known CVEs for IP's exposed services

**Create `core/routes/osint.py`** — 6-8 routes grouping above tools
**Create `mcp/tools/osint.py`** — 4-5 MCP tools grouped by workflow

**Routes moved:** 0
**New routes:** ~8
**MCP tools:** 4-5 OSINT MCP tools

---

### Batch 8 — MCP Reorganization + Final Cleanup

- Move all remaining MCP tool registrations from `hexstrike_mcp.py` into `mcp/tools/`
- Extract `HexStrikeClient` fully to `mcp/client.py`
- `hexstrike_mcp.py` becomes: parse args → import `mcp/server.py` → start (~50 lines)
- `hexstrike_server.py` becomes: parse args → import `core/server.py` → `app.run()` (~50 lines)
- Final full test suite run: all tests green
- Update `CLAUDE.md` and `CHANGELOG.md`

---

## Testing Strategy

**Per-batch structure:**
```
tests/
├── unit/
│   └── test_routes/
│       ├── test_network_routes.py     # Route logic, tools mocked
│       ├── test_web_routes.py
│       └── ...
└── integration/
    └── test_blueprints/
        ├── test_network_blueprint.py  # Flask test client, Blueprint registered
        └── ...
```

**Rules:**
- Tests written before implementation (TDD)
- Tool subprocess calls always mocked — no real tool execution in tests
- Full `pytest` run must stay green after every batch
- MCP modules tested for clean import and tool count correctness
- Target: ~200 new tests added to existing 177

---

## Success Criteria

- `hexstrike_server.py` < 100 lines (thin entry point)
- `hexstrike_mcp.py` < 100 lines (thin launcher)
- All 162 existing routes preserved and passing
- All Phase 2/3 tool modules wired to server routes
- All tools registered as MCP tools (target: 200+ MCP tools, up from 151)
- OSINT implemented: 13 tools, 6-8 routes, 4-5 MCP tools
- Full test suite green: ~377 tests (177 existing + ~200 new)
- `curl http://localhost:8888/health` passes after every batch

---

## What This Is NOT

- This phase does not add new tool categories beyond OSINT
- This phase does not implement Phase 5 (browser agent enhancement, memory optimization)
- This phase does not implement Phase 6 (desktop client, MCP bypass)
- Tool count expands from ~200 wired → 200+ properly registered, not from adding new tools

---

## Files Touched

**Modified:**
- `hexstrike_server.py` — shrinks to ~50 lines
- `hexstrike_mcp.py` — shrinks to ~50 lines
- `core/server.py` — registers all Blueprints

**Created:**
- `core/routes/__init__.py` + 12 Blueprint files
- `mcp/client.py`, `mcp/server.py`, `mcp/tools/__init__.py` + 9 tool files
- `tools/osint/__init__.py` + 3 implementation files
- ~20 test files across unit and integration

**Unchanged:**
- All existing `tools/*/` module files
- All existing `agents/`, `managers/`, `utils/` files
- All existing tests
