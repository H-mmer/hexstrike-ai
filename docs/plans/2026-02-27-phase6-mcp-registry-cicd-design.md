# Phase 6 Design: MCP Grouping + Registry Expansion + CI/CD

## Context

Phase 5b is complete (28/28 tasks, 689 tests, 114 MCP tools). A full audit of the
v7.0 plan reveals the remaining work before the desktop app (the "final piece"):

1. **MCP tool limits**: 114 individual MCP tools will hit client ceilings as we grow.
   Need grouped endpoints via SmartToolRegistry.
2. **Installer registry gap**: `registry.yaml` tracks 105 tools but Phase 2-3 added
   ~75 more tool functions that aren't registered. Installer can't detect/install them.
3. **No CI/CD**: Zero GitHub Actions, no automated quality gate.
4. **Testing gaps**: 689/1000 target tests, no e2e, no load tests, no coverage reports.

## Decision: Grouped-Only MCP Replacement

Replace all 114 individual `@mcp.tool()` functions with ~19 grouped category endpoints.
Each grouped tool accepts a `tool` parameter (enum of sub-tools) and dispatches to the
appropriate Flask route via a `SmartToolRegistry`.

**Rationale**:
- Solves the tool limit problem (114 -> 19)
- Matches the pattern Phase 2-3 already established (mobile/api/wireless are grouped)
- The MCP layer is a thin dispatch wrapper; no capability is lost
- Individual tool functions still exist in `tools/` and `core/routes/`
- Simpler codebase: one registry, one dispatch pattern

## Part 1: SmartToolRegistry + Grouped MCP Tools

### SmartToolRegistry Class

New file: `hexstrike_mcp_tools/registry.py`

```python
class SmartToolRegistry:
    """Maps grouped tool names to sub-tools and their Flask route endpoints."""

    def __init__(self):
        self._categories = {}  # category -> {tool_name -> route_config}

    def register(self, category: str, tool_name: str, route: str, method: str = "POST",
                 params: list = None, description: str = ""):
        ...

    def dispatch(self, category: str, tool_name: str, params: dict) -> dict:
        """Look up route for (category, tool_name), call via client, return result."""
        ...

    def list_tools(self, category: str = None) -> dict:
        """List available tools, optionally filtered by category."""
        ...
```

### Grouped MCP Endpoints (~19 tools)

New file: `hexstrike_mcp_tools/grouped.py`

| # | Grouped Tool | Sub-tools | Count |
|---|---|---|---|
| 1 | `network_scan` | nmap, rustscan, masscan, naabu, zmap, nmap-advanced | 6 |
| 2 | `network_recon` | amass, subfinder, httpx, waybackurls, gau, dnsenum, fierce, autorecon, nbtscan | 9 |
| 3 | `network_enum` | enum4linux, enum4linux-ng, smbmap, netexec, snmp-check, wafw00f | 6 |
| 4 | `network_advanced` | scapy, ipv6, udp-proto, cisco-torch | 4 |
| 5 | `web_scan` | gobuster, nuclei, nikto, ffuf, feroxbuster, dirsearch, wfuzz, katana | 8 |
| 6 | `web_vuln_test` | sqlmap, dalfox, arjun, paramspider | 4 |
| 7 | `web_specialized` | js-analysis, injection-test, cms-scan, auth-test, cdn-bypass, wpscan | 6 |
| 8 | `cloud_assess` | trivy, prowler, kube-hunter, kube-bench, docker-bench, scout-suite, cloudmapper, pacu, falco, checkov, terrascan, kubescape | 12 |
| 9 | `cloud_container` | container-escape, rbac-audit | 2 |
| 10 | `binary_analyze` | gdb, radare2, ghidra, binwalk, checksec, strings, objdump, ropgadget, angr, rizin, msfvenom | 11 |
| 11 | `binary_forensics` | volatility3, foremost, steghide, exiftool, yara, floss, forensics | 7 |
| 12 | `mobile_test` | apk-analyze, ios-analyze, drozer, mitm | 4 |
| 13 | `api_test` | api-discover, api-fuzz, api-auth-test, api-monitor | 4 |
| 14 | `wireless_test` | wifi-attack, bluetooth-scan, rf-analysis | 3 |
| 15 | `osint_gather` | passive-recon, threat-intel, social-recon, breach-check, shodan | 5 |
| 16 | `intelligence` | analyze-target, select-tools, attack-chain, tech-detect, optimize-params, cve-monitor, exploit-gen, threat-intel, payload-gen, advanced-payload, test-payload, vuln-correlate | 12 |
| 17 | `async_scan` | submit, poll, list, cancel | 4 |
| 18 | `browser_stealth` | navigate, screenshot, dom, form-fill | 4 |
| 19 | `system_admin` | health, command, cache-stats, cache-clear, telemetry, processes | 6 |

**Total: 19 grouped MCP tools exposing 114+ sub-tools**

### Migration Strategy

1. Create `registry.py` with SmartToolRegistry
2. Create `grouped.py` with 19 grouped `@mcp.tool()` functions
3. Populate registry from existing route definitions
4. Update `hexstrike_mcp.py` to import `grouped` instead of individual modules
5. Keep old modules in place (importable for tests) but remove their `@mcp.tool()` decorators
6. Add `list_available_tools` MCP tool for AI agent discovery

### Testing

- Unit tests for SmartToolRegistry (register, dispatch, list)
- Unit tests for each grouped endpoint (mock dispatch)
- Integration test: verify all 114+ sub-tools are reachable through grouped endpoints
- Regression: ensure existing test suite still passes

## Part 2: Registry Expansion

Expand `scripts/installer/registry.yaml` from 105 to ~180 entries.

### New entries to add (by category):

**Mobile** (~8 new): apktool, jadx, androguard, mobsf, frida, dex2jar, objection, drozer
**Wireless** (~8 new): wifite2, airgeddon, bettercap, reaver, fluxion, btlejack, rtl-sdr, hackrf
**Web enhanced** (~10 new): nosqlmap, xxeinjector, joomscan, droopescan, retire.js, linkfinder, jsluice, secretfinder, saml-raider
**Binary enhanced** (~8 new): cutter, binary-ninja-free, pwndbg, unicorn, capstone, cuckoo-sandbox, pestudio, hollows-hunter
**Cloud enhanced** (~7 new): kubescape, popeye, rbac-police, kubesec, deepce, amicontained, peirates
**Network enhanced** (~5 new): autorecon, nbtscan, cisco-torch, vlan-hopper, ipv6toolkit
**Forensics enhanced** (~4 new): plaso, rekall, ftk-imager-cli, guymager

Each entry needs: package name, manager (apt/pip/npm), category, tier, description.

### Update modes and categories

- Update mode tool counts in `scripts/installer/modes/`
- Update category filters if new sub-categories needed
- Update existing tests to use flexible `>=` assertions (already done)

## Part 3: CI/CD + Testing

### GitHub Actions Pipeline

New file: `.github/workflows/ci.yml`

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -r requirements.txt
      - run: pytest --tb=short -q
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install ruff
      - run: ruff check .
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install bandit
      - run: bandit -r core/ agents/ managers/ tools/ -f json -o security-report.json || true
```

### Testing Expansion

Target: 689 -> ~850 tests

- Route integration tests for under-tested blueprints (cloud, binary, mobile, wireless, api_security)
- E2E smoke test: start server, hit health endpoint, run a grouped MCP dispatch
- SmartToolRegistry unit + integration tests
- Registry validation tests (all entries have required fields)

### Code Quality

- `ruff.toml` configuration (line length, ignored rules)
- `bandit` security baseline
- `pytest-cov` for coverage reporting in CI

## Sequence

1. **Part 1**: SmartToolRegistry + grouped MCP tools (highest value)
2. **Part 2**: Registry expansion (quick win, independent)
3. **Part 3**: CI/CD + testing (quality gate before desktop app)

## Success Criteria

- MCP tool count: 114 individual -> 19 grouped (+ 1 discovery tool = 20)
- All existing tests pass through grouped dispatch
- Registry: 105 -> ~180 tool entries
- CI/CD: green pipeline on push/PR
- Tests: 689 -> ~850
- No regression in server functionality
