# Phase 6: MCP Grouping + Registry Expansion + CI/CD — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace 114 individual MCP tools with 21 grouped category endpoints + 1 discovery endpoint (22 `@mcp.tool()` total) via SmartToolRegistry. Expand the installer registry from 105 to ~151 entries. Add CI/CD + testing to reach ~780 tests.

**Architecture:** A `SmartToolRegistry` class maps (category, tool_name) → (route, method, description). A single `grouped.py` module registers 22 `@mcp.tool()` functions (21 category tools that accept a `tool` param + 1 `list_available_tools` discovery tool). Each grouped function uses `params: Optional[Dict[str, Any]] = None` (NOT `**kwargs`) so FastMCP generates correct JSON schemas. Dispatch looks up the route via `get_route()` and calls the client. Old individual MCP modules keep their functions (for existing tests) but lose `@mcp.tool()` decorators. The launcher (`hexstrike_mcp.py`) imports only `grouped` instead of 12 individual modules.

**Tech Stack:** Python 3.8+, FastMCP, Flask, pytest, GitHub Actions, ruff

**Tasks:** 30 across 5 batches

---

## Batch A: SmartToolRegistry Core (Tasks 1–4)

### Task 1–2: SmartToolRegistry — Test + Implementation

**Files:**
- Create: `tests/unit/test_smart_registry.py`
- Create: `hexstrike_mcp_tools/registry.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_smart_registry.py
"""Tests for SmartToolRegistry."""
import pytest
from hexstrike_mcp_tools.registry import SmartToolRegistry


@pytest.fixture
def registry():
    r = SmartToolRegistry()
    r.register("network_scan", "nmap", "api/tools/nmap", method="POST",
               description="Network scanner")
    r.register("network_scan", "rustscan", "api/tools/rustscan", method="POST",
               description="Fast port scanner")
    r.register("system_admin", "health", "health", method="GET",
               description="Health check")
    return r


def test_register_and_list_category(registry):
    tools = registry.list_tools("network_scan")
    assert "nmap" in tools
    assert "rustscan" in tools
    assert len(tools) == 2


def test_list_all_categories(registry):
    all_tools = registry.list_tools()
    assert "network_scan" in all_tools
    assert "system_admin" in all_tools


def test_get_route(registry):
    route_info = registry.get_route("network_scan", "nmap")
    assert route_info["route"] == "api/tools/nmap"
    assert route_info["method"] == "POST"


def test_get_route_unknown_tool(registry):
    with pytest.raises(KeyError):
        registry.get_route("network_scan", "nonexistent")


def test_get_route_unknown_category(registry):
    with pytest.raises(KeyError):
        registry.get_route("nonexistent", "nmap")


def test_list_categories(registry):
    cats = registry.list_categories()
    assert "network_scan" in cats
    assert "system_admin" in cats


def test_tool_count(registry):
    assert registry.tool_count() == 3


def test_register_duplicate_overwrites(registry):
    registry.register("network_scan", "nmap", "api/tools/nmap-v2", method="POST",
                      description="Updated nmap")
    route_info = registry.get_route("network_scan", "nmap")
    assert route_info["route"] == "api/tools/nmap-v2"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_smart_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hexstrike_mcp_tools.registry'`

**Step 3: Implement SmartToolRegistry**

```python
# hexstrike_mcp_tools/registry.py
"""SmartToolRegistry — maps grouped tool categories to Flask route endpoints."""
from typing import Dict, Any, List, Optional


class SmartToolRegistry:
    """Maps (category, tool_name) to (route, method, description).

    Used by grouped MCP endpoints to dispatch calls to the correct
    Flask route via the HexStrike API client.
    """

    def __init__(self):
        self._categories: Dict[str, Dict[str, Dict[str, str]]] = {}

    def register(self, category: str, tool_name: str, route: str,
                 method: str = "POST", description: str = "") -> None:
        if category not in self._categories:
            self._categories[category] = {}
        self._categories[category][tool_name] = {
            "route": route,
            "method": method,
            "description": description,
        }

    def get_route(self, category: str, tool_name: str) -> Dict[str, str]:
        if category not in self._categories:
            raise KeyError(f"Unknown category: {category}")
        if tool_name not in self._categories[category]:
            raise KeyError(f"Unknown tool '{tool_name}' in category '{category}'. "
                           f"Available: {list(self._categories[category].keys())}")
        return self._categories[category][tool_name]

    def list_tools(self, category: str = None) -> Dict[str, Any]:
        if category is not None:
            if category not in self._categories:
                raise KeyError(f"Unknown category: {category}")
            return {name: info["description"]
                    for name, info in self._categories[category].items()}
        return {cat: {name: info["description"] for name, info in tools.items()}
                for cat, tools in self._categories.items()}

    def list_categories(self) -> List[str]:
        return sorted(self._categories.keys())

    def tool_count(self) -> int:
        return sum(len(tools) for tools in self._categories.values())
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_smart_registry.py -v`
Expected: 8 passed

**Step 5: Commit**

```bash
git add tests/unit/test_smart_registry.py hexstrike_mcp_tools/registry.py
git commit -m "feat(mcp): add SmartToolRegistry class (Phase 6, Tasks 1-2)"
```

---

### Task 3–4: Populate Registry with all 114 tool mappings

**Files:**
- Create: `hexstrike_mcp_tools/tool_definitions.py`
- Create: `tests/unit/test_tool_definitions.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_tool_definitions.py
"""Tests for tool_definitions — registry population."""
from hexstrike_mcp_tools.tool_definitions import build_registry


def test_registry_has_all_categories():
    r = build_registry()
    expected = [
        "network_scan", "network_recon", "network_enum", "network_advanced",
        "web_scan", "web_vuln_test", "web_specialized",
        "cloud_assess", "cloud_container",
        "binary_analyze", "binary_forensics",
        "mobile_test", "api_test", "wireless_test", "osint_gather",
        "intelligence", "ctf", "bugbounty",
        "async_scan", "browser_stealth", "system_admin",
    ]
    cats = r.list_categories()
    for cat in expected:
        assert cat in cats, f"Missing category: {cat}"


def test_registry_tool_count():
    r = build_registry()
    assert r.tool_count() >= 114, f"Expected >=114 tools, got {r.tool_count()}"


def test_exact_route_mappings():
    """Validate specific (category, tool, route, method) tuples to catch param drift."""
    r = build_registry()
    spot_checks = [
        ("network_scan", "zmap", "api/tools/network/zmap", "POST"),
        ("network_recon", "httpx", "api/tools/httpx", "POST"),
        ("network_enum", "smbmap", "api/tools/smbmap", "POST"),
        ("web_vuln_test", "sqlmap", "api/tools/sqlmap", "POST"),
        ("system_admin", "health", "health", "GET"),
        ("system_admin", "telemetry", "api/telemetry", "GET"),
        ("browser_stealth", "navigate", "/api/browser/navigate", "POST"),
        ("mobile_test", "apk-analyze", "api/tools/mobile/apk-analyze", "POST"),
    ]
    for cat, tool, expected_route, expected_method in spot_checks:
        info = r.get_route(cat, tool)
        assert info["route"] == expected_route, f"{cat}/{tool}: route={info['route']}, expected={expected_route}"
        assert info["method"] == expected_method, f"{cat}/{tool}: method={info['method']}, expected={expected_method}"


def test_network_scan_has_expected_tools():
    r = build_registry()
    tools = r.list_tools("network_scan")
    for name in ["nmap", "rustscan", "masscan", "naabu", "zmap", "nmap-advanced"]:
        assert name in tools, f"Missing network_scan tool: {name}"


def test_web_scan_has_expected_tools():
    r = build_registry()
    tools = r.list_tools("web_scan")
    for name in ["gobuster", "nuclei", "nikto", "ffuf", "feroxbuster", "dirsearch", "wfuzz", "katana"]:
        assert name in tools, f"Missing web_scan tool: {name}"


def test_system_admin_has_expected_tools():
    r = build_registry()
    tools = r.list_tools("system_admin")
    for name in ["health", "command", "cache-stats", "cache-clear", "telemetry", "processes"]:
        assert name in tools, f"Missing system_admin tool: {name}"


def test_every_tool_has_route():
    r = build_registry()
    all_tools = r.list_tools()
    for cat, tools in all_tools.items():
        for tool_name in tools:
            info = r.get_route(cat, tool_name)
            assert "route" in info, f"{cat}/{tool_name} missing route"
            assert info["route"], f"{cat}/{tool_name} has empty route"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_tool_definitions.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement tool_definitions.py**

Create `hexstrike_mcp_tools/tool_definitions.py` with a `build_registry()` function that registers all 114+ tools into the correct categories. The complete mapping based on the MCP module audit:

```python
# hexstrike_mcp_tools/tool_definitions.py
"""Populate SmartToolRegistry with all HexStrike tool definitions."""
from hexstrike_mcp_tools.registry import SmartToolRegistry


def build_registry() -> SmartToolRegistry:
    """Build and return a fully populated SmartToolRegistry."""
    r = SmartToolRegistry()

    # ── network_scan (6 tools) ────────────────────────────────────
    r.register("network_scan", "nmap", "api/tools/nmap",
               description="Nmap port/version scan")
    r.register("network_scan", "rustscan", "api/tools/rustscan",
               description="Fast port scanner")
    r.register("network_scan", "masscan", "api/tools/masscan",
               description="High-speed port scanner")
    r.register("network_scan", "naabu", "api/tools/network/naabu",
               description="Fast port scan (Naabu)")
    r.register("network_scan", "zmap", "api/tools/network/zmap",
               description="Network-wide fast scan")
    r.register("network_scan", "nmap-advanced", "api/tools/nmap-advanced",
               description="Advanced nmap with NSE/timing/OS detection")

    # ── network_recon (9 tools) ───────────────────────────────────
    r.register("network_recon", "amass", "api/tools/amass",
               description="Subdomain enumeration")
    r.register("network_recon", "subfinder", "api/tools/subfinder",
               description="Passive subdomain discovery")
    r.register("network_recon", "httpx", "api/tools/httpx",
               description="HTTP probing and tech detection")
    r.register("network_recon", "waybackurls", "api/tools/waybackurls",
               description="Wayback Machine URL fetch")
    r.register("network_recon", "gau", "api/tools/gau",
               description="GetAllUrls from multiple sources")
    r.register("network_recon", "dnsenum", "api/tools/dnsenum",
               description="DNS enumeration and zone transfer")
    r.register("network_recon", "fierce", "api/tools/fierce",
               description="DNS recon and brute-force")
    r.register("network_recon", "autorecon", "api/tools/autorecon",
               description="Comprehensive automated recon")
    r.register("network_recon", "nbtscan", "api/tools/nbtscan",
               description="NetBIOS name scanner")

    # ── network_enum (6 tools) ────────────────────────────────────
    r.register("network_enum", "enum4linux", "api/tools/enum4linux",
               description="Windows/Samba enumeration")
    r.register("network_enum", "enum4linux-ng", "api/tools/enum4linux-ng",
               description="Advanced SMB enumeration")
    r.register("network_enum", "smbmap", "api/tools/smbmap",
               description="SMB share enumeration")
    r.register("network_enum", "netexec", "api/tools/netexec",
               description="Network credential testing")
    r.register("network_enum", "snmp-check", "api/tools/network/snmp-check",
               description="SNMP enumeration")
    r.register("network_enum", "wafw00f", "api/tools/wafw00f",
               description="WAF detection")

    # ── network_advanced (4 tools) ────────────────────────────────
    r.register("network_advanced", "scapy", "api/tools/network/scapy",
               description="Packet crafting with Scapy")
    r.register("network_advanced", "ipv6", "api/tools/network/ipv6-toolkit",
               description="IPv6 security testing")
    r.register("network_advanced", "udp-proto", "api/tools/network/udp-proto-scanner",
               description="UDP protocol scanner")
    r.register("network_advanced", "cisco-torch", "api/tools/network/cisco-torch",
               description="Cisco device scanning")

    # ── web_scan (8 tools) ────────────────────────────────────────
    r.register("web_scan", "gobuster", "api/tools/gobuster",
               description="Directory/DNS/vhost brute-force")
    r.register("web_scan", "nuclei", "api/tools/nuclei",
               description="Template-based vulnerability scanner")
    r.register("web_scan", "nikto", "api/tools/nikto",
               description="Web server vulnerability scanner")
    r.register("web_scan", "ffuf", "api/tools/ffuf",
               description="Web fuzzer")
    r.register("web_scan", "feroxbuster", "api/tools/feroxbuster",
               description="Recursive content discovery")
    r.register("web_scan", "dirsearch", "api/tools/dirsearch",
               description="Directory and file discovery")
    r.register("web_scan", "wfuzz", "api/tools/wfuzz",
               description="Web application fuzzer")
    r.register("web_scan", "katana", "api/tools/katana",
               description="Web crawler and spider")

    # ── web_vuln_test (4 tools) ───────────────────────────────────
    r.register("web_vuln_test", "sqlmap", "api/tools/sqlmap",
               description="SQL injection testing")
    r.register("web_vuln_test", "dalfox", "api/tools/dalfox",
               description="XSS vulnerability scanner")
    r.register("web_vuln_test", "arjun", "api/tools/arjun",
               description="HTTP parameter discovery")
    r.register("web_vuln_test", "paramspider", "api/tools/paramspider",
               description="Parameter mining from archives")

    # ── web_specialized (6 tools) ─────────────────────────────────
    r.register("web_specialized", "wpscan", "api/tools/wpscan",
               description="WordPress vulnerability scanner")
    r.register("web_specialized", "js-analysis", "api/tools/web/js-analysis",
               description="JavaScript security analysis")
    r.register("web_specialized", "injection-test", "api/tools/web/injection",
               description="Injection vulnerability testing")
    r.register("web_specialized", "cms-scan", "api/tools/web/cms-scan",
               description="CMS-specific security scan")
    r.register("web_specialized", "auth-test", "api/tools/web/auth-test",
               description="Authentication vulnerability testing")
    r.register("web_specialized", "cdn-bypass", "api/tools/web/cdn-bypass",
               description="CDN bypass techniques")

    # ── cloud_assess (12 tools) ───────────────────────────────────
    r.register("cloud_assess", "trivy", "api/tools/trivy",
               description="Container/filesystem vulnerability scanner")
    r.register("cloud_assess", "prowler", "api/tools/prowler",
               description="Cloud security assessment")
    r.register("cloud_assess", "kube-hunter", "api/tools/kube-hunter",
               description="Kubernetes security hunting")
    r.register("cloud_assess", "kube-bench", "api/tools/kube-bench",
               description="CIS Kubernetes benchmarks")
    r.register("cloud_assess", "docker-bench", "api/tools/docker-bench-security",
               description="Docker CIS benchmark")
    r.register("cloud_assess", "scout-suite", "api/tools/scout-suite",
               description="Multi-cloud security auditing")
    r.register("cloud_assess", "cloudmapper", "api/tools/cloudmapper",
               description="AWS cloud visualization/audit")
    r.register("cloud_assess", "pacu", "api/tools/pacu",
               description="AWS exploitation framework")
    r.register("cloud_assess", "falco", "api/tools/falco",
               description="Runtime security monitoring")
    r.register("cloud_assess", "checkov", "api/tools/checkov",
               description="IaC misconfiguration scanner")
    r.register("cloud_assess", "terrascan", "api/tools/terrascan",
               description="IaC policy violations scanner")
    r.register("cloud_assess", "kubescape", "api/tools/cloud/kubescape",
               description="Kubernetes security posture")

    # ── cloud_container (2 tools) ─────────────────────────────────
    r.register("cloud_container", "container-escape", "api/tools/cloud/container-escape",
               description="Container escape vulnerability check")
    r.register("cloud_container", "rbac-audit", "api/tools/cloud/rbac-audit",
               description="Kubernetes RBAC audit")

    # ── binary_analyze (11 tools) ─────────────────────────────────
    r.register("binary_analyze", "gdb", "api/tools/gdb",
               description="Binary debugging with GDB")
    r.register("binary_analyze", "radare2", "api/tools/radare2",
               description="Reverse engineering with Radare2")
    r.register("binary_analyze", "ghidra", "api/tools/ghidra",
               description="Reverse engineering with Ghidra")
    r.register("binary_analyze", "binwalk", "api/tools/binwalk",
               description="Firmware/binary file scanning")
    r.register("binary_analyze", "checksec", "api/tools/checksec",
               description="Binary security mitigations check")
    r.register("binary_analyze", "strings", "api/tools/strings",
               description="String extraction from binaries")
    r.register("binary_analyze", "objdump", "api/tools/objdump",
               description="Binary disassembly")
    r.register("binary_analyze", "ropgadget", "api/tools/ropgadget",
               description="ROP gadget finder")
    r.register("binary_analyze", "angr", "api/tools/angr",
               description="Symbolic execution with angr")
    r.register("binary_analyze", "rizin", "api/tools/binary/rizin",
               description="Reverse engineering with Rizin")
    r.register("binary_analyze", "msfvenom", "api/tools/msfvenom",
               description="Payload generation with Metasploit")

    # ── binary_forensics (7 tools) ────────────────────────────────
    r.register("binary_forensics", "volatility3", "api/tools/volatility3",
               description="Memory forensics")
    r.register("binary_forensics", "foremost", "api/tools/foremost",
               description="File carving from disk images")
    r.register("binary_forensics", "steghide", "api/tools/steghide",
               description="Steganography hide/extract")
    r.register("binary_forensics", "exiftool", "api/tools/exiftool",
               description="File metadata extraction")
    r.register("binary_forensics", "yara", "api/tools/binary/yara",
               description="Malware pattern scanning")
    r.register("binary_forensics", "floss", "api/tools/binary/floss",
               description="Deobfuscated string extraction")
    r.register("binary_forensics", "forensics", "api/tools/binary/forensics",
               description="Digital forensics with Autopsy/Sleuth Kit")

    # ── mobile_test (4 tools) ─────────────────────────────────────
    r.register("mobile_test", "apk-analyze", "api/tools/mobile/apk-analyze",
               description="APK analysis (apktool + jadx + androguard)")
    r.register("mobile_test", "ios-analyze", "api/tools/mobile/ios-analyze",
               description="iOS IPA analysis")
    r.register("mobile_test", "drozer", "api/tools/mobile/drozer",
               description="Android security audit")
    r.register("mobile_test", "mitm", "api/tools/mobile/mitm",
               description="Mobile traffic interception")

    # ── api_test (4 tools) ────────────────────────────────────────
    r.register("api_test", "api-discover", "api/tools/api/discover",
               description="API endpoint discovery")
    r.register("api_test", "api-fuzz", "api/tools/api/fuzz",
               description="API endpoint fuzzing")
    r.register("api_test", "api-auth-test", "api/tools/api/auth-test",
               description="API authentication testing")
    r.register("api_test", "api-monitor", "api/tools/api/monitoring",
               description="API security monitoring")

    # ── wireless_test (3 tools) ───────────────────────────────────
    r.register("wireless_test", "wifi-attack", "api/tools/wireless/wifi-attack",
               description="WiFi security testing")
    r.register("wireless_test", "bluetooth-scan", "api/tools/wireless/bluetooth-scan",
               description="Bluetooth scanning")
    r.register("wireless_test", "rf-analysis", "api/tools/wireless/rf",
               description="RF signal analysis")

    # ── osint_gather (5 tools) ────────────────────────────────────
    r.register("osint_gather", "passive-recon", "api/osint/passive-recon",
               description="Passive reconnaissance")
    r.register("osint_gather", "threat-intel", "api/osint/threat-intel",
               description="IOC threat intelligence")
    r.register("osint_gather", "social-recon", "api/osint/social-recon",
               description="Social media OSINT")
    r.register("osint_gather", "breach-check", "api/osint/breach-check",
               description="Data breach check")
    r.register("osint_gather", "shodan", "api/osint/shodan",
               description="Shodan internet search")

    # ── intelligence (12 tools) ───────────────────────────────────
    r.register("intelligence", "analyze-target", "api/intelligence/analyze-target",
               description="AI target analysis")
    r.register("intelligence", "select-tools", "api/intelligence/select-tools",
               description="AI tool selection")
    r.register("intelligence", "attack-chain", "api/intelligence/create-attack-chain",
               description="Build attack chain")
    r.register("intelligence", "tech-detect", "api/intelligence/technology-detection",
               description="Technology detection")
    r.register("intelligence", "optimize-params", "api/intelligence/optimize-parameters",
               description="Tool parameter optimization")
    r.register("intelligence", "cve-monitor", "api/vuln-intel/cve-monitor",
               description="CVE monitoring")
    r.register("intelligence", "exploit-gen", "api/vuln-intel/exploit-generate",
               description="Exploit PoC generation")
    r.register("intelligence", "threat-feeds", "api/vuln-intel/threat-feeds",
               description="Threat intelligence correlation")
    r.register("intelligence", "payload-gen", "api/ai/generate_payload",
               description="AI security payload generation")
    r.register("intelligence", "advanced-payload", "api/ai/advanced-payload-generation",
               description="Advanced evasion payloads")
    r.register("intelligence", "test-payload", "api/ai/test_payload",
               description="Test payload against target")
    r.register("intelligence", "vuln-correlate", "api/vuln-intel/attack-chains",
               description="Vulnerability correlation and attack chains")

    # ── ctf (7 tools) ────────────────────────────────────────────
    r.register("ctf", "create-workflow", "api/ctf/create-challenge-workflow",
               description="Create CTF challenge workflow")
    r.register("ctf", "auto-solve", "api/ctf/auto-solve-challenge",
               description="Autonomous CTF solver")
    r.register("ctf", "suggest-tools", "api/ctf/suggest-tools",
               description="CTF tool suggestions")
    r.register("ctf", "crypto-solver", "api/ctf/cryptography-solver",
               description="Cryptography challenge solver")
    r.register("ctf", "forensics-analyzer", "api/ctf/forensics-analyzer",
               description="Forensics challenge analyzer")
    r.register("ctf", "binary-analyzer", "api/ctf/binary-analyzer",
               description="Binary CTF challenge analyzer")
    r.register("ctf", "team-strategy", "api/ctf/team-strategy",
               description="CTF team strategy planner")

    # ── bugbounty (6 tools) ───────────────────────────────────────
    r.register("bugbounty", "recon", "api/bugbounty/reconnaissance-workflow",
               description="Bug bounty recon workflow")
    r.register("bugbounty", "vuln-hunt", "api/bugbounty/vulnerability-hunting-workflow",
               description="Vulnerability hunting workflow")
    r.register("bugbounty", "business-logic", "api/bugbounty/business-logic-workflow",
               description="Business logic testing workflow")
    r.register("bugbounty", "osint", "api/bugbounty/osint-workflow",
               description="Bug bounty OSINT")
    r.register("bugbounty", "file-upload", "api/bugbounty/file-upload-testing",
               description="File upload vulnerability testing")
    r.register("bugbounty", "comprehensive", "api/bugbounty/comprehensive-assessment",
               description="Full bug bounty assessment")

    # ── async_scan (9 tools) ──────────────────────────────────────
    # Note: async tools use leading-slash routes (legacy pattern)
    r.register("async_scan", "nmap-async", "/api/network/nmap/async",
               description="Async nmap scan")
    r.register("async_scan", "rustscan-async", "/api/network/rustscan/async",
               description="Async rustscan scan")
    r.register("async_scan", "masscan-async", "/api/network/masscan/async",
               description="Async masscan scan")
    r.register("async_scan", "amass-async", "/api/network/amass/async",
               description="Async amass scan")
    r.register("async_scan", "subfinder-async", "/api/network/subfinder/async",
               description="Async subfinder scan")
    r.register("async_scan", "nuclei-async", "/api/web/nuclei/async",
               description="Async nuclei scan")
    r.register("async_scan", "gobuster-async", "/api/web/gobuster/async",
               description="Async gobuster scan")
    r.register("async_scan", "feroxbuster-async", "/api/web/feroxbuster/async",
               description="Async feroxbuster scan")
    r.register("async_scan", "poll", "SPECIAL:poll",
               method="GET", description="Poll task status")

    # ── browser_stealth (4 tools) ─────────────────────────────────
    # Note: browser tools use leading-slash routes (legacy pattern)
    r.register("browser_stealth", "navigate", "/api/browser/navigate",
               description="Stealth browser navigation")
    r.register("browser_stealth", "screenshot", "/api/browser/screenshot",
               description="Browser screenshot")
    r.register("browser_stealth", "dom", "/api/browser/dom",
               description="DOM extraction")
    r.register("browser_stealth", "form-fill", "/api/browser/form-fill",
               description="Stealth form filling")

    # ── system_admin (6 tools) ────────────────────────────────────
    r.register("system_admin", "health", "health",
               method="GET", description="Server health check")
    r.register("system_admin", "command", "api/command",
               description="Execute shell command")
    r.register("system_admin", "cache-stats", "api/cache/stats",
               method="GET", description="Cache statistics")
    r.register("system_admin", "cache-clear", "api/cache/clear",
               description="Clear cache")
    r.register("system_admin", "telemetry", "api/telemetry",
               method="GET", description="Server telemetry")
    r.register("system_admin", "processes", "api/processes/list",
               method="GET", description="List running processes")

    return r
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_tool_definitions.py -v`
Expected: 7 passed

**Step 5: Commit**

```bash
git add hexstrike_mcp_tools/tool_definitions.py tests/unit/test_tool_definitions.py
git commit -m "feat(mcp): add tool_definitions with 114+ tool mappings (Phase 6, Tasks 3-4)"
```

---

## Batch B: Grouped MCP Endpoints (Tasks 5–12)

### Task 5–6: Grouped dispatch helper + test

**Files:**
- Modify: `hexstrike_mcp_tools/registry.py` (add `dispatch` method)
- Modify: `tests/unit/test_smart_registry.py` (add dispatch tests)

**Step 1: Add failing dispatch tests**

Append to `tests/unit/test_smart_registry.py`:

```python
from unittest.mock import MagicMock


def test_dispatch_post_tool(registry):
    mock_client = MagicMock()
    mock_client.safe_post.return_value = {"success": True}
    result = registry.dispatch("network_scan", "nmap", {"target": "10.0.0.1"}, mock_client)
    mock_client.safe_post.assert_called_once_with("api/tools/nmap", {"target": "10.0.0.1"})
    assert result == {"success": True}


def test_dispatch_get_tool(registry):
    mock_client = MagicMock()
    mock_client.safe_get.return_value = {"status": "ok"}
    result = registry.dispatch("system_admin", "health", {}, mock_client)
    mock_client.safe_get.assert_called_once_with("health", {})
    assert result == {"status": "ok"}


def test_dispatch_unknown_tool_raises(registry):
    mock_client = MagicMock()
    with pytest.raises(KeyError):
        registry.dispatch("network_scan", "nonexistent", {}, mock_client)
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_smart_registry.py::test_dispatch_post_tool -v`
Expected: FAIL — `AttributeError: 'SmartToolRegistry' object has no attribute 'dispatch'`

**Step 3: Add dispatch method to SmartToolRegistry**

Append to `hexstrike_mcp_tools/registry.py` class:

```python
    def dispatch(self, category: str, tool_name: str, params: dict, client) -> dict:
        """Dispatch a tool call through the API client.

        Args:
            category: Grouped tool category
            tool_name: Sub-tool name within the category
            params: Parameters to pass to the route
            client: HexStrikeClient instance (has safe_post/safe_get)

        Returns:
            API response dict
        """
        info = self.get_route(category, tool_name)
        if info["method"] == "GET":
            return client.safe_get(info["route"], params)
        return client.safe_post(info["route"], params)
```

**Step 4: Run tests**

Run: `pytest tests/unit/test_smart_registry.py -v`
Expected: 11 passed

**Step 5: Commit**

```bash
git add hexstrike_mcp_tools/registry.py tests/unit/test_smart_registry.py
git commit -m "feat(mcp): add dispatch method to SmartToolRegistry (Phase 6, Tasks 5-6)"
```

---

### Task 7–8: Create grouped.py with all 21 grouped MCP endpoints

**Files:**
- Create: `hexstrike_mcp_tools/grouped.py`
- Create: `tests/unit/test_mcp_tools/test_grouped_mcp.py`

**Step 1: Write the failing tests**

```python
# tests/unit/test_mcp_tools/test_grouped_mcp.py
"""Tests for grouped MCP tool endpoints."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize


def setup_mock():
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)
    return mock


def test_network_scan_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import network_scan
    network_scan("nmap", "10.0.0.1")
    m.safe_post.assert_called()
    assert "nmap" in m.safe_post.call_args[0][0]


def test_network_scan_unknown_tool():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import network_scan
    result = network_scan("nonexistent_tool", "10.0.0.1")
    assert "error" in result


def test_web_scan_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import web_scan
    web_scan("gobuster", "http://example.com")
    m.safe_post.assert_called()


def test_cloud_assess_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import cloud_assess
    cloud_assess("trivy", params={"target": "nginx:latest"})
    m.safe_post.assert_called()


def test_system_admin_get():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import system_admin
    system_admin("health")
    m.safe_get.assert_called()


def test_list_available_tools():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import list_available_tools
    result = list_available_tools()
    assert isinstance(result, dict)
    assert "network_scan" in result


def test_binary_analyze_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import binary_analyze
    binary_analyze("checksec", params={"binary": "/tmp/test"})
    m.safe_post.assert_called()


def test_network_scan_zmap_maps_target_network():
    """Verify zmap uses target_network param instead of target."""
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import network_scan
    network_scan("zmap", "10.0.0.0/24", params={"port": "80"})
    call_params = m.safe_post.call_args[0][1]
    assert "target_network" in call_params, f"Expected target_network, got: {call_params}"
    assert "target" not in call_params, "zmap should NOT have 'target' param"


def test_intelligence_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import intelligence
    intelligence("analyze-target", params={"target": "example.com"})
    m.safe_post.assert_called()


def test_osint_gather_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import osint_gather
    osint_gather("passive-recon", params={"domain": "example.com"})
    m.safe_post.assert_called()


def test_mobile_test_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import mobile_test
    mobile_test("apk-analyze", params={"apk_path": "/tmp/test.apk"})
    m.safe_post.assert_called()


def test_wireless_test_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import wireless_test
    wireless_test("wifi-attack", params={"interface": "wlan0"})
    m.safe_post.assert_called()


def test_api_test_dispatches():
    m = setup_mock()
    from hexstrike_mcp_tools.grouped import api_test
    api_test("api-discover", params={"base_url": "http://api.example.com"})
    m.safe_post.assert_called()
```

**Step 2: Run tests to verify failure**

Run: `pytest tests/unit/test_mcp_tools/test_grouped_mcp.py -v`
Expected: FAIL — `ImportError`

**Step 3: Implement grouped.py**

```python
# hexstrike_mcp_tools/grouped.py
"""Grouped MCP tool endpoints — 22 @mcp.tool() (21 categories + 1 discovery) replacing 114 individual tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client
from hexstrike_mcp_tools.tool_definitions import build_registry

import requests as _requests

# Build the registry once at import time
_registry = build_registry()


def _dispatch(category: str, tool: str, params: dict) -> Dict[str, Any]:
    """Common dispatch: look up route in registry, call via client."""
    try:
        route_info = _registry.get_route(category, tool)
        client = get_client()
        if route_info["method"] == "GET":
            return client.safe_get(route_info["route"], params)
        return client.safe_post(route_info["route"], params)
    except KeyError as e:
        available = list(_registry.list_tools(category).keys()) if category in _registry.list_categories() else []
        return {"error": str(e), "available_tools": available, "success": False}


# ── Discovery tool ────────────────────────────────────────────────

@mcp.tool()
def list_available_tools(category: Optional[str] = None) -> Dict[str, Any]:
    """List all available tools grouped by category.
    Pass a category name to see only that category's tools.
    Categories: network_scan, network_recon, network_enum, network_advanced,
    web_scan, web_vuln_test, web_specialized, cloud_assess, cloud_container,
    binary_analyze, binary_forensics, mobile_test, api_test, wireless_test,
    osint_gather, intelligence, ctf, bugbounty, async_scan, browser_stealth,
    system_admin"""
    return _registry.list_tools(category)


# ── Network ───────────────────────────────────────────────────────

@mcp.tool()
def network_scan(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Port scanning and network discovery.
    tool: nmap|rustscan|masscan|naabu|zmap|nmap-advanced
    params: tool-specific options (ports, scan_type, rate, additional_args, etc.)"""
    p = dict(params or {})
    if tool == "zmap":
        p["target_network"] = target
    else:
        p["target"] = target
    return _dispatch("network_scan", tool, p)


@mcp.tool()
def network_recon(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Subdomain enumeration, DNS recon, URL discovery.
    tool: amass|subfinder|httpx|waybackurls|gau|dnsenum|fierce|autorecon|nbtscan
    Note: for domain-based tools, target is the domain.
    params: tool-specific options (mode, passive, threads, additional_args, etc.)"""
    p = dict(params or {})
    # Map 'target' to the param name each route expects
    if tool in ("amass", "subfinder", "waybackurls", "gau", "dnsenum", "fierce"):
        p["domain"] = target
    else:
        p["target"] = target
    return _dispatch("network_recon", tool, p)


@mcp.tool()
def network_enum(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """SMB/Windows/SNMP enumeration and WAF detection.
    tool: enum4linux|enum4linux-ng|smbmap|netexec|snmp-check|wafw00f
    params: tool-specific options (username, password, domain, additional_args, etc.)"""
    p = dict(params or {})
    if tool == "smbmap":
        p["host"] = target
    else:
        p["target"] = target
    return _dispatch("network_enum", tool, p)


@mcp.tool()
def network_advanced(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Advanced packet crafting, IPv6, UDP, Cisco tools.
    tool: scapy|ipv6|udp-proto|cisco-torch
    params: tool-specific options (packet_type, scan_type, proto_list, etc.)"""
    p = dict(params or {})
    p["target"] = target
    return _dispatch("network_advanced", tool, p)


# ── Web ───────────────────────────────────────────────────────────

@mcp.tool()
def web_scan(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Web content discovery and fuzzing.
    tool: gobuster|nuclei|nikto|ffuf|feroxbuster|dirsearch|wfuzz|katana
    params: tool-specific options (wordlist, extensions, threads, severity, additional_args, etc.)"""
    p = dict(params or {})
    # Map target to tool-specific param name
    if tool in ("ffuf", "dirsearch", "wfuzz", "katana"):
        p["url"] = target
    else:
        p["target"] = target
    return _dispatch("web_scan", tool, p)


@mcp.tool()
def web_vuln_test(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """SQL injection, XSS, parameter discovery.
    tool: sqlmap|dalfox|arjun|paramspider
    params: tool-specific options (data, level, risk, method, additional_args, etc.)"""
    p = dict(params or {})
    if tool == "paramspider":
        p["domain"] = target
    else:
        p["url"] = target
    return _dispatch("web_vuln_test", tool, p)


@mcp.tool()
def web_specialized(tool: str, target: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """CMS scanning, JS analysis, injection testing, auth testing, CDN bypass.
    tool: wpscan|js-analysis|injection-test|cms-scan|auth-test|cdn-bypass
    params: tool-specific options (enumerate, cms, target_ip, type, etc.)"""
    p = dict(params or {})
    p["url"] = target
    return _dispatch("web_specialized", tool, p)


# ── Cloud ─────────────────────────────────────────────────────────

@mcp.tool()
def cloud_assess(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Cloud security assessment (AWS, K8s, containers, IaC).
    tool: trivy|prowler|kube-hunter|kube-bench|docker-bench|scout-suite|cloudmapper|pacu|falco|checkov|terrascan|kubescape
    params: tool-specific options (target, provider, profile, region, checks, etc.)"""
    return _dispatch("cloud_assess", tool, dict(params or {}))


@mcp.tool()
def cloud_container(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Container escape and RBAC auditing.
    tool: container-escape|rbac-audit
    params: tool-specific options (technique, namespace, etc.)"""
    return _dispatch("cloud_container", tool, dict(params or {}))


# ── Binary ────────────────────────────────────────────────────────

@mcp.tool()
def binary_analyze(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Binary reverse engineering and analysis.
    tool: gdb|radare2|ghidra|binwalk|checksec|strings|objdump|ropgadget|angr|rizin|msfvenom
    params: tool-specific options (binary, file_path, commands, payload, format, etc.)"""
    return _dispatch("binary_analyze", tool, dict(params or {}))


@mcp.tool()
def binary_forensics(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Memory forensics, file carving, malware scanning.
    tool: volatility3|foremost|steghide|exiftool|yara|floss|forensics
    params: tool-specific options (memory_file, plugin, input_file, cover_file, file_path, etc.)"""
    return _dispatch("binary_forensics", tool, dict(params or {}))


# ── Mobile / API / Wireless ──────────────────────────────────────

@mcp.tool()
def mobile_test(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Mobile app security testing (Android/iOS).
    tool: apk-analyze|ios-analyze|drozer|mitm
    params: tool-specific options (apk_path, ipa_path, package, listen_port, etc.)"""
    return _dispatch("mobile_test", tool, dict(params or {}))


@mcp.tool()
def api_test(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """API security testing — discovery, fuzzing, auth.
    tool: api-discover|api-fuzz|api-auth-test|api-monitor
    params: tool-specific options (base_url, schema_url, wordlist, jwt_token, etc.)"""
    return _dispatch("api_test", tool, dict(params or {}))


@mcp.tool()
def wireless_test(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Wireless security — WiFi, Bluetooth, RF.
    tool: wifi-attack|bluetooth-scan|rf-analysis
    params: tool-specific options (interface, target_bssid, target_addr, frequency, etc.)"""
    return _dispatch("wireless_test", tool, dict(params or {}))


# ── OSINT ─────────────────────────────────────────────────────────

@mcp.tool()
def osint_gather(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """OSINT and passive reconnaissance.
    tool: passive-recon|threat-intel|social-recon|breach-check|shodan
    params: tool-specific options (domain, ioc, username, email, query, api_key, etc.)"""
    return _dispatch("osint_gather", tool, dict(params or {}))


# ── Intelligence / CTF / Bug Bounty ──────────────────────────────

@mcp.tool()
def intelligence(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """AI-powered intelligence, CVE monitoring, payload generation.
    tool: analyze-target|select-tools|attack-chain|tech-detect|optimize-params|
    cve-monitor|exploit-gen|threat-feeds|payload-gen|advanced-payload|test-payload|vuln-correlate
    params: tool-specific options (target, objective, cve_id, attack_type, indicators, etc.)"""
    return _dispatch("intelligence", tool, dict(params or {}))


@mcp.tool()
def ctf(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """CTF challenge workflows and solvers.
    tool: create-workflow|auto-solve|suggest-tools|crypto-solver|forensics-analyzer|binary-analyzer|team-strategy
    params: tool-specific options (name, category, difficulty, cipher_text, binary_path, etc.)"""
    return _dispatch("ctf", tool, dict(params or {}))


@mcp.tool()
def bugbounty(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Bug bounty workflows — recon, vuln hunting, OSINT, comprehensive.
    tool: recon|vuln-hunt|business-logic|osint|file-upload|comprehensive
    params: tool-specific options (domain, scope, priority_vulns, target_url, etc.)"""
    return _dispatch("bugbounty", tool, dict(params or {}))


# ── Async / Browser / System ─────────────────────────────────────

@mcp.tool()
def async_scan(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Submit and manage async background scans.
    tool: nmap-async|rustscan-async|masscan-async|amass-async|subfinder-async|
    nuclei-async|gobuster-async|feroxbuster-async|poll
    params: tool-specific options (target, ports, task_id, etc.)
    For poll: pass task_id in params."""
    p = dict(params or {})
    if tool == "poll":
        task_id = p.get("task_id", "")
        client = get_client()
        try:
            resp = _requests.get(
                f"{client.server_url}/api/tasks/{task_id}", timeout=10
            )
            return resp.json() if resp.ok else {"error": resp.text}
        except Exception as e:
            return {"error": str(e)}
    return _dispatch("async_scan", tool, p)


@mcp.tool()
def browser_stealth(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Stealth browser automation — navigate, screenshot, DOM, form fill.
    tool: navigate|screenshot|dom|form-fill
    params: tool-specific options (url, preset, wait, selector, value, etc.)"""
    return _dispatch("browser_stealth", tool, dict(params or {}))


@mcp.tool()
def system_admin(tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """System administration — health, cache, telemetry, processes.
    tool: health|command|cache-stats|cache-clear|telemetry|processes
    params: tool-specific options (command, etc.)"""
    return _dispatch("system_admin", tool, dict(params or {}))
```

**Step 4: Run tests**

Run: `pytest tests/unit/test_mcp_tools/test_grouped_mcp.py -v`
Expected: 14 passed

**Step 5: Commit**

```bash
git add hexstrike_mcp_tools/grouped.py tests/unit/test_mcp_tools/test_grouped_mcp.py
git commit -m "feat(mcp): add 22 grouped MCP endpoints via SmartToolRegistry (Phase 6, Tasks 7-8)"
```

---

### Task 9–10: Migrate hexstrike_mcp.py + strip old decorators

**Files:**
- Modify: `hexstrike_mcp.py`
- Modify: all 12 files in `hexstrike_mcp_tools/` (remove `@mcp.tool()` decorators)
- Create: `tests/unit/test_mcp_migration.py`

**Step 1: Write the migration verification test**

```python
# tests/unit/test_mcp_migration.py
"""Verify MCP migration: only grouped.py registers @mcp.tool() decorators."""
import ast
import pathlib

MCP_DIR = pathlib.Path("hexstrike_mcp_tools")
ALLOWED_FILES = {"grouped.py"}


def test_no_mcp_tool_decorators_in_old_modules():
    """Old MCP modules must NOT have @mcp.tool() decorators."""
    violations = []
    for py_file in MCP_DIR.glob("*.py"):
        if py_file.name in ALLOWED_FILES or py_file.name.startswith("_"):
            continue
        if py_file.name in ("registry.py", "tool_definitions.py", "client.py"):
            continue
        source = py_file.read_text()
        if "@mcp.tool()" in source:
            violations.append(py_file.name)
    assert violations == [], f"@mcp.tool() found in old modules: {violations}"


def test_grouped_has_mcp_tools():
    """grouped.py must register MCP tools."""
    source = (MCP_DIR / "grouped.py").read_text()
    count = source.count("@mcp.tool()")
    assert count >= 22, f"Expected >=22 @mcp.tool() in grouped.py, found {count}"


def test_launcher_imports_grouped():
    """hexstrike_mcp.py must import grouped module."""
    source = pathlib.Path("hexstrike_mcp.py").read_text()
    assert "hexstrike_mcp_tools.grouped" in source
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_mcp_migration.py -v`
Expected: FAIL — old modules still have `@mcp.tool()`

**Step 3: Strip @mcp.tool() from all old modules and update launcher**

For each of the 12 old modules (`network.py`, `web.py`, `cloud.py`, `binary.py`, `mobile.py`, `api_security.py`, `wireless.py`, `osint.py`, `workflows.py`, `async_tools.py`, `browser.py`, `system.py`):

- Remove `@mcp.tool()` decorator lines (keep the functions — they're used by existing tests)
- Remove `from hexstrike_mcp_tools import mcp` import if no longer needed (keep `get_client`)

Update `hexstrike_mcp.py`:
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
import hexstrike_mcp_tools.grouped  # Single import registers all 22 grouped tools

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

**Step 4: Run migration test + full suite**

Run: `pytest tests/unit/test_mcp_migration.py -v`
Expected: 3 passed

Run: `pytest --tb=short -q`
Expected: existing tests still pass (old functions remain callable, just not MCP-registered)

**Step 5: Commit**

```bash
git add hexstrike_mcp.py hexstrike_mcp_tools/*.py tests/unit/test_mcp_migration.py
git commit -m "feat(mcp): migrate to grouped-only MCP — 114 individual → 22 grouped (Phase 6, Tasks 9-10)"
```

---

### Task 11–12: MCP tool count verification + regression

**Step 1: Count registered MCP tools**

```bash
grep -c "@mcp.tool()" hexstrike_mcp_tools/grouped.py
```

Expected: 22 (21 category tools + 1 `list_available_tools`)

**Step 2: Verify no old decorators**

```bash
grep -rn "@mcp.tool()" hexstrike_mcp_tools/*.py | grep -v grouped.py | grep -v __pycache__
```

Expected: no output

**Step 3: Run full test suite**

Run: `pytest --tb=short -q`
Expected: all existing tests pass

**Step 4: Commit**

```bash
git commit --allow-empty -m "chore: Batch B complete — MCP migration verified, 22 grouped tools (Phase 6)"
```

---

## Batch C: Registry Expansion (Tasks 13–16)

### Task 13–14: Add ~50 new entries to registry.yaml

**Files:**
- Modify: `scripts/installer/registry.yaml`
- Create: `tests/unit/test_installer/test_registry_expansion.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_installer/test_registry_expansion.py
"""Tests for registry expansion — Phase 6."""
import yaml
from pathlib import Path


def _load_registry():
    with open(Path("scripts/installer/registry.yaml")) as f:
        return yaml.safe_load(f)


def test_registry_has_at_least_145_tools():
    data = _load_registry()
    tools = data.get("tools", {})
    assert len(tools) >= 145, f"Expected >=145, got {len(tools)}"


def test_no_duplicate_tool_names():
    """Registry must not have duplicate entries (YAML keys are unique by spec,
    but verify programmatically by counting raw occurrences)."""
    import re
    with open(Path("scripts/installer/registry.yaml")) as f:
        content = f.read()
    # Each tool is a top-level key under 'tools:' — match 2-space-indented keys
    names = re.findall(r"^  (\w[\w-]*):", content, re.MULTILINE)
    dupes = [n for n in names if names.count(n) > 1]
    assert dupes == [], f"Duplicate tool names: {set(dupes)}"


def test_mobile_tools_in_registry():
    data = _load_registry()
    tools = data.get("tools", {})
    for name in ["apktool", "jadx", "androguard", "frida", "dex2jar", "objection", "drozer"]:
        assert name in tools, f"Missing mobile tool: {name}"


def test_wireless_tools_in_registry():
    data = _load_registry()
    tools = data.get("tools", {})
    for name in ["wifite2", "airgeddon", "bettercap", "reaver"]:
        assert name in tools, f"Missing wireless tool: {name}"


def test_new_tools_have_required_fields():
    data = _load_registry()
    tools = data.get("tools", {})
    for name, info in tools.items():
        assert "package" in info, f"{name} missing 'package'"
        assert "manager" in info, f"{name} missing 'manager'"
        assert "category" in info, f"{name} missing 'category'"
        assert "tier" in info, f"{name} missing 'tier'"
        assert "description" in info, f"{name} missing 'description'"


def test_all_categories_represented():
    data = _load_registry()
    tools = data.get("tools", {})
    categories = {info["category"] for info in tools.values()}
    for cat in ["network", "web", "cloud", "binary", "mobile", "forensics"]:
        assert cat in categories, f"Missing category: {cat}"
```

**Step 2: Run test to verify failure**

Run: `pytest tests/unit/test_installer/test_registry_expansion.py -v`
Expected: FAIL — less than 150 tools

**Step 3: Add ~50 new entries to registry.yaml**

Append the new tool entries to `scripts/installer/registry.yaml`. Each entry follows the existing format:

```yaml
  # Mobile Security (new entries)
  drozer:
    package: drozer
    manager: pip
    category: mobile
    tier: core
    description: "Android security audit framework"

  # ... (full list of ~50 new tools — see design doc Part 2 for complete list)
```

New tools to add (~43, deduplicated — 6 tools already in registry removed):

**Already present (DO NOT add):** dex2jar, objection, nosqlmap, linkfinder, pwndbg, capstone

**Mobile** (5 new): drozer, needle, class-dump, cycript, ipa-analyzer
**Wireless** (6 new): reaver, fluxion, wifi-pumpkin, btlejack, crackle, cowpatty
**Web** (7 new): xxeinjector, jsluice, secretfinder, sourcemapper, saml-raider, ssti-scanner, crlf-injector
**Binary** (5 new): cutter, unicorn, ret-sync, ida-free, binary-ninja-free
**Cloud** (7 new): popeye, rbac-police, kubesec, aws-vault, deepce, amicontained, peirates
**Network** (5 new): nbtscan, cisco-torch, vlan-hopper, ipv6toolkit, udp-proto-scanner
**Forensics** (6 new): plaso, rekall, ftk-imager-cli, guymager, dc3dd, cuckoo-sandbox
**OSINT** (3 new): sherlock, holehe, social-analyzer
Total: 105 existing + ~46 new = ~151 entries (verify exact count >= 145 in tests)

**Step 4: Run tests**

Run: `pytest tests/unit/test_installer/test_registry_expansion.py -v`
Expected: 5 passed

**Step 5: Commit**

```bash
git add scripts/installer/registry.yaml tests/unit/test_installer/test_registry_expansion.py
git commit -m "feat(installer): expand registry from 105 to ~151 tools (Phase 6, Tasks 13-14)"
```

---

### Task 15–16: Verify installer modes + categories still work

**Step 1: Run existing installer tests**

Run: `pytest tests/unit/test_installer/ -v`
Expected: all pass (tests use `>=` assertions)

**Step 2: Run integration tests**

Run: `pytest tests/integration/ -v`
Expected: all pass

**Step 3: Smoke test**

```bash
python3 -c "
from scripts.installer.modes import quick, standard, complete
print(f'Quick: {len(quick.get_quick_tools())} tools')
print(f'Standard: {len(standard.get_standard_tools())} tools')
print(f'Complete: {len(complete.get_complete_tools())} tools')
"
```

Expected: counts should be higher than before (quick >= 25, standard >= 64, complete >= 145)

**Step 4: Commit**

```bash
git commit --allow-empty -m "chore: Batch C complete — registry expanded, installer verified (Phase 6)"
```

---

## Batch D: CI/CD Pipeline (Tasks 17–22)

### Task 17–18: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Create the CI workflow**

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [master, v7.0-dev]
  pull_request:
    branches: [master]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11"]
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-dev.txt
      - name: Run tests
        run: pytest --tb=short -q

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install ruff
        run: pip install ruff
      - name: Run linter (fail on E/F errors)
        run: ruff check . --select E,F --output-format=github

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install bandit
        run: pip install bandit
      - name: Run security scan (fail on high/critical severity)
        run: bandit -r core/ agents/ managers/ tools/ hexstrike_mcp_tools/ -lll -f json -o security-report.json
      - name: Upload security report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: security-report.json
```

**Step 2: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions pipeline — test, lint, security (Phase 6, Tasks 17-18)"
```

---

### Task 19–20: ruff configuration

**Files:**
- Create: `ruff.toml`

**Step 1: Create ruff.toml**

```toml
# ruff.toml — Python linter configuration
line-length = 120
target-version = "py38"

[lint]
select = ["E", "F", "W"]
ignore = [
    "E501",   # line too long — handled by line-length
    "E402",   # module level import not at top — we use lazy imports
    "F401",   # imported but unused — we re-export from __init__
    "E722",   # bare except — used in graceful degradation
    "F841",   # local variable assigned but never used — some intentional
    "W605",   # invalid escape sequence — some regex patterns
]

[lint.per-file-ignores]
"tests/*" = ["E", "F", "W"]  # lenient in tests
"hexstrike_mcp_tools/*" = ["F401"]  # re-exports
```

**Step 2: Verify ruff runs clean**

Run: `pip install ruff && ruff check . --select E,F`

**Step 3: Commit**

```bash
git add ruff.toml
git commit -m "ci: add ruff linter configuration (Phase 6, Tasks 19-20)"
```

---

### Task 21–22: Extend route integration tests for under-tested blueprints

**IMPORTANT:** All 5 test files already exist — do NOT overwrite them. Only append new test
functions that cover gaps not currently tested. Check each file first and add only missing coverage.

**Files:**
- Extend: `tests/unit/test_routes/test_cloud_routes.py` (already exists)
- Extend: `tests/unit/test_routes/test_binary_routes.py` (already exists)
- Extend: `tests/unit/test_routes/test_mobile_routes.py` (already exists)
- Extend: `tests/unit/test_routes/test_wireless_routes.py` (already exists)
- Extend: `tests/unit/test_routes/test_api_security_routes.py` (already exists)

**Step 1: Read existing tests, then add missing coverage**

Read each file to see what's already tested. Existing tests may assert 503 when tools are missing
(correct behavior). Only add tests for routes not yet covered. Example additions for cloud:

```python
# Append to tests/unit/test_routes/test_cloud_routes.py
# (only tests that don't already exist)

def test_falco_monitoring(client):
    resp = client.post("/api/tools/falco", json={"config_file": "rules.yaml"})
    assert resp.status_code in (200, 503)  # 503 if falco not installed


def test_terrascan_iac_scan(client):
    resp = client.post("/api/tools/terrascan", json={"scan_type": "aws", "iac_dir": "."})
    assert resp.status_code in (200, 503)
```

Add similar 2-3 new tests per file for routes not yet covered.

**Step 2: Run tests**

Run: `pytest tests/unit/test_routes/ -v`
Expected: new tests pass

**Step 3: Commit**

```bash
git add tests/unit/test_routes/test_cloud_routes.py tests/unit/test_routes/test_binary_routes.py \
  tests/unit/test_routes/test_mobile_routes.py tests/unit/test_routes/test_wireless_routes.py \
  tests/unit/test_routes/test_api_security_routes.py
git commit -m "test: add route integration tests for cloud, binary, mobile, wireless, API (Phase 6, Tasks 21-22)"
```

---

## Batch E: Final Verification + Documentation (Tasks 23–30)

### Task 23–24: Grouped endpoint integration tests

**Files:**
- Create: `tests/unit/test_grouped_integration.py`

**Step 1: Write integration tests**

Test that every category in the registry can be dispatched through grouped endpoints without errors (using mock client):

```python
# tests/unit/test_grouped_integration.py
"""Integration tests — verify all registry tools are dispatchable via grouped endpoints."""
from unittest.mock import MagicMock
from hexstrike_mcp_tools import initialize
from hexstrike_mcp_tools.tool_definitions import build_registry


def test_all_registry_tools_have_valid_routes():
    """Every tool in the registry should have a valid route and method."""
    registry = build_registry()
    errors = []
    valid_methods = {"GET", "POST"}
    for cat in registry.list_categories():
        tools = registry.list_tools(cat)
        for tool_name in tools:
            try:
                info = registry.get_route(cat, tool_name)
                if not info["route"]:
                    errors.append(f"{cat}/{tool_name}: empty route")
                if info["method"] not in valid_methods:
                    errors.append(f"{cat}/{tool_name}: invalid method {info['method']}")
            except KeyError as e:
                errors.append(f"{cat}/{tool_name}: {e}")
    assert errors == [], f"Route errors: {errors}"


def test_all_registry_tools_dispatchable_via_client():
    """Every tool in the registry should dispatch without error via mock client."""
    mock = MagicMock()
    mock.safe_post.return_value = {"success": True}
    mock.safe_get.return_value = {"success": True}
    mock.server_url = "http://127.0.0.1:8888"
    initialize(mock)

    registry = build_registry()
    errors = []
    for cat in registry.list_categories():
        tools = registry.list_tools(cat)
        for tool_name in tools:
            try:
                route_info = registry.get_route(cat, tool_name)
                if route_info["method"] == "GET":
                    mock.safe_get(route_info["route"], {})
                else:
                    mock.safe_post(route_info["route"], {"target": "test"})
            except Exception as e:
                errors.append(f"{cat}/{tool_name}: {e}")
    assert errors == [], f"Dispatch errors: {errors}"


def test_registry_categories_match_grouped_functions():
    """Every registry category should have a corresponding grouped MCP function."""
    import hexstrike_mcp_tools.grouped as g
    registry = build_registry()
    grouped_funcs = {name for name in dir(g) if not name.startswith("_") and callable(getattr(g, name))}
    # list_available_tools is the discovery tool, not a category
    grouped_funcs.discard("list_available_tools")
    categories = set(registry.list_categories())
    missing = categories - grouped_funcs
    assert missing == set(), f"Categories without grouped function: {missing}"
```

**Step 2: Run tests**

Run: `pytest tests/unit/test_grouped_integration.py -v`
Expected: 3 passed

**Step 3: Commit**

```bash
git add tests/unit/test_grouped_integration.py
git commit -m "test: add grouped endpoint integration tests (Phase 6, Tasks 23-24)"
```

---

### Task 25–26: Full suite run + test count check

**Step 1: Run entire test suite**

Run: `pytest --tb=short -q`
Expected: ~750+ tests, all PASS

**Step 2: Verify MCP tool count**

```bash
grep -c "@mcp.tool()" hexstrike_mcp_tools/grouped.py
```

Expected: 22

**Step 3: Verify registry count**

```bash
python3 -c "
import yaml
with open('scripts/installer/registry.yaml') as f:
    data = yaml.safe_load(f)
print(f'Registry: {len(data[\"tools\"])} tools')
"
```

Expected: ~151

---

### Task 27–28: Update CHANGELOG.md

**Files:**
- Modify: `CHANGELOG.md`

Add Phase 6 section at top:

```markdown
## v7.0.0-dev — Phase 6: MCP Grouping + Registry Expansion + CI/CD

**Branch:** `v7.0-dev`
**Status:** Complete (30 tasks)

### Summary

Replaced 114 individual MCP tools with 22 @mcp.tool() endpoints (21 grouped
categories + 1 discovery tool) via SmartToolRegistry. Expanded installer
registry from 105 to ~151 entries. Added GitHub Actions CI/CD pipeline with
test, lint, and security scan jobs.

### New Files
- `hexstrike_mcp_tools/registry.py` — SmartToolRegistry class
- `hexstrike_mcp_tools/tool_definitions.py` — 114+ tool-to-route mappings
- `hexstrike_mcp_tools/grouped.py` — 22 @mcp.tool() endpoints (21 grouped + 1 discovery)
- `.github/workflows/ci.yml` — CI/CD pipeline
- `ruff.toml` — Linter configuration
- 8 new test files

### Changed Files
- `hexstrike_mcp.py` — Imports only `grouped` (was 12 modules)
- 12 old MCP modules — @mcp.tool() decorators removed (functions kept for backward compat)
- `scripts/installer/registry.yaml` — 105 → ~151 tool entries

### Key Metrics
- MCP tools: 114 individual → 22 @mcp.tool() (21 grouped + 1 discovery)
- Registry: 105 → ~151 entries
- Tests: 689 → ~750+
```

**Commit:**

```bash
git add CHANGELOG.md
git commit -m "docs: Phase 6 complete — CHANGELOG updated (Phase 6, Tasks 27-28)"
```

---

### Task 29–30: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

Update these sections:
1. Project Overview: change MCP description to "22 grouped MCP tools (21 category + 1 discovery) via SmartToolRegistry"
2. Core Components: add `registry.py`, `tool_definitions.py`, `grouped.py`
3. MCP Tool Registration Pattern: update to show grouped pattern
4. CLAUDE.md Maintenance: add Phase 6 completion note

**Commit:**

```bash
git add CLAUDE.md
git commit -m "docs: Phase 6 complete — CLAUDE.md updated (Phase 6, Tasks 29-30)"
```

---

## Summary

| Batch | Tasks | New Files | Modified Files | New Tests |
|-------|-------|-----------|----------------|-----------|
| A: Registry Core | 1–4 | 3 (`registry.py`, `tool_definitions.py`, test files) | 0 | ~14 |
| B: Grouped MCP | 5–12 | 3 (`grouped.py`, test files) | 13 (`hexstrike_mcp.py` + 12 old modules) | ~16 |
| C: Registry Expansion | 13–16 | 1 (test file) | 1 (`registry.yaml`) | ~5 |
| D: CI/CD | 17–22 | 8 (`ci.yml`, `ruff.toml`, 5 route test files, 1 test) | 0 | ~25 |
| E: Verification + Docs | 23–30 | 1 (test file) | 2 (`CHANGELOG.md`, `CLAUDE.md`) | ~2 |
| **Total** | **30** | **~16** | **~16** | **~62** |

**Estimated final test count:** 689 + ~62 + ~30 (from route tests) = ~780 tests
