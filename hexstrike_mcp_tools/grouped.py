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
