# hexstrike_mcp_tools/network.py
"""MCP tool registrations for network/reconnaissance tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "",
              additional_args: str = "") -> Dict[str, Any]:
    """Execute an Nmap scan. scan_type: -sV (version), -sC (scripts), -sU (UDP), -sS (SYN)."""
    return get_client().safe_post("api/tools/nmap", {
        "target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args
    })


@mcp.tool()
def rustscan(target: str, ports: str = "", ulimit: int = 5000) -> Dict[str, Any]:
    """Fast port scanner using RustScan."""
    return get_client().safe_post("api/tools/rustscan", {
        "target": target, "ports": ports, "ulimit": ulimit
    })


@mcp.tool()
def masscan(target: str, ports: str = "1-65535", rate: int = 1000) -> Dict[str, Any]:
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
    """Fast passive subdomain discovery using Subfinder."""
    return get_client().safe_post("api/tools/subfinder", {"domain": domain})


@mcp.tool()
def httpx_probe(targets: str, options: str = "") -> Dict[str, Any]:
    """HTTP probing — checks status codes, titles, tech detection."""
    return get_client().safe_post("api/tools/httpx", {"targets": targets, "options": options})


@mcp.tool()
def waybackurls(domain: str) -> Dict[str, Any]:
    """Fetch known URLs from Wayback Machine for a domain."""
    return get_client().safe_post("api/tools/waybackurls", {"domain": domain})


@mcp.tool()
def gau_fetch(domain: str) -> Dict[str, Any]:
    """Fetch known URLs from multiple sources (GetAllUrls)."""
    return get_client().safe_post("api/tools/gau", {"domain": domain})


@mcp.tool()
def dnsenum(domain: str) -> Dict[str, Any]:
    """DNS enumeration — A/MX/NS/TXT records and zone transfer attempt."""
    return get_client().safe_post("api/tools/dnsenum", {"domain": domain})


@mcp.tool()
def enum4linux(target: str) -> Dict[str, Any]:
    """Windows/Samba enumeration — users, shares, groups, policies."""
    return get_client().safe_post("api/tools/enum4linux", {"target": target})


@mcp.tool()
def smbmap_scan(host: str, username: str = "", password: str = "") -> Dict[str, Any]:
    """SMB share enumeration and permissions mapping."""
    return get_client().safe_post("api/tools/smbmap", {
        "host": host, "username": username, "password": password
    })


@mcp.tool()
def netexec_scan(target: str, protocol: str = "smb", username: str = "",
                 password: str = "") -> Dict[str, Any]:
    """Network execution and credential testing (NetExec/CrackMapExec). protocol: smb|winrm|ldap|rdp"""
    return get_client().safe_post("api/tools/netexec", {
        "target": target, "protocol": protocol, "username": username, "password": password
    })


@mcp.tool()
def wafw00f(target: str) -> Dict[str, Any]:
    """Web Application Firewall detection."""
    return get_client().safe_post("api/tools/wafw00f", {"target": target})


@mcp.tool()
def naabu_port_scan(target: str, ports: str = "") -> Dict[str, Any]:
    """Fast port scanning using Naabu (Phase 3)."""
    return get_client().safe_post("api/tools/network/naabu", {
        "target": target, "ports": ports
    })


@mcp.tool()
def snmp_check(target: str, community: str = "public") -> Dict[str, Any]:
    """SNMP enumeration (Phase 3). community: SNMP community string."""
    return get_client().safe_post("api/tools/network/snmp-check", {
        "target": target, "community": community
    })


@mcp.tool()
def zmap_scan(target_range: str, port: int = 80, rate: int = 10000) -> Dict[str, Any]:
    """Network-wide fast scanning with ZMap (Phase 3). Use rate carefully."""
    return get_client().safe_post("api/tools/network/zmap", {
        "target": target_range, "port": port, "rate": rate
    })
