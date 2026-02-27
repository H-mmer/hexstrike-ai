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


@mcp.tool()
def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "",
                       timing: str = "T4", nse_scripts: str = "",
                       os_detection: bool = False, version_detection: bool = False,
                       aggressive: bool = False, stealth: bool = False) -> Dict[str, Any]:
    """Advanced nmap scan with NSE scripts, timing, OS/version detection."""
    return get_client().safe_post("api/tools/nmap-advanced", {
        "target": target, "scan_type": scan_type, "ports": ports,
        "timing": timing, "nse_scripts": nse_scripts,
        "os_detection": os_detection, "version_detection": version_detection,
        "aggressive": aggressive, "stealth": stealth,
    })


@mcp.tool()
def fierce_scan(domain: str, dns_server: str = "",
                additional_args: str = "") -> Dict[str, Any]:
    """DNS reconnaissance using Fierce — subdomain brute-forcing and zone transfer detection."""
    return get_client().safe_post("api/tools/fierce", {
        "domain": domain, "dns_server": dns_server, "additional_args": additional_args,
    })


@mcp.tool()
def autorecon_scan(target: str, output_dir: str = "/tmp/autorecon",
                   heartbeat: int = 60, timeout: int = 300,
                   additional_args: str = "") -> Dict[str, Any]:
    """Comprehensive automated reconnaissance using AutoRecon."""
    return get_client().safe_post("api/tools/autorecon", {
        "target": target, "output_dir": output_dir, "heartbeat": heartbeat,
        "timeout": timeout, "additional_args": additional_args,
    })


@mcp.tool()
def nbtscan_scan(target: str, verbose: bool = False, timeout: int = 2,
                 additional_args: str = "") -> Dict[str, Any]:
    """NetBIOS name scanner — discover Windows hosts and their NetBIOS names."""
    return get_client().safe_post("api/tools/nbtscan", {
        "target": target, "verbose": verbose, "timeout": timeout,
        "additional_args": additional_args,
    })


@mcp.tool()
def scapy_probe(target: str, packet_type: str = "ICMP") -> Dict[str, Any]:
    """Packet crafting and probing with Scapy. packet_type: ICMP|TCP|UDP"""
    return get_client().safe_post("api/tools/network/scapy", {
        "target": target, "packet_type": packet_type,
    })


@mcp.tool()
def ipv6_scan(target: str, scan_type: str = "alive6",
              additional_args: str = "") -> Dict[str, Any]:
    """IPv6 security testing with ipv6toolkit. scan_type: alive6|dos-new-ip6|detect-new-ip6|fake_router6"""
    return get_client().safe_post("api/tools/network/ipv6-toolkit", {
        "target": target, "scan_type": scan_type, "additional_args": additional_args,
    })


@mcp.tool()
def udp_proto_scan(target: str, proto_list: Optional[str] = None,
                   additional_args: str = "") -> Dict[str, Any]:
    """UDP protocol scanner — probe common UDP services."""
    return get_client().safe_post("api/tools/network/udp-proto-scanner", {
        "target": target, "proto_list": proto_list, "additional_args": additional_args,
    })


@mcp.tool()
def cisco_torch_scan(target: str, scan_type: str = "all",
                     additional_args: str = "") -> Dict[str, Any]:
    """Cisco device security scanning with cisco-torch."""
    return get_client().safe_post("api/tools/network/cisco-torch", {
        "target": target, "scan_type": scan_type, "additional_args": additional_args,
    })


@mcp.tool()
def enum4linux_ng_scan(target: str, username: str = "", password: str = "",
                       domain: str = "", additional_args: str = "") -> Dict[str, Any]:
    """Advanced SMB/Windows enumeration using enum4linux-ng."""
    return get_client().safe_post("api/tools/enum4linux-ng", {
        "target": target, "username": username, "password": password,
        "domain": domain, "additional_args": additional_args,
    })
