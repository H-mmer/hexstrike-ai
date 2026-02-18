"""System and infrastructure routes Blueprint."""
import shutil
import time
from flask import Blueprint, jsonify, request

system_bp = Blueprint('system', __name__)

# Module-level start time for uptime calculation
_start_time = time.time()


def _check_tool(tool_name: str) -> bool:
    """Check if a tool is available using shutil.which."""
    return shutil.which(tool_name) is not None


@system_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint with comprehensive tool detection"""

    essential_tools = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "hashcat"
    ]

    network_tools = [
        "rustscan", "masscan", "autorecon", "nbtscan", "arp-scan", "responder",
        "nxc", "enum4linux-ng", "rpcclient", "enum4linux"
    ]

    web_security_tools = [
        "ffuf", "feroxbuster", "dirsearch", "dotdotpwn", "xsser", "wfuzz",
        "gau", "waybackurls", "arjun", "paramspider", "x8", "jaeles", "dalfox",
        "httpx", "wafw00f", "burpsuite", "zaproxy", "katana", "hakrawler"
    ]

    vuln_scanning_tools = [
        "nuclei", "wpscan", "graphql-scanner", "jwt-analyzer"
    ]

    password_tools = [
        "medusa", "patator", "hash-identifier", "ophcrack", "hashcat-utils"
    ]

    binary_tools = [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "ghidra", "pwntools", "one-gadget", "ropper", "angr", "libc-database",
        "pwninit"
    ]

    forensics_tools = [
        "volatility3", "vol", "steghide", "hashpump", "foremost", "exiftool",
        "strings", "xxd", "file", "photorec", "testdisk", "scalpel", "bulk-extractor",
        "stegsolve", "zsteg", "outguess"
    ]

    cloud_tools = [
        "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
        "docker-bench-security", "checkov", "terrascan", "falco", "clair"
    ]

    osint_tools = [
        "amass", "subfinder", "fierce", "dnsenum", "theharvester", "sherlock",
        "social-analyzer", "recon-ng", "maltego", "spiderfoot", "shodan-cli",
        "censys-cli", "have-i-been-pwned"
    ]

    exploitation_tools = [
        "metasploit", "exploit-db", "searchsploit"
    ]

    api_tools = [
        "api-schema-analyzer", "postman", "insomnia", "curl", "httpie", "anew", "qsreplace", "uro"
    ]

    wireless_tools = [
        "kismet", "wireshark", "tshark", "tcpdump"
    ]

    additional_tools = [
        "smbmap", "volatility", "sleuthkit", "autopsy", "evil-winrm",
        "paramspider", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
        "msfvenom", "msfconsole", "graphql-scanner", "jwt-analyzer"
    ]

    all_tools = (
        essential_tools + network_tools + web_security_tools + vuln_scanning_tools +
        password_tools + binary_tools + forensics_tools + cloud_tools +
        osint_tools + exploitation_tools + api_tools + wireless_tools + additional_tools
    )

    # Deduplicate while preserving order
    seen = set()
    all_tools_deduped = [t for t in all_tools if not (t in seen or seen.add(t))]

    tools_status = {}

    for tool in all_tools_deduped:
        try:
            tools_status[tool] = _check_tool(tool)
        except Exception:
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status[tool] for tool in essential_tools)

    category_stats = {
        "essential": {"total": len(essential_tools), "available": sum(1 for tool in essential_tools if tools_status.get(tool, False))},
        "network": {"total": len(network_tools), "available": sum(1 for tool in network_tools if tools_status.get(tool, False))},
        "web_security": {"total": len(web_security_tools), "available": sum(1 for tool in web_security_tools if tools_status.get(tool, False))},
        "vuln_scanning": {"total": len(vuln_scanning_tools), "available": sum(1 for tool in vuln_scanning_tools if tools_status.get(tool, False))},
        "password": {"total": len(password_tools), "available": sum(1 for tool in password_tools if tools_status.get(tool, False))},
        "binary": {"total": len(binary_tools), "available": sum(1 for tool in binary_tools if tools_status.get(tool, False))},
        "forensics": {"total": len(forensics_tools), "available": sum(1 for tool in forensics_tools if tools_status.get(tool, False))},
        "cloud": {"total": len(cloud_tools), "available": sum(1 for tool in cloud_tools if tools_status.get(tool, False))},
        "osint": {"total": len(osint_tools), "available": sum(1 for tool in osint_tools if tools_status.get(tool, False))},
        "exploitation": {"total": len(exploitation_tools), "available": sum(1 for tool in exploitation_tools if tools_status.get(tool, False))},
        "api": {"total": len(api_tools), "available": sum(1 for tool in api_tools if tools_status.get(tool, False))},
        "wireless": {"total": len(wireless_tools), "available": sum(1 for tool in wireless_tools if tools_status.get(tool, False))},
        "additional": {"total": len(additional_tools), "available": sum(1 for tool in additional_tools if tools_status.get(tool, False))}
    }

    return jsonify({
        "status": "healthy",
        "message": "HexStrike AI Tools API Server is operational",
        "version": "6.0.0",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "total_tools_available": sum(1 for tool, available in tools_status.items() if available),
        "total_tools_count": len(all_tools_deduped),
        "category_stats": category_stats,
        "cache_stats": {},
        "telemetry": {},
        "uptime": time.time() - _start_time
    })


@system_bp.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """Get system telemetry"""
    return jsonify({
        "uptime": time.time() - _start_time,
        "requests": 0,
        "errors": 0,
        "start_time": _start_time
    })
