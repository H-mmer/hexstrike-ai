# hexstrike_mcp_tools/osint.py
"""MCP tool registrations for OSINT tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import get_client


def osint_passive_recon(domain: str, sources: str = "all", shodan_key: str = "") -> Dict[str, Any]:
    """Passive recon — theHarvester, WHOIS, DNS, Shodan. No direct target contact."""
    return get_client().safe_post(
        "api/osint/passive-recon",
        {"domain": domain, "sources": sources, "shodan_key": shodan_key},
    )


def osint_threat_intel(ioc: str, vt_key: str = "", otx_key: str = "") -> Dict[str, Any]:
    """IOC threat intelligence — VirusTotal, OTX, URLScan. ioc: IP, domain, or file hash."""
    return get_client().safe_post(
        "api/osint/threat-intel",
        {"ioc": ioc, "vt_key": vt_key, "otx_key": otx_key},
    )


def osint_social_recon(username: str = "", email: str = "") -> Dict[str, Any]:
    """Social media OSINT — Sherlock (username) and Holehe (email). Provide at least one."""
    return get_client().safe_post(
        "api/osint/social-recon",
        {"username": username, "email": email},
    )


def osint_breach_check(email: str) -> Dict[str, Any]:
    """Check if email appears in known data breaches via HaveIBeenPwned."""
    return get_client().safe_post(
        "api/osint/breach-check",
        {"email": email},
    )


def osint_shodan_search(query: str, api_key: str = "") -> Dict[str, Any]:
    """Shodan internet-wide search. Query examples: 'nginx port:443', 'org:Google'"""
    return get_client().safe_post(
        "api/osint/shodan",
        {"query": query, "api_key": api_key},
    )
