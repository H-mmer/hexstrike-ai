"""Passive reconnaissance tools — no direct target interaction."""
import subprocess
import shutil
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)
TIMEOUT = 120


def shodan_search(query: str, api_key: str = "") -> Dict[str, Any]:
    """Shodan IP/service/banner lookup."""
    if not shutil.which("shodan"):
        return {"success": False, "error": "shodan CLI not installed"}
    try:
        cmd = ["shodan", "search", "--fields", "ip_str,port,org,hostnames", query]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return {"success": result.returncode == 0, "output": result.stdout, "query": query}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Shodan search timed out"}
    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return {"success": False, "error": str(e)}


def whois_lookup(domain: str) -> Dict[str, Any]:
    """WHOIS domain registration lookup."""
    if not shutil.which("whois"):
        return {"success": False, "error": "whois not installed"}
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=30)
        return {"success": result.returncode == 0, "output": result.stdout, "domain": domain}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "WHOIS timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def the_harvester(domain: str, sources: str = "all") -> Dict[str, Any]:
    """theHarvester — emails, subdomains, hosts from public sources."""
    if not shutil.which("theHarvester"):
        return {"success": False, "error": "theHarvester not installed"}
    try:
        cmd = ["theHarvester", "-d", domain, "-b", sources]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return {"success": result.returncode == 0, "output": result.stdout, "domain": domain}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "theHarvester timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def dnsdumpster_recon(domain: str) -> Dict[str, Any]:
    """DNS recon via hackertarget.com API (passive)."""
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=30,
        )
        lines = resp.text.strip().split('\n') if resp.ok else []
        hosts = [line.split(',') for line in lines if line]
        return {"success": True, "hosts": hosts, "count": len(hosts)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def censys_search(query: str, api_id: str = "", api_secret: str = "") -> Dict[str, Any]:
    """Censys certificate and host enumeration."""
    if not shutil.which("censys"):
        return {"success": False, "error": "censys CLI not installed. pip install censys"}
    try:
        cmd = ["censys", "search", query, "--index-type", "hosts"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        return {"success": result.returncode == 0, "output": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}
