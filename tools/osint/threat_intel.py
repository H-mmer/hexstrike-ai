"""Threat intelligence and IOC lookup tools."""
import requests
import shutil
import subprocess
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)
TIMEOUT = 30


def virustotal_lookup(ioc: str, api_key: str = "") -> Dict[str, Any]:
    """VirusTotal IP/domain/hash reputation lookup."""
    if not api_key:
        return {"success": False, "error": "VT_API_KEY required. Set api_key parameter."}
    try:
        headers = {"x-apikey": api_key}
        # Determine endpoint by IOC type
        if len(ioc) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in ioc):
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif all(c.isdigit() or c == '.' for c in ioc):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.ok:
            stats = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return {
                "success": True,
                "ioc": ioc,
                "malicious": stats.get("malicious", 0),
                "clean": stats.get("harmless", 0),
                "stats": stats,
            }
        return {"success": False, "error": f"VT API error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def otx_lookup(ioc: str, api_key: str = "") -> Dict[str, Any]:
    """AlienVault OTX threat intelligence lookup."""
    try:
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.ok:
            data = resp.json()
            return {
                "success": True,
                "ioc": ioc,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
            }
        return {"success": False, "error": f"OTX API error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def urlscan_lookup(url_or_domain: str) -> Dict[str, Any]:
    """URLScan.io passive URL/domain scanning history."""
    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{url_or_domain}&size=5",
            timeout=TIMEOUT,
        )
        if resp.ok:
            results = resp.json().get("results", [])
            return {
                "success": True,
                "target": url_or_domain,
                "scan_count": len(results),
                "recent_scans": results[:3],
            }
        return {"success": False, "error": f"URLScan error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def shodan_cve_lookup(ip: str, api_key: str = "") -> Dict[str, Any]:
    """Look up known CVEs for services running on an IP via Shodan."""
    if not shutil.which("shodan"):
        return {"success": False, "error": "shodan CLI not installed"}
    try:
        result = subprocess.run(
            ["shodan", "host", ip],
            capture_output=True, text=True, timeout=30,
        )
        return {"success": result.returncode == 0, "ip": ip, "output": result.stdout}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Shodan CVE lookup timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}
