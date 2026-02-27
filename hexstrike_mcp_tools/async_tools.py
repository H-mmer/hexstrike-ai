# hexstrike_mcp_tools/async_tools.py
"""MCP tools: async scan wrappers — POST /async -> poll /api/tasks/<id>."""
from typing import Optional

import requests

from hexstrike_mcp_tools import get_client


def nmap_scan_async(target: str, scan_type: str = "-sV") -> str:
    """Start nmap in background. Returns task_id -- poll with get_task_status()."""
    return get_client().safe_post(
        "/api/network/nmap/async", {"target": target, "scan_type": scan_type}
    )


def nuclei_scan_async(target: str, templates: Optional[str] = None) -> str:
    """Start nuclei in background. Returns task_id."""
    return get_client().safe_post(
        "/api/web/nuclei/async", {"target": target, "templates": templates}
    )


def gobuster_async(target: str, wordlist: Optional[str] = None) -> str:
    """Start gobuster in background. Returns task_id."""
    return get_client().safe_post(
        "/api/web/gobuster/async", {"target": target, "wordlist": wordlist}
    )


def get_task_status(task_id: str) -> str:
    """Poll async task status. Returns status + result when done."""
    client = get_client()
    try:
        resp = requests.get(
            f"{client.server_url}/api/tasks/{task_id}", timeout=10
        )
        return resp.text
    except Exception as e:
        return str(e)
