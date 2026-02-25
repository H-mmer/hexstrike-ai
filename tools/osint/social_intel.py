"""Social media and identity OSINT tools."""
import subprocess
import shutil
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)
TIMEOUT = 180


def sherlock_search(username: str) -> Dict[str, Any]:
    """Username search across 300+ platforms using Sherlock."""
    if not shutil.which("sherlock"):
        return {"success": False, "error": "sherlock not installed. pip install sherlock-project"}
    try:
        result = subprocess.run(
            ["sherlock", username, "--print-found"],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        found = [line for line in result.stdout.split('\n') if '[+]' in line]
        return {
            "success": True,
            "username": username,
            "found_on": found,
            "count": len(found),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Sherlock timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def holehe_check(email: str) -> Dict[str, Any]:
    """Check which services an email is registered on using Holehe."""
    if not shutil.which("holehe"):
        return {"success": False, "error": "holehe not installed. pip install holehe"}
    try:
        result = subprocess.run(
            ["holehe", email],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        registered = [line for line in result.stdout.split('\n') if '[+]' in line]
        return {
            "success": True,
            "email": email,
            "registered_on": registered,
            "count": len(registered),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Holehe timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def breach_lookup(email: str) -> Dict[str, Any]:
    """Check email against known breach databases via HaveIBeenPwned API."""
    try:
        headers = {"User-Agent": "HexStrike-OSINT/7.0"}
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 404:
            return {"success": True, "email": email, "breached": False, "breaches": []}
        elif resp.status_code == 200:
            breaches = [b.get("Name") for b in resp.json()]
            return {
                "success": True,
                "email": email,
                "breached": True,
                "breaches": breaches,
                "count": len(breaches),
            }
        else:
            return {"success": False, "error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def linkedin_recon(company: str) -> Dict[str, Any]:
    """Basic LinkedIn company OSINT (public data only)."""
    return {
        "success": True,
        "note": (
            "LinkedIn recon requires manual authentication. "
            "Use linkedin2username for automation."
        ),
        "company": company,
        "suggestion": f"Run: python3 linkedin2username.py -c '{company}' -u user@email.com",
    }
