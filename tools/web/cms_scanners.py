#!/usr/bin/env python3
"""CMS Security Scanners - Simple, focused implementations"""

import subprocess
import requests
import re
from typing import Dict, Any, Optional

def joomscan(target_url: str, enumerate: bool = True) -> Dict[str, Any]:
    """Joomla vulnerability scanner"""
    try:
        cmd = ['joomscan', '-u', target_url]
        if enumerate:
            cmd.append('--enumerate-components')
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"success": result.returncode == 0, "output": result.stdout, "tool": "joomscan"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def droopescan(target_url: str, cms_type: str = "drupal") -> Dict[str, Any]:
    """Drupal vulnerability scanner"""
    try:
        cmd = ['droopescan', 'scan', cms_type, '-u', target_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"success": result.returncode == 0, "output": result.stdout, "tool": "droopescan"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def magescan(target_url: str) -> Dict[str, Any]:
    """Magento vulnerability scanner"""
    try:
        cmd = ['magescan', 'scan:all', target_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"success": result.returncode == 0, "results": result.stdout, "tool": "magescan"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def shopware_scanner(target_url: str) -> Dict[str, Any]:
    """Shopware security scanner"""
    try:
        findings = []

        # Check for version disclosure
        paths = ['/shopware.php', '/_info.php', '/recovery/install/index.php']
        for path in paths:
            test_url = target_url.rstrip('/') + path
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200:
                findings.append({"path": path, "status": resp.status_code, "issue": "exposed_file"})

        # Check for admin panel
        admin_paths = ['/backend', '/admin', '/shopware/backend']
        for path in admin_paths:
            test_url = target_url.rstrip('/') + path
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code in [200, 302]:
                findings.append({"path": path, "status": resp.status_code, "issue": "exposed_admin"})

        return {"success": True, "findings": findings, "tool": "shopware-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def prestashop_scanner(target_url: str) -> Dict[str, Any]:
    """PrestaShop security scanner"""
    try:
        findings = []

        # Check for version disclosure
        resp = requests.get(target_url, timeout=10)
        version_match = re.search(r'prestashop\s+v?([\d.]+)', resp.text, re.IGNORECASE)
        if version_match:
            findings.append({"issue": "version_disclosure", "version": version_match.group(1)})

        # Check for debug mode
        debug_paths = ['/config/defines.inc.php', '/config/smarty.config.inc.php']
        for path in debug_paths:
            test_url = target_url.rstrip('/') + path
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200 and 'define' in resp.text:
                findings.append({"path": path, "issue": "exposed_config"})

        # Check admin panel
        admin_resp = requests.get(f"{target_url.rstrip('/')}/admin", timeout=10, allow_redirects=False)
        if admin_resp.status_code in [200, 302]:
            findings.append({"path": "/admin", "issue": "exposed_admin_panel"})

        return {"success": True, "findings": findings, "tool": "prestashop-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}
