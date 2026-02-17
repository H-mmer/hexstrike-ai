#!/usr/bin/env python3
"""Authentication Testing Tools - Simple, focused implementations"""

import subprocess
import requests
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

def csrf_scanner(target_url: str, session_cookie: Optional[str] = None) -> Dict[str, Any]:
    """CSRF vulnerability testing"""
    try:
        findings = []
        resp = requests.get(target_url, timeout=10)

        # Check for CSRF tokens in forms
        forms = re.findall(r'<form[^>]*>', resp.text, re.IGNORECASE)
        for form in forms:
            if 'csrf' not in form.lower() and 'token' not in form.lower():
                findings.append({"form": form[:100], "issue": "no_csrf_token"})

        # Check CSRF headers
        if 'X-CSRF-Token' not in resp.headers and 'X-XSRF-Token' not in resp.headers:
            findings.append({"issue": "missing_csrf_headers"})

        return {"success": True, "findings": findings, "forms_checked": len(forms), "tool": "csrf-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def session_hijacking_test(target_url: str, cookie: str) -> Dict[str, Any]:
    """Session hijacking testing"""
    try:
        findings = []

        # Test session fixation
        resp1 = requests.get(target_url, timeout=10)
        initial_cookies = resp1.cookies

        # Check HttpOnly flag
        for cookie_name, cookie_obj in resp1.cookies.items():
            if not cookie_obj.has_nonstandard_attr('HttpOnly'):
                findings.append({"cookie": cookie_name, "issue": "missing_httponly"})
            if not cookie_obj.secure:
                findings.append({"cookie": cookie_name, "issue": "missing_secure_flag"})

        return {"success": True, "findings": findings, "cookies_checked": len(resp1.cookies), "tool": "session-hijacking-kit"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def cookie_analyzer(target_url: str) -> Dict[str, Any]:
    """Cookie security analysis"""
    try:
        resp = requests.get(target_url, timeout=10)
        cookie_analysis = []

        for cookie_name, cookie_value in resp.cookies.items():
            analysis = {
                "name": cookie_name,
                "secure": cookie_value.secure if hasattr(cookie_value, 'secure') else False,
                "httponly": cookie_value.has_nonstandard_attr('HttpOnly') if hasattr(cookie_value, 'has_nonstandard_attr') else False,
                "samesite": cookie_value.get('samesite', 'none') if hasattr(cookie_value, 'get') else 'none',
                "value_length": len(str(cookie_value))
            }
            cookie_analysis.append(analysis)

        return {"success": True, "cookies": cookie_analysis, "count": len(cookie_analysis), "tool": "cookie-analyzer"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def saml_raider_test(saml_request: str, target_url: str) -> Dict[str, Any]:
    """SAML authentication testing"""
    try:
        # Basic SAML signature bypass attempts
        findings = []

        # Test signature removal
        if '<Signature' in saml_request:
            modified = re.sub(r'<Signature.*?</Signature>', '', saml_request, flags=re.DOTALL)
            findings.append({"test": "signature_removal", "modified": True})

        # Test signature wrapping
        if '<Assertion' in saml_request:
            findings.append({"test": "assertion_wrapping", "vulnerable": "potential"})

        return {"success": True, "findings": findings, "tool": "saml-raider"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def keycloak_scanner(keycloak_url: str) -> Dict[str, Any]:
    """Keycloak security scanner"""
    try:
        findings = []

        # Check for exposed admin console
        admin_paths = ['/auth/admin/', '/admin/', '/auth/admin/master/console/']
        for path in admin_paths:
            test_url = keycloak_url.rstrip('/') + path
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            if resp.status_code in [200, 302]:
                findings.append({"path": path, "status": resp.status_code, "issue": "exposed_admin"})

        # Check version disclosure
        resp = requests.get(keycloak_url, timeout=10)
        if 'Keycloak' in resp.text:
            version_match = re.search(r'Keycloak\s+([\d.]+)', resp.text)
            if version_match:
                findings.append({"issue": "version_disclosure", "version": version_match.group(1)})

        return {"success": True, "findings": findings, "tool": "keycloak-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def password_reset_analyzer(reset_url: str, email: Optional[str] = None) -> Dict[str, Any]:
    """Password reset flow testing"""
    try:
        findings = []

        # Test password reset token in URL
        if 'token=' in reset_url or 'reset=' in reset_url:
            findings.append({"issue": "token_in_url", "risk": "medium"})

        # Test reset without authentication
        resp = requests.get(reset_url, timeout=10)
        if resp.status_code == 200:
            # Check for rate limiting
            for i in range(5):
                test_resp = requests.post(reset_url, data={"email": f"test{i}@example.com"}, timeout=5)
                if test_resp.status_code != 429:
                    findings.append({"issue": "no_rate_limiting", "requests_sent": i+1})
                    break

        return {"success": True, "findings": findings, "tool": "password-reset-analyzer"}
    except Exception as e:
        return {"success": False, "error": str(e)}
