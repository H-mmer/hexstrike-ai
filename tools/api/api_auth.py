#!/usr/bin/env python3
"""API Authentication Testing Tools"""

import logging
import jwt
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)


def jwt_hack(token: str, secret: str = None, algorithm: str = "HS256") -> Dict[str, Any]:
    """JWT manipulation and cracking"""
    try:
        # Decode without verification
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        result = {
            "success": True,
            "decoded_payload": unverified,
            "algorithm": jwt.get_unverified_header(token).get("alg"),
            "tool": "jwt-hack"
        }
        
        if secret:
            try:
                verified = jwt.decode(token, secret, algorithms=[algorithm])
                result["verification"] = "SUCCESS"
                result["secret_found"] = secret
            except:
                result["verification"] = "FAILED"
        
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def oauth_scanner(auth_endpoint: str, client_id: str = "test") -> Dict[str, Any]:
    """OAuth flow security scanner"""
    try:
        findings = []
        
        # Test redirect_uri manipulation
        params = {"client_id": client_id, "redirect_uri": "https://attacker.com"}
        resp = requests.get(auth_endpoint, params=params, allow_redirects=False)
        if resp.status_code in [200, 302]:
            findings.append("Open redirect vulnerability - arbitrary redirect_uri accepted")
        
        return {
            "success": True,
            "findings": findings,
            "tool": "oauth-scanner"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def api_key_brute(target: str, header_name: str = "X-API-Key", wordlist: list = None) -> Dict[str, Any]:
    """API key brute forcing"""
    try:
        if not wordlist:
            wordlist = ["test", "admin", "key123", "apikey", "secret"]
        
        valid_keys = []
        for key in wordlist[:100]:  # Limit for safety
            headers = {header_name: key}
            resp = requests.get(target, headers=headers, timeout=5)
            if resp.status_code == 200:
                valid_keys.append(key)
        
        return {
            "success": True,
            "valid_keys": valid_keys,
            "attempts": len(wordlist[:100]),
            "tool": "api-key-brute"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def bearer_token_analyzer(token: str) -> Dict[str, Any]:
    """Analyze bearer token structure"""
    import base64
    
    try:
        parts = token.split('.')
        analysis = {"success": True, "tool": "bearer-token-analyzer"}
        
        if len(parts) == 3:  # JWT
            analysis["type"] = "JWT"
            header = base64.urlsafe_b64decode(parts[0] + '==')
            payload = base64.urlsafe_b64decode(parts[1] + '==')
            analysis["header"] = header.decode('utf-8', errors='ignore')
            analysis["payload"] = payload.decode('utf-8', errors='ignore')
        else:
            analysis["type"] = "Opaque Token"
            analysis["length"] = len(token)
        
        return analysis
    except Exception as e:
        return {"success": False, "error": str(e)}
