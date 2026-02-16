#!/usr/bin/env python3
"""API Fuzzing Tools"""

import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def rest_attacker(target: str, method: str = "GET", payloads: List[str] = None) -> Dict[str, Any]:
    """REST API fuzzer"""
    try:
        if not payloads:
            payloads = ["'", '"', "<script>", "../../etc/passwd", "1' OR '1'='1"]
        
        findings = []
        for payload in payloads:
            params = {"q": payload}
            resp = requests.request(method, target, params=params, timeout=10)
            
            if any(indicator in resp.text for indicator in ["error", "SQL", "exception"]):
                findings.append({"payload": payload, "status": resp.status_code})
        
        return {
            "success": True,
            "findings": findings,
            "total_tests": len(payloads),
            "tool": "rest-attacker"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def graphql_path_enum(target: str) -> Dict[str, Any]:
    """GraphQL path enumeration"""
    try:
        mutation = """mutation { __typename }"""
        resp = requests.post(target, json={"query": mutation})
        
        return {
            "success": resp.status_code == 200,
            "mutations_enabled": "__typename" in resp.text,
            "response": resp.json() if resp.status_code == 200 else None,
            "tool": "graphql-path-enum"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def api_injection_scanner(target: str) -> Dict[str, Any]:
    """Scan for injection vulnerabilities"""
    injection_payloads = {
        "SQL": ["' OR '1'='1", "'; DROP TABLE users--"],
        "NoSQL": ['{"$gt": ""}', '{"$ne": null}'],
        "Command": ["; ls", "| cat /etc/passwd"],
        "LDAP": ["*)(uid=*))(|(uid=*", "admin)(|(password=*)"]
    }
    
    vulnerabilities = []
    for vuln_type, payloads in injection_payloads.items():
        for payload in payloads[:2]:  # Limit
            try:
                resp = requests.get(target, params={"input": payload}, timeout=10)
                if resp.status_code == 500 or "error" in resp.text.lower():
                    vulnerabilities.append({
                        "type": vuln_type,
                        "payload": payload,
                        "evidence": resp.text[:200]
                    })
            except:
                continue
    
    return {
        "success": True,
        "vulnerabilities": vulnerabilities,
        "tool": "api-injection-scanner"
    }


def schema_fuzzer(schema: dict, target: str) -> Dict[str, Any]:
    """Fuzz API based on OpenAPI/GraphQL schema"""
    try:
        fuzz_results = []
        
        for path, methods in schema.get("paths", {}).items():
            for method, spec in methods.items():
                url = f"{target}{path}"
                resp = requests.request(method.upper(), url, timeout=10)
                fuzz_results.append({
                    "path": path,
                    "method": method,
                    "status": resp.status_code
                })
        
        return {
            "success": True,
            "tests_run": len(fuzz_results),
            "results": fuzz_results,
            "tool": "schema-fuzzer"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
