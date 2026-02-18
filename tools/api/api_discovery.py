#!/usr/bin/env python3
"""
HexStrike AI - API Discovery Tools

REST, GraphQL, and SOAP API endpoint discovery.
"""

import logging
import subprocess
import requests
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def kiterunner_scan(target: str, wordlist: Optional[str] = None, methods: List[str] = None) -> Dict[str, Any]:
    """
    Content discovery for APIs using kiterunner
    
    Args:
        target: Target URL
        wordlist: Custom wordlist path
        methods: HTTP methods to test
    """
    try:
        cmd = ['kr', 'scan', target]
        
        if wordlist:
            cmd.extend(['-w', wordlist])
        
        if methods:
            cmd.extend(['-m', ','.join(methods)])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        return {
            "success": result.returncode == 0,
            "endpoints_found": result.stdout.count('\n'),
            "output": result.stdout,
            "tool": "kiterunner"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def api_routes_finder(target: str, deep_scan: bool = False) -> Dict[str, Any]:
    """
    Find API routes and endpoints
    
    Args:
        target: Target base URL
        deep_scan: Enable deep recursive scanning
    """
    try:
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2',
            '/rest', '/graphql', '/swagger', '/openapi.json',
            '/api-docs', '/docs', '/swagger.json', '/swagger.yaml'
        ]
        
        found_endpoints = []
        
        for path in common_paths:
            url = f"{target.rstrip('/')}{path}"
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True)
                if resp.status_code < 400:
                    found_endpoints.append({
                        "url": url,
                        "status": resp.status_code,
                        "content_type": resp.headers.get('Content-Type', '')
                    })
            except:
                continue
        
        return {
            "success": True,
            "endpoints_found": len(found_endpoints),
            "endpoints": found_endpoints,
            "tool": "api-routes-finder"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def swagger_scanner(target: str) -> Dict[str, Any]:
    """
    Scan for Swagger/OpenAPI documentation
    
    Args:
        target: Target URL
    """
    try:
        swagger_paths = [
            '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/openapi.yaml',
            '/api-docs', '/docs/swagger.json',
            '/v2/api-docs', '/v3/api-docs'
        ]
        
        found_docs = []
        
        for path in swagger_paths:
            url = f"{target.rstrip('/')}{path}"
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    found_docs.append({
                        "url": url,
                        "size": len(resp.content),
                        "endpoints": resp.json().get('paths', {}) if resp.headers.get('Content-Type', '').startswith('application/json') else {}
                    })
            except:
                continue
        
        return {
            "success": True,
            "docs_found": len(found_docs),
            "documentation": found_docs,
            "tool": "swagger-scanner"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def graphql_cop_scan(target: str) -> Dict[str, Any]:
    """
    GraphQL security scanner
    
    Args:
        target: GraphQL endpoint URL
    """
    try:
        # Introspection query
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    fields {
                        name
                        args { name type { name } }
                    }
                }
            }
        }
        """
        
        resp = requests.post(target, json={"query": introspection_query}, timeout=30)
        
        if resp.status_code == 200:
            schema = resp.json()
            return {
                "success": True,
                "introspection_enabled": True,
                "schema": schema.get('data', {}),
                "tool": "graphql-cop"
            }
        else:
            return {
                "success": False,
                "introspection_enabled": False,
                "status_code": resp.status_code,
                "tool": "graphql-cop"
            }
    except Exception as e:
        return {"success": False, "error": str(e)}


def postman_automated_discovery(target: str, export_collection: bool = True) -> Dict[str, Any]:
    """
    Automated API discovery with Postman-compatible collection generation
    
    Args:
        target: Target API base URL
        export_collection: Generate Postman collection
    """
    try:
        # Discovery logic
        discovered = api_routes_finder(target)
        
        if export_collection and discovered["success"]:
            collection = {
                "info": {
                    "name": f"API Discovery - {target}",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
                },
                "item": []
            }
            
            for endpoint in discovered.get("endpoints", []):
                collection["item"].append({
                    "name": endpoint["url"],
                    "request": {
                        "method": "GET",
                        "url": endpoint["url"]
                    }
                })
            
            return {
                "success": True,
                "collection": collection,
                "endpoints_count": len(discovered.get("endpoints", [])),
                "tool": "postman-automated"
            }
        
        return discovered
    except Exception as e:
        return {"success": False, "error": str(e)}
