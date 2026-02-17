#!/usr/bin/env python3
"""CDN and Caching Tools - Simple, focused implementations"""

import subprocess
import requests
import socket
from typing import Dict, Any, List, Optional

def cdn_scanner(target_domain: str) -> Dict[str, Any]:
    """CDN detection and enumeration"""
    try:
        cdn_indicators = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'akamai': ['akamai', 'aka-'],
            'fastly': ['fastly', 'x-fastly'],
            'cloudfront': ['cloudfront', 'x-amz-cf-id'],
            'maxcdn': ['maxcdn', 'x-cdn'],
        }

        findings = []
        resp = requests.get(f"http://{target_domain}", timeout=10, allow_redirects=False)

        # Check headers for CDN indicators
        for cdn_name, indicators in cdn_indicators.items():
            for indicator in indicators:
                for header, value in resp.headers.items():
                    if indicator.lower() in header.lower() or indicator.lower() in str(value).lower():
                        findings.append({"cdn": cdn_name, "header": header, "value": value})

        # Check CNAME records
        try:
            import dns.resolver
            cname_records = dns.resolver.resolve(target_domain, 'CNAME')
            for rdata in cname_records:
                cname = str(rdata.target)
                for cdn_name, indicators in cdn_indicators.items():
                    if any(ind in cname.lower() for ind in indicators):
                        findings.append({"cdn": cdn_name, "cname": cname})
        except:
            pass

        return {"success": True, "cdn_detected": len(findings) > 0, "findings": findings, "tool": "cdn-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def cache_poisoner(target_url: str, header_name: str = "X-Forwarded-Host") -> Dict[str, Any]:
    """Cache poisoning testing"""
    try:
        findings = []
        poison_values = ['evil.com', 'attacker.local', '"><script>alert(1)</script>']

        for poison_value in poison_values:
            headers = {header_name: poison_value}
            resp = requests.get(target_url, headers=headers, timeout=10)

            # Check if poisoned value appears in response
            if poison_value in resp.text:
                findings.append({
                    "header": header_name,
                    "poison_value": poison_value,
                    "reflected": True,
                    "cache_status": resp.headers.get('X-Cache', 'unknown')
                })

            # Check cache headers
            cache_headers = ['X-Cache', 'CF-Cache-Status', 'X-Cache-Hits', 'Age']
            for cache_header in cache_headers:
                if cache_header in resp.headers:
                    findings.append({
                        "cache_header": cache_header,
                        "value": resp.headers[cache_header],
                        "poisoned": poison_value in resp.text
                    })

        return {"success": True, "findings": findings, "tested_headers": [header_name], "tool": "cache-poisoner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def cdn_bypass(target_url: str, target_ip: Optional[str] = None) -> Dict[str, Any]:
    """CDN bypass techniques"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc

        findings = []

        # Technique 1: Direct IP access (if provided)
        if target_ip:
            try:
                headers = {'Host': domain}
                resp = requests.get(f"http://{target_ip}{parsed.path}", headers=headers, timeout=10)
                if resp.status_code == 200:
                    findings.append({"technique": "direct_ip", "ip": target_ip, "success": True})
            except:
                findings.append({"technique": "direct_ip", "ip": target_ip, "success": False})

        # Technique 2: Subdomain enumeration to find origin
        subdomains = ['origin', 'direct', 'backup', 'staging', 'dev']
        for subdomain in subdomains:
            test_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(test_domain)
                findings.append({"technique": "subdomain_enum", "subdomain": test_domain, "ip": ip})
            except:
                pass

        # Technique 3: Check for origin headers
        resp = requests.get(target_url, timeout=10)
        origin_headers = ['X-Origin-IP', 'X-Real-IP', 'X-Forwarded-For']
        for header in origin_headers:
            if header in resp.headers:
                findings.append({"technique": "origin_header", "header": header, "value": resp.headers[header]})

        return {"success": True, "bypass_methods": findings, "tool": "cdn-bypass"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def cloudflare_bypass(target_url: str) -> Dict[str, Any]:
    """Cloudflare bypass testing"""
    try:
        findings = []

        # Check for Cloudflare
        resp = requests.get(target_url, timeout=10)
        is_cloudflare = 'cf-ray' in resp.headers or 'cloudflare' in str(resp.headers).lower()

        if is_cloudflare:
            findings.append({"detected": "cloudflare", "cf_ray": resp.headers.get('cf-ray', 'N/A')})

            # Technique 1: Historical DNS records
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc
            findings.append({"technique": "check_historical_dns", "domain": domain, "suggestion": "Use SecurityTrails/DNSHistory"})

            # Technique 2: Check for origin leak
            origin_test_paths = ['/.well-known/security.txt', '/robots.txt', '/sitemap.xml']
            for path in origin_test_paths:
                test_url = target_url.rstrip('/') + path
                test_resp = requests.get(test_url, timeout=10)
                if 'X-Origin-IP' in test_resp.headers:
                    findings.append({"technique": "origin_leak", "path": path, "origin_ip": test_resp.headers['X-Origin-IP']})

        return {"success": True, "is_cloudflare": is_cloudflare, "bypass_methods": findings, "tool": "cloudflare-bypass"}
    except Exception as e:
        return {"success": False, "error": str(e)}
