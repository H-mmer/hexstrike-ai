#!/usr/bin/env python3
"""JavaScript Security Analysis Tools - Simple, focused implementations"""

import subprocess
import re
from typing import Dict, Any, List

def retire_js_scan(target_url: str) -> Dict[str, Any]:
    """Scan for vulnerable JS libraries"""
    try:
        cmd = ['retire', '--outputformat', 'json', target_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {"success": result.returncode == 0, "output": result.stdout, "tool": "retire.js"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def linkfinder_extract(target_url: str) -> Dict[str, Any]:
    """Extract endpoints from JavaScript"""
    try:
        cmd = ['linkfinder', '-i', target_url, '-o', 'cli']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        endpoints = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        return {"success": True, "endpoints": endpoints, "count": len(endpoints), "tool": "linkfinder"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def subjs_discover(target_domain: str) -> Dict[str, Any]:
    """Discover JavaScript files from domain"""
    try:
        cmd = ['subjs', '-d', target_domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        js_files = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        return {"success": True, "js_files": js_files, "count": len(js_files), "tool": "subjs"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def trufflehog_scan(repo_path: str) -> Dict[str, Any]:
    """Scan for secrets in code"""
    try:
        cmd = ['trufflehog', 'filesystem', repo_path, '--json']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"success": result.returncode == 0, "findings": result.stdout, "tool": "trufflehog"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def secretfinder_analyze(js_url: str) -> Dict[str, Any]:
    """Find secrets in JavaScript files"""
    try:
        cmd = ['python3', '-m', 'secretfinder', '-i', js_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"success": True, "secrets": result.stdout, "tool": "secretfinder"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def sourcemapper_extract(js_url: str) -> Dict[str, Any]:
    """Extract and analyze source maps"""
    try:
        import requests
        resp = requests.get(js_url, timeout=30)
        has_sourcemap = '//# sourceMappingURL=' in resp.text
        return {"success": True, "has_sourcemap": has_sourcemap, "tool": "sourcemapper"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def js_beautify_code(js_code: str) -> Dict[str, Any]:
    """Beautify minified JavaScript"""
    try:
        import jsbeautifier
        beautified = jsbeautifier.beautify(js_code)
        return {"success": True, "beautified": beautified, "tool": "js-beautify"}
    except ImportError:
        return {"success": False, "error": "jsbeautifier not installed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def jsluice_analyze(js_content: str) -> Dict[str, Any]:
    """Extract URLs and secrets from JS"""
    try:
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, js_content)
        api_pattern = r'/api/[^\s<>"{}|\\^`\[\]]+'
        api_endpoints = re.findall(api_pattern, js_content)
        return {"success": True, "urls": urls, "api_endpoints": api_endpoints, "tool": "jsluice"}
    except Exception as e:
        return {"success": False, "error": str(e)}
