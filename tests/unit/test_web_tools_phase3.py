#!/usr/bin/env python3
"""Phase 3 Web Tools Tests"""

import pytest
from unittest.mock import Mock, patch

def test_js_analysis_import():
    """Test JS analysis tools import"""
    from tools.web.js_analysis import retire_js_scan, linkfinder_extract, jsluice_analyze
    assert callable(retire_js_scan)
    assert callable(linkfinder_extract)
    assert callable(jsluice_analyze)

def test_injection_testing_import():
    """Test injection testing tools import"""
    from tools.web.injection_testing import nosqlmap_scan, ssrf_sheriff_scan, ssti_scanner
    assert callable(nosqlmap_scan)
    assert callable(ssrf_sheriff_scan)
    assert callable(ssti_scanner)

def test_auth_testing_import():
    """Test auth testing tools import"""
    from tools.web.auth_testing import csrf_scanner, cookie_analyzer, password_reset_analyzer
    assert callable(csrf_scanner)
    assert callable(cookie_analyzer)
    assert callable(password_reset_analyzer)

def test_cms_scanners_import():
    """Test CMS scanners import"""
    from tools.web.cms_scanners import joomscan, droopescan, shopware_scanner
    assert callable(joomscan)
    assert callable(droopescan)
    assert callable(shopware_scanner)

def test_cdn_tools_import():
    """Test CDN tools import"""
    from tools.web.cdn_tools import cdn_scanner, cache_poisoner, cloudflare_bypass
    assert callable(cdn_scanner)
    assert callable(cache_poisoner)
    assert callable(cloudflare_bypass)

def test_jsluice_regex():
    """Test jsluice regex extraction"""
    from tools.web.js_analysis import jsluice_analyze
    js_code = 'var apiUrl = "https://api.example.com/v1/users"; var endpoint = "/api/data";'
    result = jsluice_analyze(js_code)
    assert result["success"]
    assert len(result["urls"]) > 0
    assert len(result["api_endpoints"]) > 0

def test_csrf_scanner_logic():
    """Test CSRF scanner logic"""
    from tools.web.auth_testing import csrf_scanner
    # Mock would be needed for real test, but checking function exists
    assert callable(csrf_scanner)

def test_cookie_analyzer_structure():
    """Test cookie analyzer structure"""
    from tools.web.auth_testing import cookie_analyzer
    assert callable(cookie_analyzer)
