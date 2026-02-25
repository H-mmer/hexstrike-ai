"""Web application security tool routes Blueprint."""
import subprocess
import shutil
import socket
import logging

import requests
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
web_bp = Blueprint('web', __name__)

# ---------------------------------------------------------------------------
# Optional Phase 3 module imports
# ---------------------------------------------------------------------------

try:
    from tools.web.js_analysis import retire_js_scan, linkfinder_extract, secretfinder_analyze
    _JS_ANALYSIS_AVAILABLE = True
except ImportError:
    _JS_ANALYSIS_AVAILABLE = False

try:
    from tools.web.injection_testing import nosqlmap_scan, ssti_scanner, crlf_injection_scan
    _INJECTION_AVAILABLE = True
except ImportError:
    _INJECTION_AVAILABLE = False

try:
    from tools.web.cms_scanners import joomscan, droopescan
    _CMS_AVAILABLE = True
except ImportError:
    _CMS_AVAILABLE = False

try:
    from tools.web.auth_testing import csrf_scanner, cookie_analyzer
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

try:
    from tools.web.cdn_tools import cdn_bypass, cdn_scanner
    _CDN_AVAILABLE = True
except ImportError:
    _CDN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_not_found(tool_name: str):
    """Return a standard 'tool not installed' response (503 Service Unavailable)."""
    return jsonify({
        "success": False,
        "error": f"{tool_name} is not installed or not on PATH",
        "output": "",
    }), 503


def _run(cmd: list, timeout: int = 120):
    """Execute a command list and return a JSON-serialisable result dict."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        "success": result.returncode == 0,
        "output": result.stdout,
        "error": result.stderr,
    }


# ---------------------------------------------------------------------------
# gobuster — directory/DNS/vhost brute-force
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/gobuster', methods=['POST'])
def gobuster():
    """Execute gobuster directory, DNS, or vhost scan."""
    params = request.json or {}
    target = params.get('target', '') or params.get('url', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('gobuster'):
        return _tool_not_found('gobuster')
    mode = params.get('mode', 'dir')
    wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    extensions = params.get('extensions', '')
    threads = params.get('threads', 10)
    additional_args = params.get('additional_args', '')
    cmd = ['gobuster', mode, '-u', target, '-w', wordlist, '-t', str(threads), '-q']
    if extensions and mode == 'dir':
        cmd.extend(['-x', extensions])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"gobuster error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# nuclei — template-based vulnerability scanner
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/nuclei', methods=['POST'])
def nuclei():
    """Execute Nuclei vulnerability scanner."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('nuclei'):
        return _tool_not_found('nuclei')
    severity = params.get('severity', '')
    templates = params.get('templates', '') or params.get('template', '')
    tags = params.get('tags', '')
    additional_args = params.get('additional_args', '')
    cmd = ['nuclei', '-u', target, '-silent']
    if severity:
        cmd.extend(['-severity', severity])
    if templates:
        cmd.extend(['-t', templates])
    if tags:
        cmd.extend(['-tags', tags])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"nuclei error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# nikto — web server scanner
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/nikto', methods=['POST'])
def nikto():
    """Execute Nikto web server scanner."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('nikto'):
        return _tool_not_found('nikto')
    options = params.get('options', '')
    additional_args = params.get('additional_args', '')
    cmd = ['nikto', '-h', target]
    if options:
        cmd.extend(options.split())
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"nikto error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# sqlmap — SQL injection testing
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/sqlmap', methods=['POST'])
def sqlmap():
    """Execute SQLMap SQL injection tester."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('sqlmap'):
        return _tool_not_found('sqlmap')
    data = params.get('data', '')
    level = params.get('level', 1)
    risk = params.get('risk', 1)
    additional_args = params.get('additional_args', '')
    cmd = ['sqlmap', '-u', url, '--batch', f'--level={level}', f'--risk={risk}']
    if data:
        cmd.extend(['--data', data])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"sqlmap error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# ffuf — web fuzzer
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/ffuf', methods=['POST'])
def ffuf():
    """Execute ffuf web fuzzer. Include FUZZ keyword in the URL."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('ffuf'):
        return _tool_not_found('ffuf')
    wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    match_codes = params.get('match_codes', '200,204,301,302,307,401,403')
    additional_args = params.get('additional_args', '')
    # If FUZZ is not already in the URL, append /FUZZ for directory mode
    fuzz_url = url if 'FUZZ' in url else f'{url}/FUZZ'
    cmd = ['ffuf', '-u', fuzz_url, '-w', wordlist, '-mc', match_codes]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"ffuf error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# feroxbuster — recursive content discovery
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/feroxbuster', methods=['POST'])
def feroxbuster():
    """Execute Feroxbuster recursive content discovery."""
    params = request.json or {}
    target = params.get('target', '') or params.get('url', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('feroxbuster'):
        return _tool_not_found('feroxbuster')
    wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    threads = params.get('threads', 10)
    additional_args = params.get('additional_args', '')
    cmd = ['feroxbuster', '-u', target, '-w', wordlist, '-t', str(threads), '--silent']
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"feroxbuster error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# wpscan — WordPress vulnerability scanner
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/wpscan', methods=['POST'])
def wpscan():
    """Execute WPScan WordPress vulnerability scanner."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('wpscan'):
        return _tool_not_found('wpscan')
    enumerate = params.get('enumerate', 'vp,vt,u')
    additional_args = params.get('additional_args', '')
    cmd = ['wpscan', '--url', url, '--enumerate', enumerate]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"wpscan error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# dalfox — XSS vulnerability scanner
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/dalfox', methods=['POST'])
def dalfox():
    """Execute Dalfox XSS vulnerability scanner."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('dalfox'):
        return _tool_not_found('dalfox')
    mining_dom = params.get('mining_dom', True)
    mining_dict = params.get('mining_dict', True)
    additional_args = params.get('additional_args', '')
    cmd = ['dalfox', 'url', url]
    if mining_dom:
        cmd.append('--mining-dom')
    if mining_dict:
        cmd.append('--mining-dict')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"dalfox error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# dirsearch — directory and file discovery
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/dirsearch', methods=['POST'])
def dirsearch():
    """Execute Dirsearch directory and file discovery."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('dirsearch'):
        return _tool_not_found('dirsearch')
    extensions = params.get('extensions', 'php,html,js,txt,xml,json')
    wordlist = params.get('wordlist', '')
    threads = params.get('threads', 30)
    recursive = params.get('recursive', False)
    additional_args = params.get('additional_args', '')
    cmd = ['dirsearch', '-u', url, '-e', extensions, '-t', str(threads), '--quiet']
    if wordlist:
        cmd.extend(['-w', wordlist])
    if recursive:
        cmd.append('-r')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"dirsearch error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# wfuzz — web fuzzer
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/wfuzz', methods=['POST'])
def wfuzz():
    """Execute Wfuzz web application fuzzer."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('wfuzz'):
        return _tool_not_found('wfuzz')
    wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    additional_args = params.get('additional_args', '')
    cmd = ['wfuzz', '-w', wordlist, url]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"wfuzz error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# katana — next-generation crawler
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/katana', methods=['POST'])
def katana():
    """Execute Katana next-generation web crawler."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('katana'):
        return _tool_not_found('katana')
    depth = params.get('depth', 3)
    js_crawl = params.get('js_crawl', True)
    additional_args = params.get('additional_args', '')
    cmd = ['katana', '-u', url, '-d', str(depth), '-silent']
    if js_crawl:
        cmd.append('-jc')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"katana error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# arjun — HTTP parameter discovery
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/arjun', methods=['POST'])
def arjun():
    """Execute Arjun HTTP parameter discovery."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if not shutil.which('arjun'):
        return _tool_not_found('arjun')
    method = params.get('method', 'GET')
    threads = params.get('threads', 25)
    additional_args = params.get('additional_args', '')
    cmd = ['arjun', '-u', url, '-m', method, '-t', str(threads)]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"arjun error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# paramspider — parameter mining from web archives
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/paramspider', methods=['POST'])
def paramspider():
    """Execute ParamSpider parameter mining."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('paramspider'):
        return _tool_not_found('paramspider')
    additional_args = params.get('additional_args', '')
    cmd = ['paramspider', '-d', domain]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"paramspider error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3 — /api/tools/web/js-analysis
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/web/js-analysis', methods=['POST'])
def js_analysis():
    """JavaScript security analysis — secrets, endpoints, vulnerable libraries."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if _JS_ANALYSIS_AVAILABLE:
        try:
            retire_result = retire_js_scan(url)
            linkfinder_result = linkfinder_extract(url)
            secret_result = secretfinder_analyze(url)
            return jsonify({
                "success": True,
                "retire_js": retire_result,
                "linkfinder": linkfinder_result,
                "secretfinder": secret_result,
                "tool": "js-analysis",
            })
        except Exception as e:
            logger.warning(f"js_analysis module error, falling back: {e}")
    # Subprocess fallback
    try:
        result = subprocess.run(
            ['linkfinder', '-i', url, '-o', 'cli'],
            capture_output=True, text=True, timeout=60,
        )
        return jsonify({
            "success": True,
            "output": result.stdout,
            "error": result.stderr,
            "tool": "js-analysis",
        })
    except FileNotFoundError:
        return jsonify({
            "success": True,
            "output": f"JS analysis requested for {url} — linkfinder not installed",
            "tool": "js-analysis",
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"js-analysis error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3 — /api/tools/web/injection
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/web/injection', methods=['POST'])
def injection_test():
    """Injection vulnerability testing — NoSQL, SSRF, XXE, SSTI, CRLF."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    inject_type = params.get('type', 'nosql')
    if _INJECTION_AVAILABLE:
        try:
            if inject_type == 'nosql':
                result = nosqlmap_scan(url)
            elif inject_type == 'ssti':
                result = ssti_scanner(url)
            elif inject_type == 'crlf':
                result = crlf_injection_scan(url)
            else:
                result = nosqlmap_scan(url)
            return jsonify({**result, "injection_type": inject_type})
        except Exception as e:
            logger.warning(f"injection_testing module error, falling back: {e}")
    # Subprocess fallback
    try:
        tool = 'nosqlmap' if inject_type == 'nosql' else 'tplmap'
        result = subprocess.run(
            [tool, '--url', url],
            capture_output=True, text=True, timeout=120,
        )
        return jsonify({
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "injection_type": inject_type,
            "tool": tool,
        })
    except FileNotFoundError:
        return jsonify({
            "success": True,
            "output": f"Injection test ({inject_type}) requested for {url} — tool not installed",
            "injection_type": inject_type,
            "tool": inject_type,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"injection-test error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3 — /api/tools/web/cms-scan
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/web/cms-scan', methods=['POST'])
def cms_scan():
    """CMS security scan — WordPress (wpscan), Joomla (joomscan), Drupal (droopescan)."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    cms = params.get('cms', 'wordpress').lower()
    if cms == 'wordpress':
        if not shutil.which('wpscan'):
            return _tool_not_found('wpscan')
        cmd = ['wpscan', '--url', url, '--enumerate', 'vp,vt,u']
        try:
            return jsonify({**_run(cmd, timeout=300), "cms": "wordpress"})
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""})
        except Exception as e:
            logger.error(f"wpscan error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    elif cms == 'joomla':
        if _CMS_AVAILABLE:
            try:
                result = joomscan(url)
                return jsonify({**result, "cms": "joomla"})
            except Exception as e:
                logger.warning(f"joomscan module error, falling back: {e}")
        if not shutil.which('joomscan'):
            return _tool_not_found('joomscan')
        cmd = ['joomscan', '--url', url]
        try:
            return jsonify({**_run(cmd, timeout=300), "cms": "joomla"})
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""})
        except Exception as e:
            logger.error(f"joomscan error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    elif cms == 'drupal':
        if _CMS_AVAILABLE:
            try:
                result = droopescan(url, cms_type='drupal')
                return jsonify({**result, "cms": "drupal"})
            except Exception as e:
                logger.warning(f"droopescan module error, falling back: {e}")
        if not shutil.which('droopescan'):
            return _tool_not_found('droopescan')
        cmd = ['droopescan', 'scan', 'drupal', '-u', url]
        try:
            return jsonify({**_run(cmd, timeout=300), "cms": "drupal"})
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""})
        except Exception as e:
            logger.error(f"droopescan error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    else:
        return jsonify({"success": False, "error": f"Unsupported CMS: {cms}. Use: wordpress, joomla, drupal"}), 400


# ---------------------------------------------------------------------------
# Phase 3 — /api/tools/web/auth-test
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/web/auth-test', methods=['POST'])
def auth_test():
    """Authentication vulnerability testing — CSRF, cookies, session handling."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    if _AUTH_AVAILABLE:
        try:
            csrf_result = csrf_scanner(url)
            cookie_result = cookie_analyzer(url)
            return jsonify({
                "success": True,
                "csrf": csrf_result,
                "cookies": cookie_result,
                "tool": "auth-test",
            })
        except Exception as e:
            logger.warning(f"auth_testing module error, falling back to HTTP probe: {e}")
    # Lightweight fallback: inspect cookies and headers via requests
    try:
        resp = requests.get(url, timeout=10)
        findings = []
        if 'X-CSRF-Token' not in resp.headers and 'X-XSRF-Token' not in resp.headers:
            findings.append({"issue": "missing_csrf_headers"})
        cookies = []
        for name, value in resp.cookies.items():
            cookies.append({"name": name, "value_length": len(str(value))})
        return jsonify({
            "success": True,
            "findings": findings,
            "cookies_checked": cookies,
            "tool": "auth-test",
        })
    except Exception as e:
        logger.error(f"auth-test error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3 — /api/tools/web/cdn-bypass
# ---------------------------------------------------------------------------

@web_bp.route('/api/tools/web/cdn-bypass', methods=['POST'])
def cdn_bypass_route():
    """CDN bypass techniques — origin IP discovery, cache analysis."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    target_ip = params.get('target_ip', '')
    if _CDN_AVAILABLE:
        try:
            result = cdn_bypass(url, target_ip=target_ip or None)
            return jsonify(result)
        except Exception as e:
            logger.warning(f"cdn_tools module error, falling back: {e}")
    # Lightweight fallback: check CDN headers and probe origin subdomains
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        findings = []
        resp = requests.get(url, timeout=10)
        cdn_headers = ['CF-Ray', 'X-Cache', 'X-Amz-Cf-Id', 'Fastly-Debug-Digest', 'X-CDN']
        for h in cdn_headers:
            if h in resp.headers:
                findings.append({"cdn_header": h, "value": resp.headers[h]})
        for sub in ('origin', 'direct', 'staging'):
            test = f'{sub}.{domain}'
            try:
                ip = socket.gethostbyname(test)
                findings.append({"subdomain": test, "ip": ip})
            except OSError:
                pass
        return jsonify({
            "success": True,
            "bypass_methods": findings,
            "tool": "cdn-bypass",
        })
    except Exception as e:
        logger.error(f"cdn-bypass error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500
