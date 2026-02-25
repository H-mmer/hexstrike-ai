# hexstrike_mcp_tools/web.py
"""MCP tool registrations for web application security tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def gobuster_scan(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  extensions: str = "php,html,js,txt", mode: str = "dir") -> Dict[str, Any]:
    """Directory, DNS, and vhost brute-force using Gobuster.
    mode: dir | dns | fuzz | vhost
    """
    return get_client().safe_post("api/tools/gobuster", {
        "target": target, "wordlist": wordlist, "extensions": extensions, "mode": mode
    })


@mcp.tool()
def nuclei_scan(target: str, templates: str = "",
                severity: str = "medium,high,critical", tags: str = "") -> Dict[str, Any]:
    """Vulnerability scanning with Nuclei templates.
    severity: info | low | medium | high | critical (comma-separated)
    """
    return get_client().safe_post("api/tools/nuclei", {
        "target": target, "templates": templates, "severity": severity, "tags": tags
    })


@mcp.tool()
def nikto_scan(target: str, options: str = "") -> Dict[str, Any]:
    """Web server vulnerability scanner using Nikto."""
    return get_client().safe_post("api/tools/nikto", {
        "target": target, "options": options
    })


@mcp.tool()
def sqlmap_scan(url: str, data: str = "", level: int = 1, risk: int = 1) -> Dict[str, Any]:
    """SQL injection testing using SQLMap.
    level: 1-5 (test depth), risk: 1-3 (risk of tests)
    """
    return get_client().safe_post("api/tools/sqlmap", {
        "url": url, "data": data, "level": level, "risk": risk
    })


@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
              match_codes: str = "200,204,301,302,307,401,403") -> Dict[str, Any]:
    """Web fuzzing with ffuf. Use FUZZ keyword in URL: http://target/FUZZ
    Or pass the base URL and FUZZ will be appended automatically.
    """
    return get_client().safe_post("api/tools/ffuf", {
        "url": url, "wordlist": wordlist, "match_codes": match_codes
    })


@mcp.tool()
def feroxbuster_scan(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                     threads: int = 10) -> Dict[str, Any]:
    """Recursive content discovery using Feroxbuster."""
    return get_client().safe_post("api/tools/feroxbuster", {
        "target": target, "wordlist": wordlist, "threads": threads
    })


@mcp.tool()
def wpscan(url: str, enumerate: str = "vp,vt,u") -> Dict[str, Any]:
    """WordPress vulnerability scanner.
    enumerate: vp (vuln plugins), vt (vuln themes), u (users)
    """
    return get_client().safe_post("api/tools/wpscan", {
        "url": url, "enumerate": enumerate
    })


@mcp.tool()
def dalfox_xss(url: str, mining_dom: bool = True, mining_dict: bool = True) -> Dict[str, Any]:
    """XSS vulnerability scanner using Dalfox."""
    return get_client().safe_post("api/tools/dalfox", {
        "url": url, "mining_dom": mining_dom, "mining_dict": mining_dict
    })


@mcp.tool()
def dirsearch(url: str, extensions: str = "php,html,js,txt",
              recursive: bool = False, threads: int = 30) -> Dict[str, Any]:
    """Directory and file discovery using Dirsearch."""
    return get_client().safe_post("api/tools/dirsearch", {
        "url": url, "extensions": extensions, "recursive": recursive, "threads": threads
    })


@mcp.tool()
def wfuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
    """Web application fuzzer. Include FUZZ keyword in URL."""
    return get_client().safe_post("api/tools/wfuzz", {
        "url": url, "wordlist": wordlist
    })


@mcp.tool()
def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True) -> Dict[str, Any]:
    """Next-generation web crawler and spidering using Katana."""
    return get_client().safe_post("api/tools/katana", {
        "url": url, "depth": depth, "js_crawl": js_crawl
    })


@mcp.tool()
def arjun_params(url: str, method: str = "GET", threads: int = 25) -> Dict[str, Any]:
    """HTTP parameter discovery using Arjun. method: GET | POST | JSON | XML"""
    return get_client().safe_post("api/tools/arjun", {
        "url": url, "method": method, "threads": threads
    })


@mcp.tool()
def paramspider(domain: str) -> Dict[str, Any]:
    """Parameter mining from web archives using ParamSpider."""
    return get_client().safe_post("api/tools/paramspider", {"domain": domain})


# ---------------------------------------------------------------------------
# Phase 3 web tool MCP registrations
# ---------------------------------------------------------------------------

@mcp.tool()
def web_js_analysis(url: str) -> Dict[str, Any]:
    """JavaScript security analysis — finds secrets, endpoints, and vulnerable libraries.
    Runs retire.js, linkfinder, and secretfinder against the target URL.
    """
    return get_client().safe_post("api/tools/web/js-analysis", {"url": url})


@mcp.tool()
def web_injection_test(url: str, inject_type: str = "nosql") -> Dict[str, Any]:
    """Injection vulnerability testing.
    inject_type: nosql | ssrf | xxe | ssti | crlf
    """
    return get_client().safe_post("api/tools/web/injection", {
        "url": url, "type": inject_type
    })


@mcp.tool()
def web_cms_scan(url: str, cms: str = "wordpress") -> Dict[str, Any]:
    """CMS-specific security scan.
    cms: wordpress | joomla | drupal
    """
    return get_client().safe_post("api/tools/web/cms-scan", {
        "url": url, "cms": cms
    })


@mcp.tool()
def web_auth_test(url: str) -> Dict[str, Any]:
    """Authentication vulnerability testing — CSRF, cookies, session handling."""
    return get_client().safe_post("api/tools/web/auth-test", {"url": url})


@mcp.tool()
def web_cdn_bypass(url: str, target_ip: str = "") -> Dict[str, Any]:
    """CDN bypass techniques — discovers origin IP, checks cache poisoning vectors."""
    return get_client().safe_post("api/tools/web/cdn-bypass", {
        "url": url, "target_ip": target_ip
    })
