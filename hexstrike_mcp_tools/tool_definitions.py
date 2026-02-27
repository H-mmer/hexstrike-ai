# hexstrike_mcp_tools/tool_definitions.py
"""Populate SmartToolRegistry with all HexStrike tool definitions."""
from hexstrike_mcp_tools.registry import SmartToolRegistry


def build_registry() -> SmartToolRegistry:
    """Build and return a fully populated SmartToolRegistry."""
    r = SmartToolRegistry()

    # ── network_scan (6 tools) ────────────────────────────────────
    r.register("network_scan", "nmap", "api/tools/nmap", description="Nmap port/version scan")
    r.register("network_scan", "rustscan", "api/tools/rustscan", description="Fast port scanner")
    r.register("network_scan", "masscan", "api/tools/masscan", description="High-speed port scanner")
    r.register("network_scan", "naabu", "api/tools/network/naabu", description="Fast port scan (Naabu)")
    r.register("network_scan", "zmap", "api/tools/network/zmap", description="Network-wide fast scan")
    r.register("network_scan", "nmap-advanced", "api/tools/nmap-advanced", description="Advanced nmap with NSE/timing/OS detection")

    # ── network_recon (9 tools) ───────────────────────────────────
    r.register("network_recon", "amass", "api/tools/amass", description="Subdomain enumeration")
    r.register("network_recon", "subfinder", "api/tools/subfinder", description="Passive subdomain discovery")
    r.register("network_recon", "httpx", "api/tools/httpx", description="HTTP probing and tech detection")
    r.register("network_recon", "waybackurls", "api/tools/waybackurls", description="Wayback Machine URL fetch")
    r.register("network_recon", "gau", "api/tools/gau", description="GetAllUrls from multiple sources")
    r.register("network_recon", "dnsenum", "api/tools/dnsenum", description="DNS enumeration and zone transfer")
    r.register("network_recon", "fierce", "api/tools/fierce", description="DNS recon and brute-force")
    r.register("network_recon", "autorecon", "api/tools/autorecon", description="Comprehensive automated recon")
    r.register("network_recon", "nbtscan", "api/tools/nbtscan", description="NetBIOS name scanner")

    # ── network_enum (6 tools) ────────────────────────────────────
    r.register("network_enum", "enum4linux", "api/tools/enum4linux", description="Windows/Samba enumeration")
    r.register("network_enum", "enum4linux-ng", "api/tools/enum4linux-ng", description="Advanced SMB enumeration")
    r.register("network_enum", "smbmap", "api/tools/smbmap", description="SMB share enumeration")
    r.register("network_enum", "netexec", "api/tools/netexec", description="Network credential testing")
    r.register("network_enum", "snmp-check", "api/tools/network/snmp-check", description="SNMP enumeration")
    r.register("network_enum", "wafw00f", "api/tools/wafw00f", description="WAF detection")

    # ── network_advanced (4 tools) ────────────────────────────────
    r.register("network_advanced", "scapy", "api/tools/network/scapy", description="Packet crafting with Scapy")
    r.register("network_advanced", "ipv6", "api/tools/network/ipv6-toolkit", description="IPv6 security testing")
    r.register("network_advanced", "udp-proto", "api/tools/network/udp-proto-scanner", description="UDP protocol scanner")
    r.register("network_advanced", "cisco-torch", "api/tools/network/cisco-torch", description="Cisco device scanning")

    # ── web_scan (8 tools) ────────────────────────────────────────
    r.register("web_scan", "gobuster", "api/tools/gobuster", description="Directory/DNS/vhost brute-force")
    r.register("web_scan", "nuclei", "api/tools/nuclei", description="Template-based vulnerability scanner")
    r.register("web_scan", "nikto", "api/tools/nikto", description="Web server vulnerability scanner")
    r.register("web_scan", "ffuf", "api/tools/ffuf", description="Web fuzzer")
    r.register("web_scan", "feroxbuster", "api/tools/feroxbuster", description="Recursive content discovery")
    r.register("web_scan", "dirsearch", "api/tools/dirsearch", description="Directory and file discovery")
    r.register("web_scan", "wfuzz", "api/tools/wfuzz", description="Web application fuzzer")
    r.register("web_scan", "katana", "api/tools/katana", description="Web crawler and spider")

    # ── web_vuln_test (4 tools) ───────────────────────────────────
    r.register("web_vuln_test", "sqlmap", "api/tools/sqlmap", description="SQL injection testing")
    r.register("web_vuln_test", "dalfox", "api/tools/dalfox", description="XSS vulnerability scanner")
    r.register("web_vuln_test", "arjun", "api/tools/arjun", description="HTTP parameter discovery")
    r.register("web_vuln_test", "paramspider", "api/tools/paramspider", description="Parameter mining from archives")

    # ── web_specialized (6 tools) ─────────────────────────────────
    r.register("web_specialized", "wpscan", "api/tools/wpscan", description="WordPress vulnerability scanner")
    r.register("web_specialized", "js-analysis", "api/tools/web/js-analysis", description="JavaScript security analysis")
    r.register("web_specialized", "injection-test", "api/tools/web/injection", description="Injection vulnerability testing")
    r.register("web_specialized", "cms-scan", "api/tools/web/cms-scan", description="CMS-specific security scan")
    r.register("web_specialized", "auth-test", "api/tools/web/auth-test", description="Authentication vulnerability testing")
    r.register("web_specialized", "cdn-bypass", "api/tools/web/cdn-bypass", description="CDN bypass techniques")

    # ── cloud_assess (12 tools) ───────────────────────────────────
    r.register("cloud_assess", "trivy", "api/tools/trivy", description="Container/filesystem vulnerability scanner")
    r.register("cloud_assess", "prowler", "api/tools/prowler", description="Cloud security assessment")
    r.register("cloud_assess", "kube-hunter", "api/tools/kube-hunter", description="Kubernetes security hunting")
    r.register("cloud_assess", "kube-bench", "api/tools/kube-bench", description="CIS Kubernetes benchmarks")
    r.register("cloud_assess", "docker-bench", "api/tools/docker-bench-security", description="Docker CIS benchmark")
    r.register("cloud_assess", "scout-suite", "api/tools/scout-suite", description="Multi-cloud security auditing")
    r.register("cloud_assess", "cloudmapper", "api/tools/cloudmapper", description="AWS cloud visualization/audit")
    r.register("cloud_assess", "pacu", "api/tools/pacu", description="AWS exploitation framework")
    r.register("cloud_assess", "falco", "api/tools/falco", description="Runtime security monitoring")
    r.register("cloud_assess", "checkov", "api/tools/checkov", description="IaC misconfiguration scanner")
    r.register("cloud_assess", "terrascan", "api/tools/terrascan", description="IaC policy violations scanner")
    r.register("cloud_assess", "kubescape", "api/tools/cloud/kubescape", description="Kubernetes security posture")

    # ── cloud_container (2 tools) ─────────────────────────────────
    r.register("cloud_container", "container-escape", "api/tools/cloud/container-escape", description="Container escape vulnerability check")
    r.register("cloud_container", "rbac-audit", "api/tools/cloud/rbac-audit", description="Kubernetes RBAC audit")

    # ── binary_analyze (11 tools) ─────────────────────────────────
    r.register("binary_analyze", "gdb", "api/tools/gdb", description="Binary debugging with GDB")
    r.register("binary_analyze", "radare2", "api/tools/radare2", description="Reverse engineering with Radare2")
    r.register("binary_analyze", "ghidra", "api/tools/ghidra", description="Reverse engineering with Ghidra")
    r.register("binary_analyze", "binwalk", "api/tools/binwalk", description="Firmware/binary file scanning")
    r.register("binary_analyze", "checksec", "api/tools/checksec", description="Binary security mitigations check")
    r.register("binary_analyze", "strings", "api/tools/strings", description="String extraction from binaries")
    r.register("binary_analyze", "objdump", "api/tools/objdump", description="Binary disassembly")
    r.register("binary_analyze", "ropgadget", "api/tools/ropgadget", description="ROP gadget finder")
    r.register("binary_analyze", "angr", "api/tools/angr", description="Symbolic execution with angr")
    r.register("binary_analyze", "rizin", "api/tools/binary/rizin", description="Reverse engineering with Rizin")
    r.register("binary_analyze", "msfvenom", "api/tools/msfvenom", description="Payload generation with Metasploit")

    # ── binary_forensics (7 tools) ────────────────────────────────
    r.register("binary_forensics", "volatility3", "api/tools/volatility3", description="Memory forensics")
    r.register("binary_forensics", "foremost", "api/tools/foremost", description="File carving from disk images")
    r.register("binary_forensics", "steghide", "api/tools/steghide", description="Steganography hide/extract")
    r.register("binary_forensics", "exiftool", "api/tools/exiftool", description="File metadata extraction")
    r.register("binary_forensics", "yara", "api/tools/binary/yara", description="Malware pattern scanning")
    r.register("binary_forensics", "floss", "api/tools/binary/floss", description="Deobfuscated string extraction")
    r.register("binary_forensics", "forensics", "api/tools/binary/forensics", description="Digital forensics with Autopsy/Sleuth Kit")

    # ── mobile_test (4 tools) ─────────────────────────────────────
    r.register("mobile_test", "apk-analyze", "api/tools/mobile/apk-analyze", description="APK analysis (apktool + jadx + androguard)")
    r.register("mobile_test", "ios-analyze", "api/tools/mobile/ios-analyze", description="iOS IPA analysis")
    r.register("mobile_test", "drozer", "api/tools/mobile/drozer", description="Android security audit")
    r.register("mobile_test", "mitm", "api/tools/mobile/mitm", description="Mobile traffic interception")

    # ── api_test (4 tools) ────────────────────────────────────────
    r.register("api_test", "api-discover", "api/tools/api/discover", description="API endpoint discovery")
    r.register("api_test", "api-fuzz", "api/tools/api/fuzz", description="API endpoint fuzzing")
    r.register("api_test", "api-auth-test", "api/tools/api/auth-test", description="API authentication testing")
    r.register("api_test", "api-monitor", "api/tools/api/monitoring", description="API security monitoring")

    # ── wireless_test (3 tools) ───────────────────────────────────
    r.register("wireless_test", "wifi-attack", "api/tools/wireless/wifi-attack", description="WiFi security testing")
    r.register("wireless_test", "bluetooth-scan", "api/tools/wireless/bluetooth-scan", description="Bluetooth scanning")
    r.register("wireless_test", "rf-analysis", "api/tools/wireless/rf", description="RF signal analysis")

    # ── osint_gather (5 tools) ────────────────────────────────────
    r.register("osint_gather", "passive-recon", "api/osint/passive-recon", description="Passive reconnaissance")
    r.register("osint_gather", "threat-intel", "api/osint/threat-intel", description="IOC threat intelligence")
    r.register("osint_gather", "social-recon", "api/osint/social-recon", description="Social media OSINT")
    r.register("osint_gather", "breach-check", "api/osint/breach-check", description="Data breach check")
    r.register("osint_gather", "shodan", "api/osint/shodan", description="Shodan internet search")

    # ── intelligence (12 tools) ───────────────────────────────────
    r.register("intelligence", "analyze-target", "api/intelligence/analyze-target", description="AI target analysis")
    r.register("intelligence", "select-tools", "api/intelligence/select-tools", description="AI tool selection")
    r.register("intelligence", "attack-chain", "api/intelligence/create-attack-chain", description="Build attack chain")
    r.register("intelligence", "tech-detect", "api/intelligence/technology-detection", description="Technology detection")
    r.register("intelligence", "optimize-params", "api/intelligence/optimize-parameters", description="Tool parameter optimization")
    r.register("intelligence", "cve-monitor", "api/vuln-intel/cve-monitor", description="CVE monitoring")
    r.register("intelligence", "exploit-gen", "api/vuln-intel/exploit-generate", description="Exploit PoC generation")
    r.register("intelligence", "threat-feeds", "api/vuln-intel/threat-feeds", description="Threat intelligence correlation")
    r.register("intelligence", "payload-gen", "api/ai/generate_payload", description="AI security payload generation")
    r.register("intelligence", "advanced-payload", "api/ai/advanced-payload-generation", description="Advanced evasion payloads")
    r.register("intelligence", "test-payload", "api/ai/test_payload", description="Test payload against target")
    r.register("intelligence", "vuln-correlate", "api/vuln-intel/attack-chains", description="Vulnerability correlation and attack chains")

    # ── ctf (7 tools) ────────────────────────────────────────────
    r.register("ctf", "create-workflow", "api/ctf/create-challenge-workflow", description="Create CTF challenge workflow")
    r.register("ctf", "auto-solve", "api/ctf/auto-solve-challenge", description="Autonomous CTF solver")
    r.register("ctf", "suggest-tools", "api/ctf/suggest-tools", description="CTF tool suggestions")
    r.register("ctf", "crypto-solver", "api/ctf/cryptography-solver", description="Cryptography challenge solver")
    r.register("ctf", "forensics-analyzer", "api/ctf/forensics-analyzer", description="Forensics challenge analyzer")
    r.register("ctf", "binary-analyzer", "api/ctf/binary-analyzer", description="Binary CTF challenge analyzer")
    r.register("ctf", "team-strategy", "api/ctf/team-strategy", description="CTF team strategy planner")

    # ── bugbounty (6 tools) ───────────────────────────────────────
    r.register("bugbounty", "recon", "api/bugbounty/reconnaissance-workflow", description="Bug bounty recon workflow")
    r.register("bugbounty", "vuln-hunt", "api/bugbounty/vulnerability-hunting-workflow", description="Vulnerability hunting workflow")
    r.register("bugbounty", "business-logic", "api/bugbounty/business-logic-workflow", description="Business logic testing workflow")
    r.register("bugbounty", "osint", "api/bugbounty/osint-workflow", description="Bug bounty OSINT")
    r.register("bugbounty", "file-upload", "api/bugbounty/file-upload-testing", description="File upload vulnerability testing")
    r.register("bugbounty", "comprehensive", "api/bugbounty/comprehensive-assessment", description="Full bug bounty assessment")

    # ── async_scan (9 tools) ──────────────────────────────────────
    r.register("async_scan", "nmap-async", "/api/network/nmap/async", description="Async nmap scan")
    r.register("async_scan", "rustscan-async", "/api/network/rustscan/async", description="Async rustscan scan")
    r.register("async_scan", "masscan-async", "/api/network/masscan/async", description="Async masscan scan")
    r.register("async_scan", "amass-async", "/api/network/amass/async", description="Async amass scan")
    r.register("async_scan", "subfinder-async", "/api/network/subfinder/async", description="Async subfinder scan")
    r.register("async_scan", "nuclei-async", "/api/web/nuclei/async", description="Async nuclei scan")
    r.register("async_scan", "gobuster-async", "/api/web/gobuster/async", description="Async gobuster scan")
    r.register("async_scan", "feroxbuster-async", "/api/web/feroxbuster/async", description="Async feroxbuster scan")
    r.register("async_scan", "poll", "SPECIAL:poll", method="GET", description="Poll task status")

    # ── browser_stealth (4 tools) ─────────────────────────────────
    r.register("browser_stealth", "navigate", "/api/browser/navigate", description="Stealth browser navigation")
    r.register("browser_stealth", "screenshot", "/api/browser/screenshot", description="Browser screenshot")
    r.register("browser_stealth", "dom", "/api/browser/dom", description="DOM extraction")
    r.register("browser_stealth", "form-fill", "/api/browser/form-fill", description="Stealth form filling")

    # ── system_admin (6 tools) ────────────────────────────────────
    r.register("system_admin", "health", "health", method="GET", description="Server health check")
    r.register("system_admin", "command", "api/command", description="Execute shell command")
    r.register("system_admin", "cache-stats", "api/cache/stats", method="GET", description="Cache statistics")
    r.register("system_admin", "cache-clear", "api/cache/clear", description="Clear cache")
    r.register("system_admin", "telemetry", "api/telemetry", method="GET", description="Server telemetry")
    r.register("system_admin", "processes", "api/processes/list", method="GET", description="List running processes")

    return r
