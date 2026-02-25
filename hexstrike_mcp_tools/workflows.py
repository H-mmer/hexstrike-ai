# hexstrike_mcp_tools/workflows.py
"""MCP tool registrations for AI workflow tools (CTF, BugBounty, Intelligence)."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def analyze_target(target: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
    """AI-powered target analysis and attack surface mapping using the Intelligent Decision Engine."""
    return get_client().safe_post("api/intelligence/analyze-target", {
        "target": target,
        "analysis_type": analysis_type,
    })


@mcp.tool()
def select_optimal_tools(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
    """Select the best security tools for a target using AI-driven scoring.
    objective: comprehensive|quick|stealth"""
    return get_client().safe_post("api/intelligence/select-tools", {
        "target": target,
        "objective": objective,
    })


@mcp.tool()
def create_attack_chain(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
    """Build an intelligent multi-step attack chain from target profile."""
    return get_client().safe_post("api/intelligence/create-attack-chain", {
        "target": target,
        "objective": objective,
    })


@mcp.tool()
def technology_detection(target: str) -> Dict[str, Any]:
    """Detect technologies on target and return tool recommendations per tech stack."""
    return get_client().safe_post("api/intelligence/technology-detection", {
        "target": target,
    })


@mcp.tool()
def ctf_create_workflow(name: str, category: str = "misc", difficulty: str = "unknown",
                        description: str = "", points: int = 100) -> Dict[str, Any]:
    """Create an AI-driven CTF challenge workflow.
    category: web|crypto|pwn|forensics|rev|misc|osint
    difficulty: easy|medium|hard|insane|unknown"""
    return get_client().safe_post("api/ctf/create-challenge-workflow", {
        "name": name,
        "category": category,
        "difficulty": difficulty,
        "description": description,
        "points": points,
    })


@mcp.tool()
def ctf_auto_solve(name: str, category: str = "misc", difficulty: str = "unknown",
                   description: str = "", target: str = "") -> Dict[str, Any]:
    """Autonomous CTF challenge solver.
    category: web|crypto|pwn|forensics|rev|misc|osint"""
    return get_client().safe_post("api/ctf/auto-solve-challenge", {
        "name": name,
        "category": category,
        "difficulty": difficulty,
        "description": description,
        "target": target,
    })


@mcp.tool()
def ctf_suggest_tools(description: str, category: str = "misc") -> Dict[str, Any]:
    """Suggest optimal tools for a CTF challenge based on description and category."""
    return get_client().safe_post("api/ctf/suggest-tools", {
        "description": description,
        "category": category,
    })


@mcp.tool()
def ctf_crypto_solver(cipher_text: str, cipher_type: str = "unknown",
                       additional_info: str = "") -> Dict[str, Any]:
    """Analyse and suggest solutions for cryptography CTF challenges.
    cipher_type: unknown|caesar|vigenere|rsa|substitution"""
    return get_client().safe_post("api/ctf/cryptography-solver", {
        "cipher_text": cipher_text,
        "cipher_type": cipher_type,
        "additional_info": additional_info,
    })


@mcp.tool()
def ctf_forensics_analyzer(file_path: str, analysis_type: str = "comprehensive",
                             extract_hidden: bool = True) -> Dict[str, Any]:
    """Forensics challenge analyzer — metadata, steganography, hidden data extraction."""
    return get_client().safe_post("api/ctf/forensics-analyzer", {
        "file_path": file_path,
        "analysis_type": analysis_type,
        "extract_hidden": extract_hidden,
    })


@mcp.tool()
def ctf_binary_analyzer(binary_path: str, analysis_depth: str = "comprehensive",
                          find_gadgets: bool = True) -> Dict[str, Any]:
    """Binary analysis for reverse engineering and pwn CTF challenges.
    analysis_depth: basic|comprehensive|deep"""
    return get_client().safe_post("api/ctf/binary-analyzer", {
        "binary_path": binary_path,
        "analysis_depth": analysis_depth,
        "find_gadgets": find_gadgets,
    })


@mcp.tool()
def bugbounty_recon(domain: str, scope: Optional[str] = None,
                    program_type: str = "web") -> Dict[str, Any]:
    """Automated bug bounty reconnaissance workflow (subdomain enum, content discovery, params)."""
    return get_client().safe_post("api/bugbounty/reconnaissance-workflow", {
        "domain": domain,
        "scope": scope.split(",") if scope else [],
        "program_type": program_type,
    })


@mcp.tool()
def bugbounty_vuln_hunt(domain: str,
                         priority_vulns: str = "rce,sqli,xss,idor,ssrf") -> Dict[str, Any]:
    """Bug bounty vulnerability hunting workflow prioritized by bounty impact."""
    return get_client().safe_post("api/bugbounty/vulnerability-hunting-workflow", {
        "domain": domain,
        "priority_vulns": [v.strip() for v in priority_vulns.split(",")],
    })


@mcp.tool()
def bugbounty_osint(domain: str) -> Dict[str, Any]:
    """OSINT gathering workflow for bug bounty (domain intel, social media, email intel)."""
    return get_client().safe_post("api/bugbounty/osint-workflow", {"domain": domain})


@mcp.tool()
def bugbounty_comprehensive(domain: str, include_osint: bool = True,
                              include_business_logic: bool = True) -> Dict[str, Any]:
    """Full bug bounty assessment — recon + vuln hunting + OSINT + business logic."""
    return get_client().safe_post("api/bugbounty/comprehensive-assessment", {
        "domain": domain,
        "include_osint": include_osint,
        "include_business_logic": include_business_logic,
    })


@mcp.tool()
def cve_monitor(hours: int = 24, severity_filter: str = "HIGH,CRITICAL",
                keywords: str = "") -> Dict[str, Any]:
    """Monitor CVE databases for new vulnerabilities with AI exploitability analysis."""
    return get_client().safe_post("api/vuln-intel/cve-monitor", {
        "hours": hours,
        "severity_filter": severity_filter,
        "keywords": keywords,
    })


@mcp.tool()
def cve_exploit_generate(cve_id: str, target_os: str = "",
                          exploit_type: str = "poc") -> Dict[str, Any]:
    """Generate exploit proof-of-concept from CVE data using AI analysis."""
    return get_client().safe_post("api/vuln-intel/exploit-generate", {
        "cve_id": cve_id,
        "target_os": target_os,
        "exploit_type": exploit_type,
    })


@mcp.tool()
def threat_intelligence(indicators: str, timeframe: str = "30d") -> Dict[str, Any]:
    """Correlate threat intelligence for CVEs, IPs, and file hashes.
    indicators: comma-separated list (CVE-..., IP, hash)"""
    return get_client().safe_post("api/vuln-intel/threat-feeds", {
        "indicators": [i.strip() for i in indicators.split(",")],
        "timeframe": timeframe,
    })


@mcp.tool()
def zero_day_research(target_software: str,
                       analysis_depth: str = "standard") -> Dict[str, Any]:
    """AI-assisted zero-day vulnerability research for a target software.
    analysis_depth: quick|standard|comprehensive"""
    return get_client().safe_post("api/vuln-intel/zero-day-research", {
        "target_software": target_software,
        "analysis_depth": analysis_depth,
    })


@mcp.tool()
def ai_generate_payload(attack_type: str = "xss",
                         complexity: str = "basic",
                         technology: str = "") -> Dict[str, Any]:
    """Generate AI-powered contextual security testing payloads.
    attack_type: xss|sqli|ssrf|rce"""
    return get_client().safe_post("api/ai/generate_payload", {
        "attack_type": attack_type,
        "complexity": complexity,
        "technology": technology,
    })


@mcp.tool()
def ai_advanced_payload(attack_type: str, evasion_level: str = "standard",
                         target_context: str = "") -> Dict[str, Any]:
    """Generate advanced payloads with AI evasion techniques.
    evasion_level: standard|advanced|nation-state"""
    return get_client().safe_post("api/ai/advanced-payload-generation", {
        "attack_type": attack_type,
        "evasion_level": evasion_level,
        "target_context": target_context,
    })
