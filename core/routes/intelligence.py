"""AI intelligence, CVE/vuln-intel, and AI payload routes Blueprint."""
import ipaddress
import logging
import re
import shutil
import socket
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests as requests_lib
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
intelligence_bp = Blueprint('intelligence', __name__)

# ---------------------------------------------------------------------------
# Optional agent imports
# ---------------------------------------------------------------------------

try:
    from agents.decision_engine import IntelligentDecisionEngine
    _DECISION_ENGINE_AVAILABLE = True
except ImportError:
    _DECISION_ENGINE_AVAILABLE = False

try:
    from agents.cve_intelligence import CVEIntelligenceManager
    _CVE_INTEL_AVAILABLE = True
except ImportError:
    _CVE_INTEL_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level singletons (lazy)
# ---------------------------------------------------------------------------

_decision_engine: Optional[Any] = None
_cve_intelligence: Optional[Any] = None


def _get_decision_engine():
    global _decision_engine
    if _decision_engine is None and _DECISION_ENGINE_AVAILABLE:
        engine = IntelligentDecisionEngine()
        # Disable the advanced optimizer path which depends on the server-level
        # parameter_optimizer global that does not exist in the Blueprint context.
        _decision_engine = engine
    return _decision_engine


def _get_cve_intelligence():
    global _cve_intelligence
    if _cve_intelligence is None and _CVE_INTEL_AVAILABLE:
        _cve_intelligence = CVEIntelligenceManager()
    return _cve_intelligence


# ---------------------------------------------------------------------------
# Lightweight AIExploitGenerator fallback
# ---------------------------------------------------------------------------

class _SimpleExploitGenerator:
    """Exploit lookup via searchsploit (exploitdb)."""

    def generate_exploit_from_cve(
        self, cve_data: Dict[str, Any], target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        cve_id = cve_data.get("cve_id", "")
        if not cve_id:
            return {"success": False, "error": "cve_id is required"}

        if not shutil.which("searchsploit"):
            return {"success": False, "error": "searchsploit not installed"}

        try:
            result = subprocess.run(
                ["searchsploit", "--cve", cve_id, "--json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return {"success": True, "exploits": [], "note": "No exploits found"}

            import json as _json
            data = _json.loads(result.stdout)
            exploits = [
                {
                    "edb_id": e.get("EDB-ID", ""),
                    "title": e.get("Title", ""),
                    "path": e.get("Path", ""),
                }
                for e in data.get("RESULTS_EXPLOIT", [])
            ]
            return {"success": True, "exploits": exploits, "cve_id": cve_id}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "searchsploit timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Lightweight VulnerabilityCorrelator fallback
# ---------------------------------------------------------------------------

class _SimpleVulnerabilityCorrelator:
    """Correlator that uses CVEIntelligenceManager for real CVE data lookup."""

    def find_attack_chains(
        self, target_software: str, attack_depth: int = 3
    ) -> Dict[str, Any]:
        try:
            cve_mgr = _get_cve_intelligence()
        except Exception:
            return {"success": False, "error": "CVE intelligence not available"}

        try:
            cves = cve_mgr.fetch_latest_cves(keyword=target_software, max_results=attack_depth)
            chains = []
            for i, cve in enumerate(cves if isinstance(cves, list) else cves.get("vulnerabilities", [])):
                cve_id = cve.get("cve_id", cve.get("id", f"CVE-UNKNOWN-{i}"))
                desc = cve.get("description", "No description available")
                chains.append({
                    "chain_id": f"CHAIN-{i + 1:03d}",
                    "description": f"Attack chain via {cve_id}",
                    "stages": [{
                        "stage": 1,
                        "description": desc[:200],
                        "vulnerability": {"cve_id": cve_id, "description": desc[:200]},
                        "impact": cve.get("severity", "MEDIUM"),
                    }],
                    "total_stages": 1,
                    "success_probability": 0.5,
                })
            return {
                "success": True,
                "target_software": target_software,
                "attack_depth": attack_depth,
                "attack_chains": chains,
                "total_chains": len(chains),
            }
        except Exception as exc:
            logger.error(f"Vulnerability correlator error: {exc}")
            return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Lightweight AIPayloadGenerator fallback
# ---------------------------------------------------------------------------

class _SimpleAIPayloadGenerator:
    """Minimal payload generator used when the full server class is not available."""

    _PAYLOADS: Dict[str, List[Dict[str, Any]]] = {
        "xss": [
            {"payload": "<script>alert(1)</script>", "context": "Reflected XSS", "risk_level": "HIGH"},
            {"payload": "<img src=x onerror=alert(1)>", "context": "DOM XSS", "risk_level": "HIGH"},
        ],
        "sqli": [
            {"payload": "' OR 1=1--", "context": "Boolean-based SQLi", "risk_level": "CRITICAL"},
            {"payload": "'; WAITFOR DELAY '00:00:05'--", "context": "Time-based SQLi", "risk_level": "CRITICAL"},
        ],
        "ssrf": [
            {"payload": "http://127.0.0.1:80", "context": "Internal network SSRF", "risk_level": "HIGH"},
            {"payload": "http://169.254.169.254/", "context": "Cloud metadata SSRF", "risk_level": "CRITICAL"},
        ],
        "rce": [
            {"payload": "$(whoami)", "context": "Command injection", "risk_level": "CRITICAL"},
            {"payload": "{{7*7}}", "context": "Template injection probe", "risk_level": "HIGH"},
        ],
    }

    def generate_contextual_payload(
        self, target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        attack_type = target_info.get("attack_type", "xss").lower()
        payloads = self._PAYLOADS.get(attack_type, self._PAYLOADS["xss"])
        return {
            "attack_type": attack_type,
            "payload_count": len(payloads),
            "payloads": payloads,
            "disclaimer": "For authorized security testing only.",
        }


_exploit_generator = _SimpleExploitGenerator()
_vulnerability_correlator = _SimpleVulnerabilityCorrelator()
_ai_payload_generator = _SimpleAIPayloadGenerator()

# ---------------------------------------------------------------------------
# /api/intelligence/* routes
# ---------------------------------------------------------------------------

@intelligence_bp.route("/api/intelligence/analyze-target", methods=["POST"])
def analyze_target():
    """Analyze target and create comprehensive profile using Intelligent Decision Engine."""
    try:
        data = request.get_json() or {}
        if "target" not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data["target"]
        logger.info(f"Analyzing target: {target}")

        engine = _get_decision_engine()
        if engine is None:
            return jsonify({"success": False, "error": "Decision engine not available"}), 503

        profile = engine.analyze_target(target)

        logger.info(f"Target analysis completed for {target}")
        return jsonify({
            "success": True,
            "target_profile": profile.to_dict(),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error analyzing target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/intelligence/select-tools", methods=["POST"])
def select_optimal_tools():
    """Select optimal tools based on target profile and objective."""
    try:
        data = request.get_json() or {}
        if "target" not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data["target"]
        objective = data.get("objective", "comprehensive")

        logger.info(f"Selecting optimal tools for {target} with objective: {objective}")

        engine = _get_decision_engine()
        if engine is None:
            return jsonify({"success": False, "error": "Decision engine not available"}), 503

        profile = engine.analyze_target(target)
        selected_tools = engine.select_optimal_tools(profile, objective)

        logger.info(f"Selected {len(selected_tools)} tools for {target}")
        return jsonify({
            "success": True,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "selected_tools": selected_tools,
            "tool_count": len(selected_tools),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error selecting tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/intelligence/optimize-parameters", methods=["POST"])
def optimize_tool_parameters():
    """Optimize tool parameters based on target profile and context."""
    try:
        data = request.get_json() or {}
        if "target" not in data or "tool" not in data:
            return jsonify({"error": "Target and tool are required"}), 400

        target = data["target"]
        tool = data["tool"]
        context = data.get("context", {})

        logger.info(f"Optimizing parameters for {tool} against {target}")

        engine = _get_decision_engine()
        if engine is None:
            return jsonify({"success": False, "error": "Decision engine not available"}), 503

        profile = engine.analyze_target(target)
        optimized_params = engine.optimize_parameters(tool, profile, context)

        logger.info(f"Parameters optimized for {tool}")
        return jsonify({
            "success": True,
            "target": target,
            "tool": tool,
            "context": context,
            "target_profile": profile.to_dict(),
            "optimized_parameters": optimized_params,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error optimizing parameters: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/intelligence/create-attack-chain", methods=["POST"])
def create_attack_chain():
    """Create an intelligent attack chain based on target profile."""
    try:
        data = request.get_json() or {}
        if "target" not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data["target"]
        objective = data.get("objective", "comprehensive")

        logger.info(f"Creating attack chain for {target} with objective: {objective}")

        engine = _get_decision_engine()
        if engine is None:
            return jsonify({"success": False, "error": "Decision engine not available"}), 503

        profile = engine.analyze_target(target)
        attack_chain = engine.create_attack_chain(profile, objective)

        logger.info(f"Attack chain created with {len(attack_chain.steps)} steps")
        return jsonify({
            "success": True,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "attack_chain": attack_chain.to_dict(),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating attack chain: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/intelligence/technology-detection", methods=["POST"])
def detect_technologies():
    """Detect technologies and create technology-specific testing recommendations."""
    try:
        data = request.get_json() or {}
        if "target" not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data["target"]

        logger.info(f"Detecting technologies for {target}")

        engine = _get_decision_engine()
        if engine is None:
            return jsonify({"success": False, "error": "Decision engine not available"}), 503

        profile = engine.analyze_target(target)

        # Technology-specific recommendations
        tech_recommendations: Dict[str, Any] = {}
        for tech in profile.technologies:
            tech_val = tech.value if hasattr(tech, "value") else str(tech)
            if "wordpress" in tech_val.lower():
                tech_recommendations["WordPress"] = {
                    "tools": ["wpscan", "nuclei"],
                    "focus_areas": ["plugin vulnerabilities", "theme issues", "user enumeration"],
                    "priority": "high",
                }
            elif "php" in tech_val.lower():
                tech_recommendations["PHP"] = {
                    "tools": ["nikto", "sqlmap", "ffuf"],
                    "focus_areas": ["code injection", "file inclusion", "SQL injection"],
                    "priority": "high",
                }
            elif "nodejs" in tech_val.lower() or "node" in tech_val.lower():
                tech_recommendations["Node.js"] = {
                    "tools": ["nuclei", "ffuf"],
                    "focus_areas": ["prototype pollution", "dependency vulnerabilities"],
                    "priority": "medium",
                }

        logger.info(f"Technology detection completed for {target}")
        return jsonify({
            "success": True,
            "target": target,
            "detected_technologies": [
                t.value if hasattr(t, "value") else str(t) for t in profile.technologies
            ],
            "cms_type": profile.cms_type,
            "technology_recommendations": tech_recommendations,
            "target_profile": profile.to_dict(),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in technology detection: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ---------------------------------------------------------------------------
# /api/vuln-intel/* routes
# ---------------------------------------------------------------------------

@intelligence_bp.route("/api/vuln-intel/cve-monitor", methods=["POST"])
def cve_monitor():
    """Monitor CVE databases for new vulnerabilities with AI analysis."""
    try:
        params = request.json or {}
        hours = params.get("hours", 24)
        severity_filter = params.get("severity_filter", "HIGH,CRITICAL")
        keywords = params.get("keywords", "")

        logger.info(f"Monitoring CVE feeds for last {hours} hours")

        cve_intel = _get_cve_intelligence()
        if cve_intel is None:
            return jsonify({"success": False, "error": "CVE intelligence agent not available"}), 503

        cve_results = cve_intel.fetch_latest_cves(hours, severity_filter)

        if keywords and cve_results.get("success"):
            keyword_list = [k.strip().lower() for k in keywords.split(",")]
            filtered_cves = [
                cve for cve in cve_results.get("cves", [])
                if any(kw in cve.get("description", "").lower() for kw in keyword_list)
            ]
            cve_results["cves"] = filtered_cves
            cve_results["filtered_by_keywords"] = keywords
            cve_results["total_after_filter"] = len(filtered_cves)

        exploitability_analysis = []
        for cve in cve_results.get("cves", [])[:5]:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                analysis = cve_intel.analyze_cve_exploitability(cve_id)
                if analysis.get("success"):
                    exploitability_analysis.append(analysis)

        result = {
            "success": True,
            "cve_monitoring": cve_results,
            "exploitability_analysis": exploitability_analysis,
            "timestamp": datetime.now().isoformat(),
        }

        logger.info(f"CVE monitoring completed | Found: {len(cve_results.get('cves', []))} CVEs")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in CVE monitoring: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/vuln-intel/exploit-generate", methods=["POST"])
def exploit_generate():
    """Generate exploits from vulnerability data using AI."""
    try:
        params = request.json or {}
        cve_id = params.get("cve_id", "")

        if not cve_id:
            return jsonify({"success": False, "error": "CVE ID parameter is required"}), 400

        target_info = {
            "target_os": params.get("target_os", ""),
            "target_arch": params.get("target_arch", "x64"),
            "exploit_type": params.get("exploit_type", "poc"),
            "evasion_level": params.get("evasion_level", "none"),
            "target_ip": params.get("target_ip", "192.168.1.100"),
            "target_port": params.get("target_port", 80),
            "description": params.get("target_description", f"Target for {cve_id}"),
        }

        logger.info(f"Generating exploit for {cve_id}")

        cve_intel = _get_cve_intelligence()
        if cve_intel is None:
            return jsonify({"success": False, "error": "CVE intelligence agent not available"}), 503

        cve_analysis = cve_intel.analyze_cve_exploitability(cve_id)
        if not cve_analysis.get("success"):
            return jsonify({
                "success": False,
                "error": f"Failed to analyze CVE {cve_id}: {cve_analysis.get('error', 'Unknown error')}",
            }), 400

        cve_data = {
            "cve_id": cve_id,
            "description": f"Vulnerability analysis for {cve_id}",
            "exploitability_level": cve_analysis.get("exploitability_level", "UNKNOWN"),
            "exploitability_score": cve_analysis.get("exploitability_score", 0),
        }

        exploit_result = _exploit_generator.generate_exploit_from_cve(cve_data, target_info)
        existing_exploits = cve_intel.search_existing_exploits(cve_id)

        result = {
            "success": True,
            "cve_analysis": cve_analysis,
            "exploit_generation": exploit_result,
            "existing_exploits": existing_exploits,
            "target_info": target_info,
            "timestamp": datetime.now().isoformat(),
        }

        logger.info(f"Exploit generation completed for {cve_id}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in exploit generation: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/vuln-intel/attack-chains", methods=["POST"])
def discover_attack_chains():
    """Discover multi-stage attack possibilities."""
    try:
        params = request.json or {}
        target_software = params.get("target_software", "")
        attack_depth = params.get("attack_depth", 3)

        if not target_software:
            return jsonify({"success": False, "error": "Target software parameter is required"}), 400

        logger.info(f"Discovering attack chains for {target_software} | Depth: {attack_depth}")

        chain_results = _vulnerability_correlator.find_attack_chains(target_software, attack_depth)

        if chain_results.get("success") and chain_results.get("attack_chains"):
            cve_intel = _get_cve_intelligence()
            enhanced_chains = []
            for chain in chain_results["attack_chains"][:2]:
                enhanced_chain = chain.copy()
                enhanced_stages = []
                for stage in chain.get("stages", []):
                    enhanced_stage = stage.copy()
                    vuln = stage.get("vulnerability", {})
                    cve_id = vuln.get("cve_id", "")
                    if cve_id and cve_intel:
                        try:
                            cve_data = {"cve_id": cve_id, "description": vuln.get("description", "")}
                            t_info = {"target_os": "linux", "target_arch": "x64", "evasion_level": "basic"}
                            exploit_result = _exploit_generator.generate_exploit_from_cve(cve_data, t_info)
                            enhanced_stage["exploit_available"] = exploit_result.get("success", False)
                        except Exception:
                            enhanced_stage["exploit_available"] = False
                    enhanced_stages.append(enhanced_stage)
                enhanced_chain["stages"] = enhanced_stages
                enhanced_chains.append(enhanced_chain)
            chain_results["enhanced_chains"] = enhanced_chains

        result = {
            "success": True,
            "attack_chain_discovery": chain_results,
            "parameters": {
                "target_software": target_software,
                "attack_depth": attack_depth,
            },
            "timestamp": datetime.now().isoformat(),
        }

        logger.info(f"Attack chain discovery completed | Found: {len(chain_results.get('attack_chains', []))} chains")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in attack chain discovery: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/vuln-intel/threat-feeds", methods=["POST"])
def threat_intelligence_feeds():
    """Aggregate and correlate threat intelligence from multiple sources."""
    try:
        params = request.json or {}
        indicators = params.get("indicators", [])
        timeframe = params.get("timeframe", "30d")
        sources = params.get("sources", "all")

        if isinstance(indicators, str):
            indicators = [i.strip() for i in indicators.split(",")]

        if not indicators:
            return jsonify({"success": False, "error": "Indicators parameter is required"}), 400

        logger.info(f"Correlating threat intelligence for {len(indicators)} indicators")

        correlation_results: Dict[str, Any] = {
            "indicators_analyzed": indicators,
            "timeframe": timeframe,
            "sources": sources,
            "correlations": [],
            "threat_score": 0,
            "recommendations": [],
        }

        cve_intel = _get_cve_intelligence()

        cve_indicators = [i for i in indicators if i.startswith("CVE-")]
        ip_indicators = [i for i in indicators if i.replace(".", "").isdigit()]
        hash_indicators = [
            i for i in indicators
            if len(i) in [32, 40, 64] and all(c in "0123456789abcdef" for c in i.lower())
        ]

        for cve_id in cve_indicators:
            if cve_intel:
                try:
                    cve_analysis = cve_intel.analyze_cve_exploitability(cve_id)
                    if cve_analysis.get("success"):
                        correlation_results["correlations"].append({
                            "indicator": cve_id,
                            "type": "cve",
                            "analysis": cve_analysis,
                            "threat_level": cve_analysis.get("exploitability_level", "UNKNOWN"),
                        })
                        correlation_results["threat_score"] += min(
                            cve_analysis.get("exploitability_score", 0), 100
                        )
                    exploits = cve_intel.search_existing_exploits(cve_id)
                    if exploits.get("success") and exploits.get("total_exploits", 0) > 0:
                        correlation_results["correlations"].append({
                            "indicator": cve_id,
                            "type": "exploit_availability",
                            "exploits_found": exploits.get("total_exploits", 0),
                            "threat_level": "HIGH",
                        })
                        correlation_results["threat_score"] += 25
                except Exception as ex:
                    logger.warning(f"Error analyzing CVE {cve_id}: {str(ex)}")

        for ip in ip_indicators:
            correlation_results["correlations"].append({
                "indicator": ip,
                "type": "ip_reputation",
                "analysis": {"reputation": "unknown", "geolocation": "unknown", "associated_threats": []},
                "threat_level": "MEDIUM",
            })

        for hash_val in hash_indicators:
            correlation_results["correlations"].append({
                "indicator": hash_val,
                "type": "file_hash",
                "analysis": {
                    "hash_type": f"hash{len(hash_val)}",
                    "malware_family": "unknown",
                    "detection_rate": "unknown",
                },
                "threat_level": "MEDIUM",
            })

        total_indicators = len(indicators)
        if total_indicators > 0:
            correlation_results["threat_score"] = min(
                correlation_results["threat_score"] / total_indicators, 100
            )
            score = correlation_results["threat_score"]
            if score >= 75:
                correlation_results["recommendations"] = [
                    "Immediate threat response required",
                    "Block identified indicators",
                    "Enhance monitoring for related IOCs",
                    "Implement emergency patches for identified CVEs",
                ]
            elif score >= 50:
                correlation_results["recommendations"] = [
                    "Elevated threat level detected",
                    "Increase monitoring for identified indicators",
                    "Plan patching for identified vulnerabilities",
                    "Review security controls",
                ]
            else:
                correlation_results["recommendations"] = [
                    "Low to medium threat level",
                    "Continue standard monitoring",
                    "Plan routine patching",
                    "Consider additional threat intelligence sources",
                ]

        result = {
            "success": True,
            "threat_intelligence": correlation_results,
            "timestamp": datetime.now().isoformat(),
        }

        logger.info(f"Threat intelligence correlation completed | Threat Score: {correlation_results['threat_score']:.1f}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in threat intelligence: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


# ---------------------------------------------------------------------------
# /api/ai/* routes
# ---------------------------------------------------------------------------

@intelligence_bp.route("/api/ai/generate_payload", methods=["POST"])
def ai_generate_payload():
    """Generate AI-powered contextual payloads for security testing."""
    try:
        params = request.json or {}
        target_info = {
            "attack_type": params.get("attack_type", "xss"),
            "complexity": params.get("complexity", "basic"),
            "technology": params.get("technology", ""),
            "url": params.get("url", ""),
        }

        logger.info(f"Generating AI payloads for {target_info['attack_type']} attack")
        result = _ai_payload_generator.generate_contextual_payload(target_info)

        logger.info(f"Generated {result['payload_count']} contextual payloads")
        return jsonify({
            "success": True,
            "ai_payload_generation": result,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in AI payload generation: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


def _is_safe_url(url: str) -> bool:
    """Resolve URL hostname and reject private/loopback/link-local/metadata IPs.

    Accepted risk: DNS rebinding (resolve-then-request TOCTOU) is not mitigated.
    This is a local pentesting tool behind API key auth, not a public web app.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        addrs = socket.getaddrinfo(hostname, parsed.port or 80)
    except socket.gaierror:
        return False
    for family, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
        # Block cloud metadata
        if str(ip) == "169.254.169.254":
            return False
    return True


_WAF_HEADERS = {"cf-ray", "x-waf", "x-sucuri-id", "x-cdn"}
_WAF_SERVERS = {"cloudflare", "akamai", "imperva", "sucuri"}


@intelligence_bp.route("/api/ai/test_payload", methods=["POST"])
def ai_test_payload():
    """Test generated payload against target with SSRF-safe real HTTP request."""
    try:
        params = request.json or {}
        payload = params.get("payload", "")
        target_url = params.get("target_url", "")
        method = params.get("method", "GET").upper()

        if not payload or not target_url:
            return jsonify({"success": False, "error": "Payload and target_url are required"}), 400

        # SSRF guard: block private/loopback/link-local/metadata IPs
        if not _is_safe_url(target_url):
            return jsonify({"success": False, "error": "Blocked: target resolves to private/reserved IP"}), 400

        logger.info(f"Testing payload against {target_url} via {method}")

        # Send the real request
        try:
            if method == "GET":
                resp = requests_lib.request(method, target_url, params={"q": payload},
                                            timeout=10, allow_redirects=False)
            else:
                resp = requests_lib.request(method, target_url, data={"payload": payload},
                                            timeout=10, allow_redirects=False)
        except requests_lib.RequestException as exc:
            return jsonify({"success": False, "error": f"Request failed: {str(exc)}"}), 502

        body = resp.text[:2048]
        reflection_detected = payload in body

        # WAF detection
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        waf_detected = bool(_WAF_HEADERS & set(resp_headers.keys()))
        server = resp_headers.get("server", "").lower()
        if any(w in server for w in _WAF_SERVERS):
            waf_detected = True

        return jsonify({
            "success": True,
            "test_result": {
                "status_code": resp.status_code,
                "reflection_detected": reflection_detected,
                "waf_detected": waf_detected,
                "response_size": len(resp.text),
                "body_preview": body[:512],
            },
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in AI payload testing: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500


@intelligence_bp.route("/api/ai/advanced-payload-generation", methods=["POST"])
def advanced_payload_generation():
    """Generate advanced payloads with AI-powered evasion techniques."""
    try:
        params = request.json or {}
        attack_type = params.get("attack_type", "")
        target_context = params.get("target_context", "")
        evasion_level = params.get("evasion_level", "standard")
        custom_constraints = params.get("custom_constraints", "")

        if not attack_type:
            return jsonify({"success": False, "error": "Attack type parameter is required"}), 400

        logger.info(f"Generating advanced {attack_type} payload with {evasion_level} evasion")

        target_info = {
            "attack_type": attack_type,
            "complexity": "advanced",
            "technology": target_context,
            "evasion_level": evasion_level,
            "constraints": custom_constraints,
        }

        base_result = _ai_payload_generator.generate_contextual_payload(target_info)
        advanced_payloads = []

        for payload_info in base_result.get("payloads", [])[:10]:
            enhanced = {
                "payload": payload_info["payload"],
                "original_context": payload_info["context"],
                "risk_level": payload_info["risk_level"],
                "evasion_techniques": [],
                "deployment_methods": [
                    "Direct injection",
                    "Parameter pollution",
                    "Header injection",
                    "Cookie manipulation",
                    "Fragment-based delivery",
                ],
            }
            if evasion_level in ["advanced", "nation-state"]:
                enhanced["evasion_techniques"].extend([
                    {
                        "technique": "Double URL Encoding",
                        "payload": payload_info["payload"].replace("%", "%25").replace(" ", "%2520"),
                    },
                    {
                        "technique": "Case Variation",
                        "payload": "".join(
                            c.upper() if i % 2 else c.lower()
                            for i, c in enumerate(payload_info["payload"])
                        ),
                    },
                ])
            advanced_payloads.append(enhanced)

        deployment_guide = {
            "pre_deployment": [
                "Reconnaissance of target environment",
                "Identification of input validation mechanisms",
                "Analysis of security controls (WAF, IDS, etc.)",
                "Selection of appropriate evasion techniques",
            ],
            "deployment": [
                "Start with least detectable payloads",
                "Monitor for defensive responses",
                "Escalate evasion techniques as needed",
                "Document successful techniques for future use",
            ],
            "post_deployment": [
                "Monitor for payload execution",
                "Clean up traces if necessary",
                "Document findings",
                "Report vulnerabilities responsibly",
            ],
        }

        result = {
            "success": True,
            "advanced_payload_generation": {
                "attack_type": attack_type,
                "evasion_level": evasion_level,
                "target_context": target_context,
                "payload_count": len(advanced_payloads),
                "advanced_payloads": advanced_payloads,
                "deployment_guide": deployment_guide,
                "custom_constraints_applied": custom_constraints if custom_constraints else "none",
            },
            "disclaimer": "These payloads are for authorized security testing only. Ensure proper authorization before use.",
            "timestamp": datetime.now().isoformat(),
        }

        logger.info(f"Advanced payload generation completed | Generated: {len(advanced_payloads)} payloads")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in advanced payload generation: {str(e)}")
        return jsonify({"success": False, "error": f"Server error: {str(e)}"}), 500
