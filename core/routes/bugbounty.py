"""Bug bounty workflow routes Blueprint."""
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
bugbounty_bp = Blueprint('bugbounty', __name__)

# ---------------------------------------------------------------------------
# Optional agent imports
# ---------------------------------------------------------------------------

try:
    from agents.bugbounty_manager import BugBountyWorkflowManager
    _BUGBOUNTY_AVAILABLE = True
except ImportError:
    _BUGBOUNTY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BugBountyTarget:
    """Bug bounty target information."""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"   # web, api, mobile, iot
    priority_vulns: List[str] = field(
        default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"]
    )
    bounty_range: str = "unknown"


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

_bugbounty_manager = None


def _get_bugbounty_manager():
    global _bugbounty_manager
    if _bugbounty_manager is None and _BUGBOUNTY_AVAILABLE:
        _bugbounty_manager = BugBountyWorkflowManager()
    return _bugbounty_manager


# ---------------------------------------------------------------------------
# Lightweight FileUploadTestingFramework (inline, no server dependency)
# ---------------------------------------------------------------------------

class _FileUploadTestingFramework:
    def create_upload_testing_workflow(self, target_url: str) -> Dict[str, Any]:
        return {
            "target_url": target_url,
            "test_phases": [
                {
                    "phase": "extension_bypass",
                    "tests": [
                        "Double extension (file.php.jpg)",
                        "Null byte injection (file.php%00.jpg)",
                        "Case variation (file.pHp)",
                    ],
                },
                {
                    "phase": "content_type_bypass",
                    "tests": [
                        "Change Content-Type to image/jpeg",
                        "Polyglot files (valid image + PHP code)",
                        "Magic bytes manipulation",
                    ],
                },
                {
                    "phase": "directory_traversal",
                    "tests": [
                        "Path traversal in filename",
                        "Directory traversal with encoding",
                        "Upload to arbitrary location",
                    ],
                },
                {
                    "phase": "file_execution",
                    "tests": [
                        "Direct file access after upload",
                        "Include uploaded file via LFI",
                        "Execute via web server misconfiguration",
                    ],
                },
            ],
            "estimated_time": 120,
            "tools_count": 3,
            "risk_level": "HIGH",
        }

    def generate_test_files(self) -> List[Dict[str, str]]:
        return [
            {
                "filename": "test_shell.php.jpg",
                "content_type": "image/jpeg",
                "purpose": "Double extension bypass",
            },
            {
                "filename": "shell.php%00.jpg",
                "content_type": "image/jpeg",
                "purpose": "Null byte injection",
            },
            {
                "filename": "polyglot.php",
                "content_type": "image/gif",
                "content": "GIF89a; <?php system($_GET['cmd']); ?>",
                "purpose": "Polyglot file bypass",
            },
            {
                "filename": "htaccess",
                "content_type": "text/plain",
                "content": "AddType application/x-httpd-php .jpg",
                "purpose": ".htaccess upload for PHP execution",
            },
        ]


_fileupload_framework = _FileUploadTestingFramework()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bugbounty_bp.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
def create_reconnaissance_workflow():
    """Create comprehensive reconnaissance workflow for bug bounty hunting."""
    try:
        data = request.get_json() or {}
        if "domain" not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data["domain"]
        scope = data.get("scope", [])
        out_of_scope = data.get("out_of_scope", [])
        program_type = data.get("program_type", "web")

        logger.info(f"Creating reconnaissance workflow for {domain}")

        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            out_of_scope=out_of_scope,
            program_type=program_type,
        )

        mgr = _get_bugbounty_manager()
        if mgr is None:
            return jsonify({"success": False, "error": "BugBounty agent not available"}), 503

        workflow = mgr.create_reconnaissance_workflow(target)

        logger.info(f"Reconnaissance workflow created for {domain}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating reconnaissance workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bugbounty_bp.route("/api/bugbounty/vulnerability-hunting-workflow", methods=["POST"])
def create_vulnerability_hunting_workflow():
    """Create vulnerability hunting workflow prioritized by impact."""
    try:
        data = request.get_json() or {}
        if "domain" not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data["domain"]
        priority_vulns = data.get("priority_vulns", ["rce", "sqli", "xss", "idor", "ssrf"])
        bounty_range = data.get("bounty_range", "unknown")

        logger.info(f"Creating vulnerability hunting workflow for {domain}")

        target = BugBountyTarget(
            domain=domain,
            priority_vulns=priority_vulns,
            bounty_range=bounty_range,
        )

        mgr = _get_bugbounty_manager()
        if mgr is None:
            return jsonify({"success": False, "error": "BugBounty agent not available"}), 503

        workflow = mgr.create_vulnerability_hunting_workflow(target)

        logger.info(f"Vulnerability hunting workflow created for {domain}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating vulnerability hunting workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bugbounty_bp.route("/api/bugbounty/business-logic-workflow", methods=["POST"])
def create_business_logic_workflow():
    """Create business logic testing workflow."""
    try:
        data = request.get_json() or {}
        if "domain" not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data["domain"]
        program_type = data.get("program_type", "web")

        logger.info(f"Creating business logic testing workflow for {domain}")

        target = BugBountyTarget(domain=domain, program_type=program_type)

        mgr = _get_bugbounty_manager()
        if mgr is None:
            return jsonify({"success": False, "error": "BugBounty agent not available"}), 503

        workflow = mgr.create_business_logic_testing_workflow(target)

        logger.info(f"Business logic testing workflow created for {domain}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating business logic workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bugbounty_bp.route("/api/bugbounty/osint-workflow", methods=["POST"])
def create_osint_workflow():
    """Create OSINT gathering workflow."""
    try:
        data = request.get_json() or {}
        if "domain" not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data["domain"]

        logger.info(f"Creating OSINT workflow for {domain}")

        target = BugBountyTarget(domain=domain)

        mgr = _get_bugbounty_manager()
        if mgr is None:
            return jsonify({"success": False, "error": "BugBounty agent not available"}), 503

        workflow = mgr.create_osint_workflow(target)

        logger.info(f"OSINT workflow created for {domain}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating OSINT workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bugbounty_bp.route("/api/bugbounty/file-upload-testing", methods=["POST"])
def create_file_upload_testing():
    """Create file upload vulnerability testing workflow."""
    try:
        data = request.get_json() or {}
        if "target_url" not in data:
            return jsonify({"error": "Target URL is required"}), 400

        target_url = data["target_url"]

        logger.info(f"Creating file upload testing workflow for {target_url}")

        workflow = _fileupload_framework.create_upload_testing_workflow(target_url)
        test_files = _fileupload_framework.generate_test_files()
        workflow["test_files"] = test_files

        logger.info(f"File upload testing workflow created for {target_url}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating file upload testing workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bugbounty_bp.route("/api/bugbounty/comprehensive-assessment", methods=["POST"])
def create_comprehensive_bugbounty_assessment():
    """Create comprehensive bug bounty assessment combining all workflows."""
    try:
        data = request.get_json() or {}
        if "domain" not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data["domain"]
        scope = data.get("scope", [])
        priority_vulns = data.get("priority_vulns", ["rce", "sqli", "xss", "idor", "ssrf"])
        include_osint = data.get("include_osint", True)
        include_business_logic = data.get("include_business_logic", True)

        logger.info(f"Creating comprehensive bug bounty assessment for {domain}")

        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            priority_vulns=priority_vulns,
        )

        mgr = _get_bugbounty_manager()
        if mgr is None:
            return jsonify({"success": False, "error": "BugBounty agent not available"}), 503

        assessment: Dict[str, Any] = {
            "target": domain,
            "reconnaissance": mgr.create_reconnaissance_workflow(target),
            "vulnerability_hunting": mgr.create_vulnerability_hunting_workflow(target),
        }

        if include_osint:
            assessment["osint"] = mgr.create_osint_workflow(target)

        if include_business_logic:
            assessment["business_logic"] = mgr.create_business_logic_testing_workflow(target)

        total_time = sum(
            wf.get("estimated_time", 0)
            for wf in assessment.values()
            if isinstance(wf, dict)
        )
        total_tools = sum(
            wf.get("tools_count", 0)
            for wf in assessment.values()
            if isinstance(wf, dict)
        )

        assessment["summary"] = {
            "total_estimated_time": total_time,
            "total_tools": total_tools,
            "workflow_count": len([k for k in assessment.keys() if k != "target"]),
            "priority_score": assessment["vulnerability_hunting"].get("priority_score", 0),
        }

        logger.info(f"Comprehensive bug bounty assessment created for {domain}")
        return jsonify({
            "success": True,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating comprehensive assessment: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
