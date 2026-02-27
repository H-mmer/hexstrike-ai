"""API security tool routes Blueprint."""
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
api_security_bp = Blueprint('api_security', __name__)


# ---------------------------------------------------------------------------
# API discovery
# ---------------------------------------------------------------------------

@api_security_bp.route('/api/tools/api/discover', methods=['POST'])
def api_discover():
    """API endpoint discovery using kiterunner, swagger-scanner, and graphql-cop."""
    params = request.json or {}
    base_url = params.get('base_url', '')
    if not base_url:
        return jsonify({"success": False, "error": "base_url is required"}), 400
    try:
        from tools.api.api_discovery import kiterunner_scan, swagger_scanner, graphql_cop_scan
    except ImportError:
        return jsonify({"success": False, "error": "api_discovery not available"}), 503
    schema_url = params.get('schema_url', '')
    try:
        results = {
            'kiterunner': kiterunner_scan(base_url),
            'swagger': swagger_scanner(schema_url or base_url),
            'graphql': graphql_cop_scan(base_url),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"API discovery error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# API fuzzing
# ---------------------------------------------------------------------------

@api_security_bp.route('/api/tools/api/fuzz', methods=['POST'])
def api_fuzz():
    """API endpoint fuzzing using rest-attacker."""
    params = request.json or {}
    base_url = params.get('base_url', '')
    if not base_url:
        return jsonify({"success": False, "error": "base_url is required"}), 400
    try:
        from tools.api.api_fuzzing import rest_attacker
    except ImportError:
        return jsonify({"success": False, "error": "api_fuzzing not available"}), 503
    wordlist = params.get('wordlist', '')
    try:
        result = rest_attacker(base_url, payloads=wordlist if wordlist else None)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"API fuzzing error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# API authentication testing
# ---------------------------------------------------------------------------

@api_security_bp.route('/api/tools/api/auth-test', methods=['POST'])
def api_auth_test():
    """API authentication vulnerability testing -- JWT, OAuth, API keys."""
    params = request.json or {}
    base_url = params.get('base_url', '')
    if not base_url:
        return jsonify({"success": False, "error": "base_url is required"}), 400
    try:
        from tools.api.api_auth import jwt_hack, oauth_scanner, api_key_brute
    except ImportError:
        return jsonify({"success": False, "error": "api_auth not available"}), 503
    jwt_token = params.get('jwt_token', '')
    try:
        results = {
            'jwt': jwt_hack(jwt_token) if jwt_token else {"skipped": "no jwt_token provided"},
            'oauth': oauth_scanner(base_url),
            'api_keys': api_key_brute(base_url),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"API auth test error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# API monitoring
# ---------------------------------------------------------------------------

@api_security_bp.route('/api/tools/api/monitoring', methods=['POST'])
def api_monitoring():
    """API security monitoring and rate-limit testing."""
    params = request.json or {}
    base_url = params.get('base_url', '')
    if not base_url:
        return jsonify({"success": False, "error": "base_url is required"}), 400
    try:
        from tools.api.api_monitoring import rate_limit_tester
    except ImportError:
        return jsonify({"success": False, "error": "api_monitoring not available"}), 503
    try:
        result = rate_limit_tester(base_url)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"API monitoring error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
