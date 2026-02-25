"""API security tool routes Blueprint."""
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
api_security_bp = Blueprint('api_security', __name__)

# ---------------------------------------------------------------------------
# Optional tool imports — api_discovery
# ---------------------------------------------------------------------------

try:
    from tools.api.api_discovery import kiterunner_scan, swagger_scanner, graphql_cop_scan
    _DISCOVERY_AVAILABLE = True
except ImportError:
    _DISCOVERY_AVAILABLE = False

    def kiterunner_scan(target, **kwargs):
        return {"success": False, "error": "api_discovery not available"}

    def swagger_scanner(target, **kwargs):
        return {"success": False, "error": "api_discovery not available"}

    def graphql_cop_scan(target, **kwargs):
        return {"success": False, "error": "api_discovery not available"}


# ---------------------------------------------------------------------------
# Optional tool imports — api_fuzzing
# ---------------------------------------------------------------------------

try:
    from tools.api.api_fuzzing import rest_attacker
    _FUZZING_AVAILABLE = True
except ImportError:
    _FUZZING_AVAILABLE = False

    def rest_attacker(target, **kwargs):
        return {"success": False, "error": "api_fuzzing not available"}


# ---------------------------------------------------------------------------
# Optional tool imports — api_auth
# ---------------------------------------------------------------------------

try:
    from tools.api.api_auth import jwt_hack, oauth_scanner, api_key_brute
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

    def jwt_hack(token, **kwargs):
        return {"success": False, "error": "api_auth not available"}

    def oauth_scanner(auth_endpoint, **kwargs):
        return {"success": False, "error": "api_auth not available"}

    def api_key_brute(target, **kwargs):
        return {"success": False, "error": "api_auth not available"}


# ---------------------------------------------------------------------------
# Optional tool imports — api_monitoring
# ---------------------------------------------------------------------------

try:
    from tools.api.api_monitoring import rate_limit_tester
    _MONITORING_AVAILABLE = True
except ImportError:
    _MONITORING_AVAILABLE = False

    def rate_limit_tester(target, **kwargs):
        return {"success": False, "error": "api_monitoring not available"}


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
    """API authentication vulnerability testing — JWT, OAuth, API keys."""
    params = request.json or {}
    base_url = params.get('base_url', '')
    if not base_url:
        return jsonify({"success": False, "error": "base_url is required"}), 400
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
        result = rate_limit_tester(base_url)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"API monitoring error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
