"""Mobile security tool routes Blueprint."""
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
mobile_bp = Blueprint('mobile', __name__)


# ---------------------------------------------------------------------------
# APK analysis
# ---------------------------------------------------------------------------

@mobile_bp.route('/api/tools/mobile/apk-analyze', methods=['POST'])
def mobile_apk_analyze():
    """APK analysis using apktool, jadx, and androguard."""
    params = request.json or {}
    apk_path = params.get('apk_path', '')
    if not apk_path:
        return jsonify({"success": False, "error": "apk_path is required"}), 400
    try:
        from tools.mobile.apk_tools import apktool_decompile, jadx_decompile, androguard_analyze
    except ImportError:
        return jsonify({"success": False, "error": "apk_tools not available"}), 503
    try:
        results = {
            'apktool': apktool_decompile(apk_path),
            'jadx': jadx_decompile(apk_path),
            'androguard': androguard_analyze(apk_path),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"APK analysis error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# iOS analysis
# ---------------------------------------------------------------------------

@mobile_bp.route('/api/tools/mobile/ios-analyze', methods=['POST'])
def mobile_ios_analyze():
    """iOS IPA analysis using ipa-analyzer and class-dump."""
    params = request.json or {}
    ipa_path = params.get('ipa_path', '')
    if not ipa_path:
        return jsonify({"success": False, "error": "ipa_path is required"}), 400
    try:
        from tools.mobile.ios_tools import ipa_analyzer, class_dump
    except ImportError:
        return jsonify({"success": False, "error": "ios_tools not available"}), 503
    try:
        results = {
            'ipa_analyzer': ipa_analyzer(ipa_path),
            'class_dump': class_dump(ipa_path),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"iOS analysis error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# Drozer (Android attack surface assessment)
# ---------------------------------------------------------------------------

@mobile_bp.route('/api/tools/mobile/drozer', methods=['POST'])
def mobile_drozer():
    """Android app security audit using Drozer."""
    params = request.json or {}
    package = params.get('package', '')
    if not package:
        return jsonify({"success": False, "error": "package is required"}), 400
    try:
        from tools.mobile.mobile_exploit import drozer_scan
    except ImportError:
        return jsonify({"success": False, "error": "mobile_exploit not available"}), 503
    try:
        return jsonify({"success": True, "result": drozer_scan(package)})
    except Exception as e:
        logger.error(f"Drozer error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# Mobile traffic interception (mitmproxy)
# ---------------------------------------------------------------------------

@mobile_bp.route('/api/tools/mobile/mitm', methods=['POST'])
def mobile_mitm():
    """Mobile traffic interception using mitmproxy."""
    params = request.json or {}
    listen_port = params.get('listen_port', 8080)
    try:
        from tools.mobile.mobile_network import setup_mitmproxy_mobile
    except ImportError:
        return jsonify({"success": False, "error": "mobile_network not available"}), 503
    try:
        return jsonify({"success": True, "result": setup_mitmproxy_mobile(listen_port=listen_port)})
    except Exception as e:
        logger.error(f"Mobile MITM error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
