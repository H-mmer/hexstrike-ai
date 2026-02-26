# core/routes/browser.py
"""Stealth browser agent routes Blueprint."""
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
browser_bp = Blueprint('browser', __name__)


# ---------------------------------------------------------------------------
# Navigate
# ---------------------------------------------------------------------------

@browser_bp.route('/api/browser/navigate', methods=['POST'])
def browser_navigate():
    """Navigate to a URL using StealthBrowserAgent."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        preset = params.get('preset', 'standard')
        agent = StealthBrowserAgent(preset=preset)
        result = agent.navigate_stealth(url, wait_seconds=params.get('wait', 2.0))
        agent.close()
        return jsonify(result)
    except Exception as exc:
        logger.error("browser_navigate error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------

@browser_bp.route('/api/browser/screenshot', methods=['POST'])
def browser_screenshot():
    """Navigate to a URL and return a base64-encoded screenshot."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        agent = StealthBrowserAgent(preset=params.get('preset', 'standard'))
        agent.setup_browser()
        agent.navigate_stealth(url)
        result = agent.screenshot_stealth()
        agent.close()
        return jsonify(result)
    except Exception as exc:
        logger.error("browser_screenshot error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# DOM extraction
# ---------------------------------------------------------------------------

@browser_bp.route('/api/browser/dom', methods=['POST'])
def browser_dom():
    """Extract DOM structure from a URL."""
    params = request.json or {}
    url = params.get('url', '')
    if not url:
        return jsonify({"success": False, "error": "url is required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        agent = StealthBrowserAgent(preset=params.get('preset', 'standard'))
        agent.navigate_stealth(url)
        result = agent.extract_dom_stealth()
        agent.close()
        return jsonify(result)
    except Exception as exc:
        logger.error("browser_dom error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Form fill
# ---------------------------------------------------------------------------

@browser_bp.route('/api/browser/form-fill', methods=['POST'])
def browser_form_fill():
    """Fill a form field with human-like typing."""
    params = request.json or {}
    url = params.get('url', '')
    selector = params.get('selector', '')
    value = params.get('value', '')
    if not url or not selector:
        return jsonify({"success": False, "error": "url and selector are required"}), 400
    try:
        from agents.stealth_browser_agent import StealthBrowserAgent
        agent = StealthBrowserAgent(preset=params.get('preset', 'standard'))
        agent.navigate_stealth(url)
        result = agent.form_fill_stealth(selector, value)
        agent.close()
        return jsonify(result)
    except Exception as exc:
        logger.error("browser_form_fill error: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500
