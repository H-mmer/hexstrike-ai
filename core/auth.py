# core/auth.py
"""API key authentication middleware."""
import logging
import os

from flask import request, jsonify

logger = logging.getLogger(__name__)

# Endpoints that bypass auth (exact match)
_PUBLIC_ENDPOINTS = frozenset({"/health"})


def register_auth(app):
    """Register @before_request API key check on *app*.

    If HEXSTRIKE_API_KEY is not set, auth is disabled (dev mode).
    """
    api_key = os.environ.get("HEXSTRIKE_API_KEY")

    if not api_key:
        logger.warning("HEXSTRIKE_API_KEY not set — auth disabled (dev mode)")
        return

    @app.before_request
    def _check_api_key():
        if request.path in _PUBLIC_ENDPOINTS:
            return None
        supplied = request.headers.get("X-API-Key", "")
        if supplied != api_key:
            return jsonify({"success": False, "error": "Missing or invalid API key"}), 401
