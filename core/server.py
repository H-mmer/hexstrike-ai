#!/usr/bin/env python3
"""
HexStrike AI - Flask Server Core

Flask application initialization and configuration.
Routes remain in hexstrike_server.py for Phase 1.
"""

from flask import Flask
from core.constants import API_PORT, API_HOST


def create_app():
    """Application factory — returns a fresh Flask instance each call."""
    flask_app = Flask(__name__)
    flask_app.config['JSON_SORT_KEYS'] = False

    from core.routes.system import system_bp
    flask_app.register_blueprint(system_bp)

    return flask_app


# Module-level singleton for the production server entry point
app = create_app()

def get_server_info():
    """Get server configuration info"""
    return {
        'host': API_HOST,
        'port': API_PORT,
        'debug': False
    }
