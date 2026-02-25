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

    from core.routes.network import network_bp
    flask_app.register_blueprint(network_bp)

    from core.routes.web import web_bp
    flask_app.register_blueprint(web_bp)

    from core.routes.cloud import cloud_bp
    flask_app.register_blueprint(cloud_bp)

    from core.routes.binary import binary_bp
    flask_app.register_blueprint(binary_bp)

    from core.routes.ctf import ctf_bp
    flask_app.register_blueprint(ctf_bp)

    from core.routes.bugbounty import bugbounty_bp
    flask_app.register_blueprint(bugbounty_bp)

    from core.routes.intelligence import intelligence_bp
    flask_app.register_blueprint(intelligence_bp)

    from core.routes.mobile import mobile_bp
    flask_app.register_blueprint(mobile_bp)

    from core.routes.api_security import api_security_bp
    flask_app.register_blueprint(api_security_bp)

    from core.routes.wireless import wireless_bp
    flask_app.register_blueprint(wireless_bp)

    from core.routes.osint import osint_bp
    flask_app.register_blueprint(osint_bp)

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
