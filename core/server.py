#!/usr/bin/env python3
"""
HexStrike AI - Flask Server Core

Flask application initialization and configuration.
Routes remain in hexstrike_server.py for Phase 1.
"""

from flask import Flask
from core.constants import API_PORT, API_HOST

# Initialize Flask application
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

def create_app():
    """Factory function to create Flask app"""
    from core.routes.system import system_bp
    app.register_blueprint(system_bp)
    return app

def get_server_info():
    """Get server configuration info"""
    return {
        'host': API_HOST,
        'port': API_PORT,
        'debug': False
    }
