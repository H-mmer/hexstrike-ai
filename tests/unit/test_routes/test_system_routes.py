# tests/unit/test_routes/test_system_routes.py
import pytest
from flask import Flask
from core.routes.system import system_bp

def test_system_blueprint_registers():
    app = Flask(__name__)
    app.register_blueprint(system_bp)
    assert 'system' in app.blueprints
