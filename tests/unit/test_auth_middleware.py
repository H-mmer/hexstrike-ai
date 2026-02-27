# tests/unit/test_auth_middleware.py
"""Tests for API key authentication middleware."""
import os
import pytest
from core.server import create_app


@pytest.fixture
def app_with_auth(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_API_KEY", "test-secret-key-123")
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def app_no_auth(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)
    app = create_app()
    app.config["TESTING"] = True
    return app


def test_request_without_key_returns_401(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/api/telemetry")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error"] == "Missing or invalid API key"


def test_request_with_correct_key_returns_200(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/api/telemetry", headers={"X-API-Key": "test-secret-key-123"})
        assert resp.status_code == 200


def test_request_with_wrong_key_returns_401(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/api/telemetry", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401


def test_health_endpoint_bypasses_auth(app_with_auth):
    with app_with_auth.test_client() as c:
        resp = c.get("/health")
        assert resp.status_code == 200


def test_no_api_key_env_allows_all_requests(app_no_auth):
    """Dev mode: if HEXSTRIKE_API_KEY is not set, all requests pass through."""
    with app_no_auth.test_client() as c:
        resp = c.get("/api/telemetry")
        assert resp.status_code == 200
