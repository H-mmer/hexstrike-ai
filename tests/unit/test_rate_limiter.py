# tests/unit/test_rate_limiter.py
"""Tests for rate limiting middleware."""
import pytest
from core.server import create_app


@pytest.fixture
def app(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_API_KEY", raising=False)  # isolate from auth
    a = create_app()
    a.config["TESTING"] = True
    return a


def test_rate_limit_returns_429_when_exceeded(app):
    with app.test_client() as c:
        # /api/command has 10/minute limit
        for _ in range(11):
            resp = c.post("/api/command", json={"command": "echo hi"})
        assert resp.status_code == 429


def test_health_not_rate_limited(app):
    with app.test_client() as c:
        for _ in range(200):
            resp = c.get("/health")
        assert resp.status_code == 200
