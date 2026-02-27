# tests/unit/test_proxy_provider_v2.py
"""Tests for round-robin proxy provider."""
from agents.proxy_provider import ProxyProvider


def test_empty_proxy_list():
    p = ProxyProvider()
    assert p.get_proxy() is None


def test_round_robin_rotation():
    proxies = [
        {"http": "http://proxy1:8080", "https": "http://proxy1:8080"},
        {"http": "http://proxy2:8080", "https": "http://proxy2:8080"},
    ]
    p = ProxyProvider(proxies=proxies)
    assert p.get_proxy() == proxies[0]
    p.rotate()
    assert p.get_proxy() == proxies[1]
    p.rotate()
    assert p.get_proxy() == proxies[0]  # wraps around


def test_from_env(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_PROXIES", "http://p1:8080,http://p2:8080")
    p = ProxyProvider.from_env()
    assert p.get_proxy() is not None
    assert "p1" in p.get_proxy()["http"]


def test_from_env_empty(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_PROXIES", raising=False)
    p = ProxyProvider.from_env()
    assert p.get_proxy() is None
