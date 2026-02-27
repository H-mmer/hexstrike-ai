# tests/unit/test_browser_routes.py
"""Tests for core/routes/browser.py -- stealth browser agent endpoints."""
import pytest
from unittest.mock import patch, MagicMock
from core.server import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


# ---------------------------------------------------------------------------
# /api/browser/navigate
# ---------------------------------------------------------------------------

_AGENT_PATH = "agents.stealth_browser_agent.StealthBrowserAgent"


def test_browser_navigate_returns_success(client):
    with patch(_AGENT_PATH) as mock_cls:
        mock_agent = MagicMock()
        mock_agent.navigate_stealth.return_value = {
            "success": True,
            "url": "https://example.com",
            "title": "Example",
            "page_source_length": 100,
        }
        mock_cls.return_value = mock_agent
        resp = client.post('/api/browser/navigate', json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["url"] == "https://example.com"
    mock_agent.close.assert_called_once()


def test_browser_navigate_missing_url_returns_400(client):
    resp = client.post('/api/browser/navigate', json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["success"] is False
    assert "url" in data["error"].lower()


def test_browser_navigate_passes_preset_and_wait(client):
    with patch(_AGENT_PATH) as mock_cls:
        mock_agent = MagicMock()
        mock_agent.navigate_stealth.return_value = {"success": True}
        mock_cls.return_value = mock_agent
        client.post('/api/browser/navigate', json={
            "url": "https://example.com",
            "preset": "paranoid",
            "wait": 5.0,
        })
    mock_cls.assert_called_once_with(preset="paranoid")
    mock_agent.navigate_stealth.assert_called_once_with(
        "https://example.com", wait_seconds=5.0,
    )


def test_browser_navigate_exception_returns_500(client):
    with patch(_AGENT_PATH) as mock_cls:
        mock_cls.side_effect = RuntimeError("chrome crashed")
        resp = client.post('/api/browser/navigate', json={"url": "https://example.com"})
    assert resp.status_code == 500
    data = resp.get_json()
    assert data["success"] is False
    assert "chrome crashed" in data["error"]


# ---------------------------------------------------------------------------
# /api/browser/screenshot
# ---------------------------------------------------------------------------

def test_browser_screenshot_returns_b64(client):
    with patch(_AGENT_PATH) as mock_cls:
        mock_agent = MagicMock()
        mock_agent.setup_browser.return_value = True
        mock_agent.screenshot_stealth.return_value = {
            "success": True,
            "screenshot_b64": "abc123",
        }
        mock_cls.return_value = mock_agent
        resp = client.post('/api/browser/screenshot', json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["screenshot_b64"] == "abc123"
    mock_agent.close.assert_called_once()


def test_browser_screenshot_missing_url_returns_400(client):
    resp = client.post('/api/browser/screenshot', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/browser/dom
# ---------------------------------------------------------------------------

def test_browser_dom_returns_structure(client):
    with patch(_AGENT_PATH) as mock_cls:
        mock_agent = MagicMock()
        mock_agent.navigate_stealth.return_value = {"success": True}
        mock_agent.extract_dom_stealth.return_value = {
            "success": True,
            "url": "https://example.com",
            "title": "Example",
            "link_count": 5,
            "links_sample": ["https://example.com/a"],
            "form_count": 2,
            "page_source": "<html></html>",
        }
        mock_cls.return_value = mock_agent
        resp = client.post('/api/browser/dom', json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["link_count"] == 5
    mock_agent.close.assert_called_once()


def test_browser_dom_missing_url_returns_400(client):
    resp = client.post('/api/browser/dom', json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/browser/form-fill
# ---------------------------------------------------------------------------

def test_browser_form_fill_returns_success(client):
    with patch(_AGENT_PATH) as mock_cls:
        mock_agent = MagicMock()
        mock_agent.navigate_stealth.return_value = {"success": True}
        mock_agent.form_fill_stealth.return_value = {
            "success": True,
            "selector": "#email",
            "value_length": 10,
        }
        mock_cls.return_value = mock_agent
        resp = client.post('/api/browser/form-fill', json={
            "url": "https://example.com",
            "selector": "#email",
            "value": "test@a.com",
        })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    mock_agent.close.assert_called_once()


def test_browser_form_fill_missing_fields_returns_400(client):
    resp = client.post('/api/browser/form-fill', json={"url": "https://example.com"})
    assert resp.status_code == 400

    resp2 = client.post('/api/browser/form-fill', json={"selector": "#email"})
    assert resp2.status_code == 400
