"""Integration: browser routes + StealthBrowserAgent (mock UC driver).

Tests exercise the full Flask route -> StealthBrowserAgent pipeline with
a mocked undetected-chromedriver so no real Chrome instance is needed.
"""
import pytest
from unittest.mock import patch, MagicMock

from core.server import create_app


@pytest.fixture
def client():
    """Flask test client with all blueprints (including browser) registered."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def _mock_uc():
    """Patch ``agents.stealth_browser_agent.uc`` and ``time.sleep``
    so browser tests run instantly without a real Chrome binary."""
    with patch("agents.stealth_browser_agent.uc") as uc_mock, \
         patch("agents.stealth_browser_agent.time.sleep"):
        drv = MagicMock()
        drv.current_url = "https://target.com"
        drv.title = "Target"
        drv.page_source = "<html><body>Hello</body></html>"
        drv.execute_script.return_value = ["https://target.com/page"]
        drv.get_screenshot_as_base64.return_value = "FAKEB64"
        uc_mock.Chrome.return_value = drv
        uc_mock.ChromeOptions.return_value = MagicMock()
        yield uc_mock, drv


class TestStealthBrowserE2E:
    """End-to-end: Flask route -> StealthBrowserAgent -> mock UC driver."""

    def test_navigate_returns_success(self, client, _mock_uc):
        """POST /api/browser/navigate returns success with page metadata."""
        resp = client.post(
            "/api/browser/navigate",
            json={"url": "https://target.com"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["url"] == "https://target.com"
        assert data["title"] == "Target"

    def test_screenshot_returns_base64(self, client, _mock_uc):
        """POST /api/browser/screenshot returns a base64 screenshot."""
        resp = client.post(
            "/api/browser/screenshot",
            json={"url": "https://target.com"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["screenshot_b64"] == "FAKEB64"

    def test_dom_extraction_returns_links(self, client, _mock_uc):
        """POST /api/browser/dom returns DOM structure with link count."""
        resp = client.post(
            "/api/browser/dom",
            json={"url": "https://target.com"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["link_count"] >= 0

    def test_navigate_dom_screenshot_pipeline(self, client, _mock_uc):
        """Simulate full pipeline: navigate -> DOM extraction -> screenshot."""
        # Step 1 -- Navigate
        resp = client.post(
            "/api/browser/navigate",
            json={"url": "https://target.com"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

        # Step 2 -- Screenshot
        resp = client.post(
            "/api/browser/screenshot",
            json={"url": "https://target.com"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["screenshot_b64"] == "FAKEB64"

        # Step 3 -- DOM extraction
        resp = client.post(
            "/api/browser/dom",
            json={"url": "https://target.com"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["link_count"] >= 0

    def test_navigate_missing_url_returns_400(self, client):
        """POST /api/browser/navigate without url returns 400."""
        resp = client.post("/api/browser/navigate", json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["success"] is False
        assert "url" in data["error"].lower()

    def test_screenshot_missing_url_returns_400(self, client):
        """POST /api/browser/screenshot without url returns 400."""
        resp = client.post("/api/browser/screenshot", json={})
        assert resp.status_code == 400

    def test_dom_missing_url_returns_400(self, client):
        """POST /api/browser/dom without url returns 400."""
        resp = client.post("/api/browser/dom", json={})
        assert resp.status_code == 400
