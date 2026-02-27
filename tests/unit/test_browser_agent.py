# tests/unit/test_browser_agent.py
"""Tests for BrowserAgent (Phase 5b, Task 26)."""
import sys
import types
import pytest
from unittest.mock import patch, MagicMock

# Ensure selenium's websocket dependency is satisfied before importing
if "websocket" not in sys.modules:
    sys.modules["websocket"] = types.ModuleType("websocket")
    sys.modules["websocket"].WebSocketApp = MagicMock()

from agents.browser_agent import BrowserAgent


@pytest.fixture
def agent():
    return BrowserAgent()


def test_init(agent):
    assert agent.driver is None
    assert agent.screenshots == []
    assert agent.page_sources == []
    assert agent.network_logs == []


@patch("agents.browser_agent.webdriver.Chrome")
def test_setup_browser_success(mock_chrome, agent):
    mock_driver = MagicMock()
    mock_chrome.return_value = mock_driver
    result = agent.setup_browser(headless=True)
    assert result is True
    assert agent.driver is mock_driver


@patch("agents.browser_agent.webdriver.Chrome")
def test_setup_browser_failure(mock_chrome, agent):
    mock_chrome.side_effect = Exception("No Chrome")
    result = agent.setup_browser()
    assert result is False
    assert agent.driver is None


@patch("agents.browser_agent.webdriver.Chrome")
def test_navigate_and_inspect(mock_chrome, agent):
    mock_driver = MagicMock()
    mock_chrome.return_value = mock_driver
    mock_driver.page_source = "<html><body>Test</body></html>"
    mock_driver.title = "Test Page"
    mock_driver.current_url = "http://example.com"
    mock_driver.get_log.return_value = []
    mock_driver.find_elements.return_value = []
    agent.setup_browser()
    result = agent.navigate_and_inspect("http://example.com", wait_time=0)
    assert isinstance(result, dict)
    mock_driver.get.assert_called_with("http://example.com")


def test_navigate_without_driver(agent):
    """navigate_and_inspect without setup_browser tries to auto-setup."""
    with patch("agents.browser_agent.webdriver.Chrome") as mock_chrome:
        mock_chrome.side_effect = Exception("No Chrome")
        result = agent.navigate_and_inspect("http://example.com", wait_time=0)
        assert isinstance(result, dict)
        assert result.get("success") is False
