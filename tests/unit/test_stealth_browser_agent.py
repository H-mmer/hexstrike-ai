"""StealthBrowserAgent tests -- all Chrome calls are mocked."""
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_uc():
    """Patch undetected_chromedriver so no real Chrome needed."""
    with patch("agents.stealth_browser_agent.uc") as mock:
        mock_driver = MagicMock()
        mock.Chrome.return_value = mock_driver
        mock.ChromeOptions.return_value = MagicMock()
        yield mock, mock_driver


def test_stealth_agent_instantiation():
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    assert agent.driver is None
    assert agent.preset == "standard"


def test_setup_browser_creates_driver(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    result = agent.setup_browser()
    assert result is True
    assert agent.driver is driver_mock


def test_preset_minimal(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent(preset="minimal")
    agent.setup_browser()
    assert uc_mock.Chrome.called


def test_preset_paranoid(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent(preset="paranoid")
    agent.setup_browser()
    assert uc_mock.Chrome.called


def test_navigate_stealth_calls_get(mock_uc):
    uc_mock, driver_mock = mock_uc
    driver_mock.current_url = "https://example.com"
    driver_mock.title = "Example"
    driver_mock.page_source = "<html></html>"
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    result = agent.navigate_stealth("https://example.com")
    driver_mock.get.assert_called_once_with("https://example.com")
    assert result["success"] is True


def test_close_quits_driver(mock_uc):
    uc_mock, driver_mock = mock_uc
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    agent.close()
    driver_mock.quit.assert_called_once()
    assert agent.driver is None
