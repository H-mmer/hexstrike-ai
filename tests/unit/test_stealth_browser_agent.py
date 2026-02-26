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


def test_standard_preset_has_human_behaviour(mock_uc):
    from agents.stealth_browser_agent import StealthBrowserAgent
    from agents.human_behaviour import HumanBehaviourMixin
    agent = StealthBrowserAgent(preset="standard")
    assert isinstance(agent, HumanBehaviourMixin)


def test_screenshot_stealth_returns_base64(mock_uc):
    uc_mock, driver_mock = mock_uc
    driver_mock.get_screenshot_as_base64.return_value = "abc123base64"
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    result = agent.screenshot_stealth()
    assert result["success"] is True
    assert result["screenshot_b64"] == "abc123base64"


def test_form_fill_stealth_types_with_delays(mock_uc):
    uc_mock, driver_mock = mock_uc
    mock_element = MagicMock()
    driver_mock.find_element.return_value = mock_element
    from agents.stealth_browser_agent import StealthBrowserAgent
    with patch("time.sleep"):
        agent = StealthBrowserAgent()
        agent.setup_browser()
        result = agent.form_fill_stealth("#username", "testuser")
    assert result["success"] is True
    assert mock_element.send_keys.call_count == len("testuser")


def test_extract_dom_stealth_returns_page_source(mock_uc):
    uc_mock, driver_mock = mock_uc
    driver_mock.page_source = "<html><body>test</body></html>"
    driver_mock.current_url = "https://example.com"
    driver_mock.title = "Example"
    driver_mock.execute_script.return_value = []
    from agents.stealth_browser_agent import StealthBrowserAgent
    agent = StealthBrowserAgent()
    agent.setup_browser()
    result = agent.extract_dom_stealth()
    assert result["success"] is True
    assert "page_source" in result
    assert "<html>" in result["page_source"]
