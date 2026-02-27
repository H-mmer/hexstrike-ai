# tests/unit/test_decision_engine.py
"""Tests for IntelligentDecisionEngine (Phase 5b, Task 22)."""
import pytest
from unittest.mock import patch
from agents.decision_engine import IntelligentDecisionEngine


@pytest.fixture
def engine():
    return IntelligentDecisionEngine()


def test_analyze_target_ip(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "93.184.216.34"
        profile = engine.analyze_target("93.184.216.34")
        assert profile is not None
        assert hasattr(profile, "to_dict")


def test_analyze_target_domain(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "93.184.216.34"
        profile = engine.analyze_target("example.com")
        assert profile is not None


def test_select_optimal_tools(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "93.184.216.34"
        profile = engine.analyze_target("example.com")
        tools = engine.select_optimal_tools(profile)
        assert isinstance(tools, list)
        assert len(tools) > 0


def test_optimize_parameters_nmap(engine):
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "10.0.0.1"
        profile = engine.analyze_target("10.0.0.1")
        params = engine.optimize_parameters("nmap", profile)
        assert isinstance(params, dict)


def test_no_name_error_on_optimize(engine):
    """Verify the broken parameter_optimizer reference is gone."""
    with patch("agents.decision_engine.socket") as mock_socket:
        mock_socket.gethostbyname.return_value = "10.0.0.1"
        profile = engine.analyze_target("10.0.0.1")
        # This should NOT raise NameError
        params = engine.optimize_parameters("nuclei", profile)
        assert isinstance(params, dict)
