# tests/unit/test_ctf_manager.py
"""Tests for CTFWorkflowManager (Phase 5b, Task 24)."""
import pytest
from dataclasses import dataclass
from agents.ctf_manager import CTFWorkflowManager


@dataclass
class CTFChallenge:
    """Minimal challenge for testing."""
    name: str
    category: str = "misc"
    description: str = ""
    points: int = 0
    difficulty: str = "unknown"
    target: str = ""


@pytest.fixture
def manager():
    return CTFWorkflowManager()


def test_category_tools_populated(manager):
    assert "web" in manager.category_tools
    assert "crypto" in manager.category_tools
    assert "pwn" in manager.category_tools
    assert "forensics" in manager.category_tools
    assert "rev" in manager.category_tools


def test_create_web_challenge_workflow(manager):
    challenge = CTFChallenge(name="WebLogin", category="web", description="Bypass login", points=100)
    workflow = manager.create_ctf_challenge_workflow(challenge)
    assert isinstance(workflow, dict)
    assert "challenge" in workflow
    assert "strategies" in workflow


def test_create_crypto_challenge_workflow(manager):
    challenge = CTFChallenge(name="RSABreak", category="crypto", description="Break RSA", points=200)
    workflow = manager.create_ctf_challenge_workflow(challenge)
    assert isinstance(workflow, dict)
    assert "challenge" in workflow


def test_create_pwn_challenge_workflow(manager):
    challenge = CTFChallenge(name="BufferOverflow", category="pwn", description="Stack smash", points=300)
    workflow = manager.create_ctf_challenge_workflow(challenge)
    assert isinstance(workflow, dict)


def test_create_team_strategy(manager):
    challenges = [
        CTFChallenge(name="Web1", category="web", points=100),
        CTFChallenge(name="Crypto1", category="crypto", points=200),
        CTFChallenge(name="Pwn1", category="pwn", points=300),
    ]
    strategy = manager.create_ctf_team_strategy(challenges, team_size=3)
    assert isinstance(strategy, dict)
    assert "assignments" in strategy or "team_strategy" in strategy or "team_size" in strategy
