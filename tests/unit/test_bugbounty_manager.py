# tests/unit/test_bugbounty_manager.py
"""Tests for BugBountyWorkflowManager (Phase 5b, Task 23)."""
import pytest
from dataclasses import dataclass, field
from typing import List
from agents.bugbounty_manager import BugBountyWorkflowManager


@dataclass
class BugBountyTarget:
    """Minimal target for testing."""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "ssrf", "idor"])


@pytest.fixture
def manager():
    return BugBountyWorkflowManager()


@pytest.fixture
def target():
    return BugBountyTarget(domain="example.com")


def test_create_recon_workflow(manager, target):
    workflow = manager.create_reconnaissance_workflow(target)
    assert isinstance(workflow, dict)
    assert workflow["target"] == "example.com"
    assert "phases" in workflow
    assert len(workflow["phases"]) > 0


def test_create_vuln_hunting_workflow(manager, target):
    workflow = manager.create_vulnerability_hunting_workflow(target)
    assert isinstance(workflow, dict)
    assert workflow["target"] == "example.com"
    assert "vulnerability_tests" in workflow


def test_create_business_logic_workflow(manager, target):
    workflow = manager.create_business_logic_testing_workflow(target)
    assert isinstance(workflow, dict)
    assert workflow["target"] == "example.com"
    assert "business_logic_tests" in workflow


def test_create_osint_workflow(manager, target):
    workflow = manager.create_osint_workflow(target)
    assert isinstance(workflow, dict)
    assert workflow["target"] == "example.com"
    assert "osint_phases" in workflow


def test_high_impact_vulns_populated(manager):
    assert "rce" in manager.high_impact_vulns
    assert "sqli" in manager.high_impact_vulns
    assert manager.high_impact_vulns["rce"]["priority"] == 10
