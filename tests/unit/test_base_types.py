"""
Tests for agent base types
"""

import pytest
from agents.base import TargetType, TechnologyStack, TargetProfile, AttackStep, AttackChain


def test_target_type_enum():
    """Test TargetType enum"""
    assert TargetType.WEB_APPLICATION.value == "web_application"
    assert TargetType.NETWORK_HOST.value == "network_host"
    assert TargetType.UNKNOWN.value == "unknown"


def test_technology_stack_enum():
    """Test TechnologyStack enum"""
    assert TechnologyStack.APACHE.value == "apache"
    assert TechnologyStack.NGINX.value == "nginx"
    assert TechnologyStack.WORDPRESS.value == "wordpress"


def test_target_profile_creation():
    """Test TargetProfile creation"""
    profile = TargetProfile(target="example.com")
    assert profile.target == "example.com"
    assert profile.target_type == TargetType.UNKNOWN
    assert isinstance(profile.ip_addresses, list)
    assert isinstance(profile.open_ports, list)


def test_target_profile_to_dict():
    """Test TargetProfile serialization"""
    profile = TargetProfile(
        target="example.com",
        target_type=TargetType.WEB_APPLICATION,
        ip_addresses=["1.2.3.4"]
    )
    data = profile.to_dict()
    assert isinstance(data, dict)
    assert data['target'] == "example.com"
    assert data['target_type'] == "web_application"
    assert "1.2.3.4" in data['ip_addresses']


def test_attack_step_creation():
    """Test AttackStep creation"""
    step = AttackStep(
        tool="nmap",
        parameters={"target": "example.com"},
        expected_outcome="port scan",
        success_probability=0.9,
        execution_time_estimate=60
    )
    assert step.tool == "nmap"
    assert step.success_probability == 0.9


def test_attack_chain_creation():
    """Test AttackChain creation"""
    profile = TargetProfile(target="example.com")
    chain = AttackChain(profile)
    assert chain.target_profile.target == "example.com"
    assert len(chain.steps) == 0
    assert chain.success_probability == 0.0


def test_attack_chain_add_step():
    """Test adding steps to attack chain"""
    profile = TargetProfile(target="example.com")
    chain = AttackChain(profile)

    step = AttackStep(
        tool="nmap",
        parameters={},
        expected_outcome="scan",
        success_probability=0.9,
        execution_time_estimate=60
    )

    chain.add_step(step)
    assert len(chain.steps) == 1
    assert 'nmap' in chain.required_tools
    assert chain.estimated_time == 60
