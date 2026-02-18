"""
Tests for ModernVisualEngine
"""

import pytest
from utils.visual_engine import ModernVisualEngine


def test_colors_defined():
    """Test that color constants are defined"""
    assert len(ModernVisualEngine.COLORS) > 0
    assert 'HACKER_RED' in ModernVisualEngine.COLORS
    assert 'PRIMARY_BORDER' in ModernVisualEngine.COLORS


def test_create_banner():
    """Test banner creation"""
    banner = ModernVisualEngine.create_banner()
    assert isinstance(banner, str)
    assert len(banner) > 100
    assert 'HEXSTRIKE' in banner.upper()


def test_progress_bar():
    """Test progress bar creation"""
    bar = ModernVisualEngine.create_progress_bar(50, 100, width=50, tool="nmap")
    assert isinstance(bar, str)
    assert 'nmap' in bar


def test_render_progress_bar():
    """Test progress bar rendering"""
    bar = ModernVisualEngine.render_progress_bar(0.5, width=40, style='cyber', label="Test")
    assert isinstance(bar, str)
    assert 'Test' in bar
    assert '50.0%' in bar


def test_format_tool_status():
    """Test tool status formatting"""
    status = ModernVisualEngine.format_tool_status("nmap", "RUNNING", "example.com")
    assert isinstance(status, str)
    assert 'NMAP' in status  # Tool name is uppercased in the format
    assert 'example.com' in status.lower()


def test_format_vulnerability_severity():
    """Test vulnerability severity formatting"""
    severity = ModernVisualEngine.format_vulnerability_severity("HIGH", 5)
    assert isinstance(severity, str)
    assert 'HIGH' in severity
    assert '(5)' in severity
