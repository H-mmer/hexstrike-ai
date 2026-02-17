import pytest
from scripts.installer.modes.quick import get_quick_tools
from scripts.installer.modes.standard import get_standard_tools
from scripts.installer.modes.complete import get_complete_tools

class TestQuickMode:
    """Test QuickMode (essential tier only)"""

    def test_returns_essential_tools_only(self):
        """Test that quick mode returns only essential tier tools"""
        tools = get_quick_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 20  # At least 20 essential tools
        assert 'nmap' in tools
        assert 'gobuster' in tools
        assert 'gdb' in tools

    def test_no_core_or_specialized_tools(self):
        """Test that quick mode excludes core and specialized tiers"""
        tools = get_quick_tools()

        # Core tier tools should not be present
        assert 'autorecon' not in tools  # core tier
        assert 'feroxbuster' not in tools  # core tier

        # Specialized tier tools should not be present
        assert 'apktool' not in tools  # specialized
        assert 'frida' not in tools  # specialized


class TestStandardMode:
    """Test StandardMode (essential + core tiers)"""

    def test_returns_essential_and_core_tools(self):
        """Test that standard mode returns essential + core tiers"""
        tools = get_standard_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 36  # At least 36 tools (essential + core)

        # Essential tools
        assert 'nmap' in tools
        assert 'gobuster' in tools

        # Core tools
        assert 'autorecon' in tools
        assert 'feroxbuster' in tools

    def test_no_specialized_tools(self):
        """Test that standard mode excludes specialized tier"""
        tools = get_standard_tools()

        # Specialized tier should not be present
        assert 'apktool' not in tools
        assert 'frida' not in tools


class TestCompleteMode:
    """Test CompleteMode (all tiers)"""

    def test_returns_all_tools(self):
        """Test that complete mode returns all tools"""
        tools = get_complete_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 54  # At least 54 tools (all registry)

        # Essential
        assert 'nmap' in tools

        # Core
        assert 'autorecon' in tools

        # Specialized
        assert 'apktool' in tools
        assert 'frida' in tools

    def test_includes_all_tiers(self):
        """Test that complete mode has tools from all tiers"""
        tools = get_complete_tools()
        quick = get_quick_tools()
        standard = get_standard_tools()

        # Complete should include all quick tools
        for tool in quick:
            assert tool in tools

        # Complete should include all standard tools
        for tool in standard:
            assert tool in tools
