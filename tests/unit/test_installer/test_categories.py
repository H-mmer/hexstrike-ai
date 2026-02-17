import pytest
from scripts.installer.categories.network import get_network_tools
from scripts.installer.categories.web import get_web_tools
from scripts.installer.categories.cloud import get_cloud_tools
from scripts.installer.categories.binary import get_binary_tools
from scripts.installer.categories.mobile import get_mobile_tools
from scripts.installer.categories.forensics import get_forensics_tools

class TestNetworkCategory:
    """Test Network/Reconnaissance category"""

    def test_returns_network_tools(self):
        """Test that network category returns correct tools"""
        tools = get_network_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 25  # Should have at least 25 network tools

        # Check for key network tools
        assert 'nmap' in tools
        assert 'rustscan' in tools
        assert 'masscan' in tools
        assert 'amass' in tools
        assert 'subfinder' in tools

    def test_network_tools_are_sorted(self):
        """Test that network tools are alphabetically sorted"""
        tools = get_network_tools()
        assert tools == sorted(tools)


class TestWebCategory:
    """Test Web Application Security category"""

    def test_returns_web_tools(self):
        """Test that web category returns correct tools"""
        tools = get_web_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 30  # Should have at least 30 web tools

        # Check for key web tools
        assert 'gobuster' in tools
        assert 'nuclei' in tools
        assert 'sqlmap' in tools
        assert 'nikto' in tools

    def test_web_tools_are_sorted(self):
        """Test that web tools are alphabetically sorted"""
        tools = get_web_tools()
        assert tools == sorted(tools)


class TestCloudCategory:
    """Test Cloud Security category"""

    def test_returns_cloud_tools(self):
        """Test that cloud category returns correct tools"""
        tools = get_cloud_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 10  # Should have at least 10 cloud tools

        # Check for key cloud tools
        assert 'trivy' in tools
        assert 'scout-suite' in tools

    def test_cloud_tools_are_sorted(self):
        """Test that cloud tools are alphabetically sorted"""
        tools = get_cloud_tools()
        assert tools == sorted(tools)


class TestBinaryCategory:
    """Test Binary Analysis category"""

    def test_returns_binary_tools(self):
        """Test that binary category returns correct tools"""
        tools = get_binary_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 15  # Should have at least 15 binary tools

        # Check for key binary tools
        assert 'gdb' in tools
        assert 'radare2' in tools
        assert 'ghidra' in tools

    def test_binary_tools_are_sorted(self):
        """Test that binary tools are alphabetically sorted"""
        tools = get_binary_tools()
        assert tools == sorted(tools)


class TestMobileCategory:
    """Test Mobile Security category"""

    def test_returns_mobile_tools(self):
        """Test that mobile category returns correct tools"""
        tools = get_mobile_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 8  # Should have at least 8 mobile tools

        # Check for key mobile tools
        assert 'apktool' in tools
        assert 'jadx' in tools

    def test_mobile_tools_are_sorted(self):
        """Test that mobile tools are alphabetically sorted"""
        tools = get_mobile_tools()
        assert tools == sorted(tools)


class TestForensicsCategory:
    """Test Forensics & Malware category"""

    def test_returns_forensics_tools(self):
        """Test that forensics category returns correct tools"""
        tools = get_forensics_tools()

        assert isinstance(tools, list)
        assert len(tools) >= 8  # Should have at least 8 forensics tools

        # Check for key forensics tools
        assert 'yara' in tools
        assert 'volatility3' in tools
        assert 'autopsy' in tools

    def test_forensics_tools_are_sorted(self):
        """Test that forensics tools are alphabetically sorted"""
        tools = get_forensics_tools()
        assert tools == sorted(tools)
