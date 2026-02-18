import pytest
from unittest.mock import MagicMock, mock_open, patch
from scripts.installer.core.tool_manager import ToolManager, InstallStatus, InstallResult
from scripts.installer.core.os_detector import OSDetector

class TestToolManager:
    """Test tool detection and installation"""

    def test_check_installed_tool_exists(self, monkeypatch):
        """Test detection of installed tool"""
        monkeypatch.setattr('shutil.which', lambda x: '/usr/bin/nmap')
        mock_run = MagicMock()
        mock_run.return_value.returncode = 0
        monkeypatch.setattr('subprocess.run', mock_run)

        os_detector = OSDetector()
        manager = ToolManager(os_detector)

        status = manager.check_installed('nmap')

        assert status.installed is True
        assert status.path == '/usr/bin/nmap'

    def test_check_installed_tool_missing(self, monkeypatch):
        """Test detection of missing tool"""
        monkeypatch.setattr('shutil.which', lambda x: None)

        os_detector = OSDetector()
        manager = ToolManager(os_detector)

        status = manager.check_installed('nonexistent-tool')

        assert status.installed is False
        assert status.path is None

    def test_get_package_name_simple(self):
        """Test simple package name resolution"""
        manager = ToolManager(OSDetector())
        assert manager.get_package_name('nmap') == 'nmap'

    def test_get_package_name_from_registry(self, monkeypatch):
        """Test package name from registry"""
        mock_registry = {
            'tools': {
                'retire-js': {
                    'package': 'retire',
                    'manager': 'npm'
                }
            }
        }

        # Mock the _load_registry method
        def mock_load_registry(self):
            return mock_registry

        monkeypatch.setattr('scripts.installer.core.tool_manager.ToolManager._load_registry', mock_load_registry)

        manager = ToolManager(OSDetector())
        assert manager.get_package_name('retire-js') == 'retire'

    def test_get_category(self, monkeypatch):
        """Test category detection"""
        mock_registry = {
            'tools': {
                'nmap': {'category': 'network'},
                'sqlmap': {'category': 'web'}
            }
        }

        def mock_load_registry(self):
            return mock_registry

        monkeypatch.setattr('scripts.installer.core.tool_manager.ToolManager._load_registry', mock_load_registry)

        manager = ToolManager(OSDetector())
        assert manager.get_category('nmap') == 'network'
        assert manager.get_category('sqlmap') == 'web'
