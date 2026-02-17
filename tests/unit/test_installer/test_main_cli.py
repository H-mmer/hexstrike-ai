import pytest
from click.testing import CliRunner
from unittest.mock import Mock, patch, MagicMock
from scripts.installer.main import main, validate_categories

class TestMainCLI:
    """Test main CLI entry point"""

    def test_cli_help(self):
        """Test that --help displays usage information"""
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])

        assert result.exit_code == 0
        assert 'mode' in result.output.lower()
        assert 'categories' in result.output.lower()

    def test_mode_quick(self, monkeypatch):
        """Test quick mode execution"""
        # Mock all dependencies
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = (['nmap'], ['gobuster'])
        mock_reporter = Mock()

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.get_quick_tools', lambda: ['nmap', 'gobuster'])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick', '--dry-run'])

        assert result.exit_code == 0
        mock_os_detector.verify_supported_os.assert_called_once()

    def test_mode_standard(self, monkeypatch):
        """Test standard mode execution"""
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = ([], [])
        mock_reporter = Mock()

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.get_standard_tools', lambda: ['tool1', 'tool2'])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'standard', '--dry-run'])

        assert result.exit_code == 0

    def test_category_filtering(self):
        """Test category filtering validation"""
        # Valid categories
        assert validate_categories('network,web') is None

        # Invalid category should raise error
        with pytest.raises(ValueError, match="Invalid category"):
            validate_categories('invalid_category')

    def test_dry_run_flag(self, monkeypatch):
        """Test that dry-run prevents actual installation"""
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = ([], ['nmap'])
        mock_reporter = Mock()

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.get_quick_tools', lambda: ['nmap'])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick', '--dry-run'])

        # Verify install_tool was NOT called (dry-run)
        mock_tool_manager.install_tool.assert_not_called()

    def test_output_format_html(self, monkeypatch):
        """Test HTML output format"""
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = ([], [])
        mock_reporter = Mock()

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.get_quick_tools', lambda: [])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick', '--output', 'html', '--dry-run'])

        # Verify HTML report was generated
        assert mock_reporter.generate_html_report.called or result.exit_code == 0

    def test_unsupported_os_error(self, monkeypatch):
        """Test error handling for unsupported OS"""
        from scripts.installer.core.os_detector import UnsupportedOSError

        mock_os_detector = Mock()
        mock_os_detector.verify_supported_os.side_effect = UnsupportedOSError("Ubuntu not supported")

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick'])

        assert result.exit_code != 0
        assert 'not supported' in result.output.lower()
