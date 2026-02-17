import pytest
from click.testing import CliRunner
from unittest.mock import Mock
from scripts.installer.main import main
from scripts.installer.core.dependency_checker import DependencyCheckResult

class TestPreflightValidation:
    """Test pre-flight dependency checking in main CLI"""

    def test_dependency_checks_run_before_installation(self, monkeypatch):
        """Test that dependency checks run before OS detection"""
        # Mock all dependencies
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = ([], [])
        mock_reporter = Mock()
        mock_dependency_checker = Mock()

        # Mock successful dependency checks
        mock_dependency_checker.check_all.return_value = {
            'python_version': DependencyCheckResult('Python', True, 'Python 3.10'),
            'pip': DependencyCheckResult('pip', True, 'Found'),
            'git': DependencyCheckResult('git', True, 'Found'),
            'disk_space': DependencyCheckResult('Disk', True, '10GB'),
            'internet': DependencyCheckResult('Internet', True, 'Connected')
        }

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.DependencyChecker', lambda: mock_dependency_checker)
        monkeypatch.setattr('scripts.installer.main.get_quick_tools', lambda: [])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick', '--dry-run'])

        # Verify dependency checker was called
        mock_dependency_checker.check_all.assert_called_once()

        # Should succeed
        assert result.exit_code == 0

    def test_skip_checks_flag_bypasses_validation(self, monkeypatch):
        """Test that --skip-checks bypasses dependency validation"""
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = ([], [])
        mock_reporter = Mock()
        mock_dependency_checker = Mock()

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.DependencyChecker', lambda: mock_dependency_checker)
        monkeypatch.setattr('scripts.installer.main.get_quick_tools', lambda: [])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick', '--dry-run', '--skip-checks'])

        # Verify dependency checker was NOT called
        mock_dependency_checker.check_all.assert_not_called()

        # Should succeed
        assert result.exit_code == 0

    def test_failed_dependency_check_exits(self, monkeypatch):
        """Test that failed dependency check exits early"""
        from scripts.installer.core.dependency_checker import DependencyError

        mock_dependency_checker = Mock()
        mock_dependency_checker.check_all.side_effect = DependencyError("Python 3.8+ required")

        monkeypatch.setattr('scripts.installer.main.DependencyChecker', lambda: mock_dependency_checker)

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick'])

        # Should exit with error
        assert result.exit_code != 0
        assert 'dependency' in result.output.lower() or 'python' in result.output.lower()

    def test_dependency_check_warnings_shown(self, monkeypatch):
        """Test that dependency warnings are displayed to user"""
        mock_os_detector = Mock()
        mock_tool_manager = Mock()
        mock_tool_manager.scan_tools.return_value = ([], [])
        mock_reporter = Mock()
        mock_dependency_checker = Mock()

        # Mock one check failing (but not raising)
        mock_dependency_checker.check_all.return_value = {
            'python_version': DependencyCheckResult('Python', True, 'Python 3.10'),
            'pip': DependencyCheckResult('pip', True, 'Found'),
            'git': DependencyCheckResult('git', False, 'git not found'),  # Failed
            'disk_space': DependencyCheckResult('Disk', True, '10GB'),
            'internet': DependencyCheckResult('Internet', True, 'Connected')
        }

        monkeypatch.setattr('scripts.installer.main.OSDetector', lambda: mock_os_detector)
        monkeypatch.setattr('scripts.installer.main.ToolManager', lambda x: mock_tool_manager)
        monkeypatch.setattr('scripts.installer.main.Reporter', lambda: mock_reporter)
        monkeypatch.setattr('scripts.installer.main.DependencyChecker', lambda: mock_dependency_checker)
        monkeypatch.setattr('scripts.installer.main.get_quick_tools', lambda: [])

        runner = CliRunner()
        result = runner.invoke(main, ['--mode', 'quick', '--dry-run'])

        # Should display warning about git
        assert 'git' in result.output.lower() or result.exit_code != 0
