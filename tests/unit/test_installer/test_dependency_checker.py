import pytest
from unittest.mock import Mock, patch
from scripts.installer.core.dependency_checker import (
    DependencyChecker,
    DependencyCheckResult,
    DependencyError
)

class TestDependencyChecker:
    """Test dependency checker module"""

    def test_check_python_version_success(self, monkeypatch):
        """Test Python version check passes for 3.8+"""
        checker = DependencyChecker()

        # Mock sys.version_info for Python 3.10
        import sys
        mock_version = Mock()
        mock_version.major = 3
        mock_version.minor = 10
        monkeypatch.setattr(sys, 'version_info', mock_version)

        result = checker.check_python_version()
        assert result.passed is True
        assert 'Python 3.10' in result.message or result.message == ''

    def test_check_python_version_failure(self, monkeypatch):
        """Test Python version check fails for < 3.8"""
        checker = DependencyChecker()

        # Mock sys.version_info for Python 3.6
        import sys
        mock_version = Mock()
        mock_version.major = 3
        mock_version.minor = 6
        monkeypatch.setattr(sys, 'version_info', mock_version)

        result = checker.check_python_version()
        assert result.passed is False
        assert '3.8' in result.message

    def test_check_pip_installed(self, monkeypatch):
        """Test pip availability check"""
        checker = DependencyChecker()

        # Mock shutil.which to find pip
        mock_which = Mock(return_value='/usr/bin/pip3')
        monkeypatch.setattr('shutil.which', mock_which)

        result = checker.check_pip()
        assert result.passed is True

    def test_check_pip_missing(self, monkeypatch):
        """Test pip missing"""
        checker = DependencyChecker()

        # Mock shutil.which to not find pip
        mock_which = Mock(return_value=None)
        monkeypatch.setattr('shutil.which', mock_which)

        result = checker.check_pip()
        assert result.passed is False

    def test_check_git_installed(self, monkeypatch):
        """Test git availability check"""
        checker = DependencyChecker()

        # Mock shutil.which to find git
        mock_which = Mock(return_value='/usr/bin/git')
        monkeypatch.setattr('shutil.which', mock_which)

        result = checker.check_git()
        assert result.passed is True

    def test_check_disk_space_sufficient(self, monkeypatch):
        """Test disk space check passes with enough space"""
        checker = DependencyChecker()

        # Mock shutil.disk_usage to show 10GB free
        mock_usage = Mock()
        mock_usage.free = 10 * 1024 * 1024 * 1024  # 10GB in bytes
        mock_disk_usage = Mock(return_value=mock_usage)
        monkeypatch.setattr('shutil.disk_usage', mock_disk_usage)

        result = checker.check_disk_space(required_gb=5)
        assert result.passed is True

    def test_check_disk_space_insufficient(self, monkeypatch):
        """Test disk space check fails with insufficient space"""
        checker = DependencyChecker()

        # Mock shutil.disk_usage to show 2GB free
        mock_usage = Mock()
        mock_usage.free = 2 * 1024 * 1024 * 1024  # 2GB in bytes
        mock_disk_usage = Mock(return_value=mock_usage)
        monkeypatch.setattr('shutil.disk_usage', mock_disk_usage)

        result = checker.check_disk_space(required_gb=5)
        assert result.passed is False

    def test_check_all_dependencies(self, monkeypatch):
        """Test checking all dependencies at once"""
        checker = DependencyChecker()

        # Mock all checks to pass
        import sys
        mock_version = Mock()
        mock_version.major = 3
        mock_version.minor = 10
        monkeypatch.setattr(sys, 'version_info', mock_version)

        mock_which = Mock(return_value='/usr/bin/tool')
        monkeypatch.setattr('shutil.which', mock_which)

        mock_usage = Mock()
        mock_usage.free = 10 * 1024 * 1024 * 1024
        mock_disk_usage = Mock(return_value=mock_usage)
        monkeypatch.setattr('shutil.disk_usage', mock_disk_usage)

        results = checker.check_all()

        assert 'python_version' in results
        assert 'pip' in results
        assert 'git' in results
        assert 'disk_space' in results

        # All should pass
        assert all(r.passed for r in results.values())

    def test_check_all_raises_on_failure(self, monkeypatch):
        """Test that check_all raises DependencyError if any check fails"""
        checker = DependencyChecker()

        # Mock Python version to fail
        import sys
        mock_version = Mock()
        mock_version.major = 3
        mock_version.minor = 6  # Too old
        monkeypatch.setattr(sys, 'version_info', mock_version)

        with pytest.raises(DependencyError):
            checker.check_all(raise_on_failure=True)
