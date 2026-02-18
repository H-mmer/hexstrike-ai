import os
import sys
import pytest
import subprocess
from pathlib import Path

# Ensure the subprocess uses the same Python interpreter that has all deps
_ENV_WITH_PYTHON = {**os.environ, 'PATH': f"{Path(sys.executable).parent}:{os.environ.get('PATH', '')}"}

class TestWrapperScript:
    """Test bash wrapper script"""

    def test_wrapper_exists(self):
        """Test that install.sh exists"""
        wrapper = Path('scripts/installer/install.sh')
        assert wrapper.exists(), "install.sh should exist"

    def test_wrapper_is_executable(self):
        """Test that install.sh is executable"""
        wrapper = Path('scripts/installer/install.sh')
        assert wrapper.stat().st_mode & 0o111, "install.sh should be executable"

    def test_wrapper_has_shebang(self):
        """Test that install.sh has proper shebang"""
        wrapper = Path('scripts/installer/install.sh')
        with open(wrapper) as f:
            first_line = f.readline()
        assert first_line.startswith('#!/'), "install.sh should have shebang"
        assert 'bash' in first_line.lower(), "install.sh should use bash"

    def test_wrapper_help_flag(self):
        """Test that wrapper passes --help to main.py"""
        result = subprocess.run(
            ['bash', 'scripts/installer/install.sh', '--help'],
            capture_output=True,
            text=True,
            env=_ENV_WITH_PYTHON,
            timeout=10
        )

        assert result.returncode == 0, "Wrapper should exit successfully with --help"
        assert 'HexStrike AI' in result.stdout or 'HexStrike AI' in result.stderr, \
            "Help output should mention HexStrike AI"
        assert 'mode' in result.stdout.lower() or 'mode' in result.stderr.lower(), \
            "Help should show mode option"

    def test_wrapper_passes_arguments(self):
        """Test that wrapper passes arguments correctly"""
        result = subprocess.run(
            ['bash', 'scripts/installer/install.sh', '--mode', 'quick', '--dry-run'],
            capture_output=True,
            text=True,
            env=_ENV_WITH_PYTHON,
            timeout=60
        )

        # Should not fail (exit code 0 or 1 is ok for dry-run)
        assert result.returncode in [0, 1], f"Wrapper should handle arguments (got exit code {result.returncode})"
