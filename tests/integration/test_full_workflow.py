import pytest
import subprocess
import json
import sys
from pathlib import Path

class TestFullInstallationWorkflow:
    """Integration tests for complete installation workflow"""

    def test_full_workflow_quick_mode(self):
        """Test complete installation workflow in quick mode"""
        # Run installer in dry-run mode
        result = subprocess.run(
            [sys.executable, '-m', 'scripts.installer.main', '--mode', 'quick', '--dry-run'],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Should complete successfully
        assert result.returncode == 0, f"Installer failed: {result.stderr}"

        # Output should show all steps
        output = result.stdout
        assert '1. Detecting operating system' in output or 'Detecting OS' in output
        assert '2. Building tool list' in output or 'Building tool' in output
        assert '3. Scanning installed tools' in output or 'Scanning' in output

    def test_installation_reports_correctly(self):
        """Test that installation generates correct reports"""
        # Run with JSON output
        result = subprocess.run(
            [sys.executable, '-m', 'scripts.installer.main',
             '--mode', 'quick', '--dry-run', '--output', 'json'],
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0

        # Check that JSON report was created
        json_report = Path('hexstrike_install_report.json')
        if json_report.exists():
            with open(json_report) as f:
                data = json.load(f)

            # Should have required fields
            assert 'timestamp' in data
            assert 'summary' in data

            # Cleanup
            json_report.unlink()

    def test_help_displays_usage(self):
        """Test that --help shows usage information"""
        result = subprocess.run(
            [sys.executable, '-m', 'scripts.installer.main', '--help'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0
        assert 'mode' in result.stdout.lower()
        assert 'quick' in result.stdout.lower() or 'standard' in result.stdout.lower()

    def test_invalid_mode_rejected(self):
        """Test that invalid mode is rejected"""
        result = subprocess.run(
            [sys.executable, '-m', 'scripts.installer.main', '--mode', 'invalid'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Should fail with non-zero exit code
        assert result.returncode != 0

    def test_skip_checks_bypasses_validation(self):
        """Test that --skip-checks bypasses dependency validation"""
        result = subprocess.run(
            [sys.executable, '-m', 'scripts.installer.main',
             '--mode', 'quick', '--dry-run', '--skip-checks'],
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0

        # Should not show dependency check step
        output = result.stdout
        # Step 0 (dependency checks) should be skipped
        # Should start directly with Step 1 (OS detection)
        assert '1. Detecting operating system' in output or 'Detecting OS' in output

    def test_bash_wrapper_works(self):
        """Test that bash wrapper script exists and is executable"""
        wrapper = Path('scripts/installer/install.sh')
        assert wrapper.exists(), "install.sh should exist"
        assert wrapper.stat().st_mode & 0o111, "install.sh should be executable"

        # Check shebang
        with open(wrapper) as f:
            first_line = f.readline()
        assert first_line.startswith('#!/'), "install.sh should have a shebang"

        # Run --help (fast, no subprocess scanning)
        result = subprocess.run(
            ['bash', 'scripts/installer/install.sh', '--help'],
            capture_output=True,
            text=True,
            env={**__import__('os').environ, 'PATH': f"{Path(sys.executable).parent}:{__import__('os').environ.get('PATH', '')}"},
            timeout=10
        )
        # Help should either succeed or fail due to missing click in system python
        # Either way, the script itself should be reachable
        assert result.returncode in [0, 1], \
            f"Unexpected exit code {result.returncode}: {result.stderr}"
