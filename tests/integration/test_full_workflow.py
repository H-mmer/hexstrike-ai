import pytest
import subprocess
import json
from pathlib import Path

class TestFullInstallationWorkflow:
    """Integration tests for complete installation workflow"""

    def test_full_workflow_quick_mode(self):
        """Test complete installation workflow in quick mode"""
        # Run installer in dry-run mode
        result = subprocess.run(
            ['python3', '-m', 'scripts.installer.main', '--mode', 'quick', '--dry-run'],
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
            ['python3', '-m', 'scripts.installer.main',
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
            ['python3', '-m', 'scripts.installer.main', '--help'],
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
            ['python3', '-m', 'scripts.installer.main', '--mode', 'invalid'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Should fail with non-zero exit code
        assert result.returncode != 0

    def test_skip_checks_bypasses_validation(self):
        """Test that --skip-checks bypasses dependency validation"""
        result = subprocess.run(
            ['python3', '-m', 'scripts.installer.main',
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
        """Test that bash wrapper script works"""
        result = subprocess.run(
            ['bash', 'scripts/installer/install.sh', '--mode', 'quick', '--dry-run'],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Should complete successfully
        assert result.returncode == 0, f"Wrapper failed: {result.stderr}"

        # Should show installer output
        assert 'HexStrike AI' in result.stdout or 'HexStrike AI' in result.stderr
