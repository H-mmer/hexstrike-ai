"""Tests for Phase 4 final documentation (Task 22)."""

import re
from pathlib import Path


class TestInstallationGuide:
    """Tests for docs/installation.md."""

    def test_installation_guide_exists(self):
        assert Path("docs/installation.md").exists()

    def test_installation_guide_has_quick_start(self):
        content = Path("docs/installation.md").read_text()
        assert "Quick Start" in content

    def test_installation_guide_has_prerequisites(self):
        content = Path("docs/installation.md").read_text()
        assert "Prerequisites" in content or "prerequisite" in content.lower()

    def test_installation_guide_has_mode_table(self):
        content = Path("docs/installation.md").read_text()
        # Mode table should list quick, standard, complete
        assert "quick" in content.lower()
        assert "standard" in content.lower()
        assert "complete" in content.lower()

    def test_installation_guide_has_category_reference(self):
        content = Path("docs/installation.md").read_text()
        assert "network" in content.lower()
        assert "web" in content.lower()
        assert "cloud" in content.lower()

    def test_installation_guide_has_cli_reference(self):
        content = Path("docs/installation.md").read_text()
        assert "--mode" in content
        assert "--categories" in content
        assert "--dry-run" in content

    def test_installation_guide_has_docker_section(self):
        content = Path("docs/installation.md").read_text()
        assert "docker" in content.lower() or "Docker" in content


class TestChangelog:
    """Tests for CHANGELOG.md."""

    def test_changelog_exists(self):
        assert Path("CHANGELOG.md").exists()

    def test_changelog_has_phase4_section(self):
        content = Path("CHANGELOG.md").read_text()
        assert "Phase 4" in content or "phase4" in content.lower()

    def test_changelog_has_version_header(self):
        content = Path("CHANGELOG.md").read_text()
        # Should have a version or release header
        assert "v7" in content or "7.0" in content

    def test_changelog_mentions_installer(self):
        content = Path("CHANGELOG.md").read_text()
        assert "installer" in content.lower() or "installation" in content.lower()

    def test_changelog_mentions_docker(self):
        content = Path("CHANGELOG.md").read_text()
        assert "docker" in content.lower() or "Docker" in content


class TestReadmeInstallerSection:
    """Tests that README.md references the automated installer."""

    def test_readme_exists(self):
        assert Path("README.md").exists()

    def test_readme_mentions_automated_installer(self):
        content = Path("README.md").read_text()
        # Should mention the installer script
        assert "install.sh" in content or "scripts/installer" in content

    def test_readme_mentions_quick_mode(self):
        content = Path("README.md").read_text()
        assert "--mode quick" in content or "mode quick" in content

    def test_readme_installer_section_has_example(self):
        content = Path("README.md").read_text()
        # Should have a code block showing installer usage
        assert "python3 -m scripts.installer.main" in content or "install.sh" in content
