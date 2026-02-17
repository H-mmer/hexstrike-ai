import pytest
from pathlib import Path
import re

class TestDockerfile:
    """Test Dockerfile for HexStrike AI installer"""

    def test_dockerfile_exists(self):
        """Test that Dockerfile exists"""
        dockerfile = Path('Dockerfile')
        assert dockerfile.exists(), "Dockerfile should exist in project root"

    def test_dockerfile_has_from_statement(self):
        """Test that Dockerfile has FROM statement"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        assert re.search(r'^FROM\s+', content, re.MULTILINE), \
            "Dockerfile should have FROM statement"

    def test_dockerfile_uses_kali_or_parrot(self):
        """Test that Dockerfile uses Kali or Parrot base image"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        # Check for kali or parrot in FROM statements
        from_statements = re.findall(r'^FROM\s+(\S+)', content, re.MULTILINE)
        assert any('kali' in img.lower() or 'parrot' in img.lower() or 'debian' in img.lower()
                   for img in from_statements), \
            "Dockerfile should use Kali, Parrot, or Debian base image"

    def test_dockerfile_has_multistage_build(self):
        """Test that Dockerfile uses multi-stage build"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        # Count FROM statements (multi-stage should have multiple)
        from_count = len(re.findall(r'^FROM\s+', content, re.MULTILINE))
        assert from_count >= 2, \
            "Dockerfile should use multi-stage build (multiple FROM statements)"

    def test_dockerfile_has_build_stages(self):
        """Test that Dockerfile has named build stages"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        # Check for stage names (FROM ... AS stage_name)
        stages = re.findall(r'^FROM\s+\S+\s+AS\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
        assert len(stages) >= 2, \
            "Dockerfile should have at least 2 named stages"

    def test_dockerfile_copies_installer(self):
        """Test that Dockerfile copies installer code"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        assert 'scripts/installer' in content or 'installer' in content, \
            "Dockerfile should copy installer scripts"

    def test_dockerfile_exposes_port(self):
        """Test that Dockerfile exposes a port"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        assert re.search(r'^EXPOSE\s+\d+', content, re.MULTILINE), \
            "Dockerfile should expose a port"

    def test_dockerfile_has_workdir(self):
        """Test that Dockerfile sets WORKDIR"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        assert re.search(r'^WORKDIR\s+', content, re.MULTILINE), \
            "Dockerfile should set WORKDIR"

    def test_dockerfile_has_cmd_or_entrypoint(self):
        """Test that Dockerfile has CMD or ENTRYPOINT"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        has_cmd = re.search(r'^CMD\s+', content, re.MULTILINE)
        has_entrypoint = re.search(r'^ENTRYPOINT\s+', content, re.MULTILINE)

        assert has_cmd or has_entrypoint, \
            "Dockerfile should have CMD or ENTRYPOINT"

    def test_dockerfile_installs_python(self):
        """Test that Dockerfile installs Python"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        assert 'python3' in content.lower(), \
            "Dockerfile should install python3"

    def test_dockerfile_runs_installer(self):
        """Test that Dockerfile runs the installer"""
        dockerfile = Path('Dockerfile')
        with open(dockerfile) as f:
            content = f.read()

        # Should run installer in some form
        assert 'install' in content.lower() and ('RUN' in content or 'CMD' in content), \
            "Dockerfile should run installer"
