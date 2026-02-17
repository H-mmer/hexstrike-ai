import pytest
from pathlib import Path

class TestDockerFiles:
    """Test Docker-related configuration files"""

    def test_dockerignore_exists(self):
        """Test that .dockerignore exists"""
        dockerignore = Path('.dockerignore')
        assert dockerignore.exists(), ".dockerignore should exist in project root"

    def test_dockerignore_ignores_python_cache(self):
        """Test that .dockerignore excludes Python cache"""
        dockerignore = Path('.dockerignore')
        with open(dockerignore) as f:
            content = f.read()

        assert '__pycache__' in content, ".dockerignore should exclude __pycache__"
        assert '*.pyc' in content or '*.py[cod]' in content, \
            ".dockerignore should exclude compiled Python files"

    def test_dockerignore_ignores_venv(self):
        """Test that .dockerignore excludes virtual environments"""
        dockerignore = Path('.dockerignore')
        with open(dockerignore) as f:
            content = f.read()

        assert 'venv' in content or 'hexstrike-env' in content, \
            ".dockerignore should exclude virtual environments"

    def test_dockerignore_ignores_git(self):
        """Test that .dockerignore excludes .git directory"""
        dockerignore = Path('.dockerignore')
        with open(dockerignore) as f:
            content = f.read()

        assert '.git' in content, ".dockerignore should exclude .git directory"

    def test_docker_documentation_exists(self):
        """Test that Docker documentation exists"""
        docker_md = Path('scripts/installer/DOCKER.md')
        assert docker_md.exists(), "DOCKER.md documentation should exist"

    def test_docker_documentation_has_sections(self):
        """Test that DOCKER.md has required sections"""
        docker_md = Path('scripts/installer/DOCKER.md')
        with open(docker_md) as f:
            content = f.read()

        required_sections = [
            'Overview',
            'Prerequisites',
            'Quick Start',
            'Build',
        ]

        for section in required_sections:
            assert section in content, f"DOCKER.md should have {section} section"

    def test_docker_documentation_has_examples(self):
        """Test that DOCKER.md has usage examples"""
        docker_md = Path('scripts/installer/DOCKER.md')
        with open(docker_md) as f:
            content = f.read()

        # Should have code blocks with docker commands
        assert 'docker-compose up' in content or 'docker compose up' in content, \
            "DOCKER.md should have docker-compose examples"
        assert 'docker build' in content, \
            "DOCKER.md should have docker build examples"
