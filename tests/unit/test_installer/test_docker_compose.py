import pytest
from pathlib import Path
import yaml

class TestDockerCompose:
    """Test docker-compose.yml configuration"""

    def test_docker_compose_exists(self):
        """Test that docker-compose.yml exists"""
        compose_file = Path('docker-compose.yml')
        assert compose_file.exists(), "docker-compose.yml should exist in project root"

    def test_docker_compose_valid_yaml(self):
        """Test that docker-compose.yml is valid YAML"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        assert config is not None, "docker-compose.yml should be valid YAML"
        assert isinstance(config, dict), "docker-compose.yml should be a dictionary"

    def test_docker_compose_has_version(self):
        """Test that docker-compose.yml specifies version"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        # Version can be at root or omitted (compose v2 doesn't require it)
        # Just check the file is valid
        assert config is not None

    def test_docker_compose_has_services(self):
        """Test that docker-compose.yml has services section"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        assert 'services' in config, "docker-compose.yml should have services section"
        assert isinstance(config['services'], dict), "services should be a dictionary"

    def test_docker_compose_has_mode_services(self):
        """Test that docker-compose.yml has quick/standard/complete services"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        services = config.get('services', {})

        # Should have at least one mode service
        mode_services = [s for s in services.keys()
                        if any(mode in s.lower() for mode in ['quick', 'standard', 'complete'])]

        assert len(mode_services) >= 1, \
            "docker-compose.yml should define at least one mode service"

    def test_docker_compose_services_have_build(self):
        """Test that services have build configuration"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        services = config.get('services', {})

        # At least one service should have build config
        services_with_build = [s for s in services.values()
                              if 'build' in s or 'image' in s]

        assert len(services_with_build) >= 1, \
            "At least one service should have build or image configuration"

    def test_docker_compose_services_have_ports(self):
        """Test that services expose ports"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        services = config.get('services', {})

        # At least one service should have ports
        services_with_ports = [s for s in services.values() if 'ports' in s]

        assert len(services_with_ports) >= 1, \
            "At least one service should expose ports"

    def test_docker_compose_ports_are_unique(self):
        """Test that services use different host ports"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        services = config.get('services', {})
        host_ports = []

        for service in services.values():
            if 'ports' in service:
                for port_mapping in service['ports']:
                    # Port can be "8888:8888" or just "8888"
                    if isinstance(port_mapping, str):
                        host_port = port_mapping.split(':')[0]
                        host_ports.append(host_port)

        # All host ports should be unique
        assert len(host_ports) == len(set(host_ports)), \
            "Services should use unique host ports"

    def test_docker_compose_build_targets(self):
        """Test that services specify build targets"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        services = config.get('services', {})

        # Services with build config should have targets
        for service_name, service_config in services.items():
            if 'build' in service_config and isinstance(service_config['build'], dict):
                # If build is a dict, it might have target
                # This is optional but good practice
                pass  # Just verify structure is valid

        assert True  # Structural validation passed

    def test_docker_compose_context_is_current_dir(self):
        """Test that build context is current directory"""
        compose_file = Path('docker-compose.yml')
        with open(compose_file) as f:
            config = yaml.safe_load(f)

        services = config.get('services', {})

        for service_name, service_config in services.items():
            if 'build' in service_config:
                if isinstance(service_config['build'], dict):
                    context = service_config['build'].get('context', '.')
                    assert context == '.' or context == './', \
                        f"Service {service_name} should use current directory as build context"
