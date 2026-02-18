import pytest
import yaml
from pathlib import Path

def test_registry_file_exists():
    """Test that registry.yaml exists"""
    registry_path = Path('scripts/installer/registry.yaml')
    assert registry_path.exists()

def test_registry_valid_yaml():
    """Test that registry is valid YAML"""
    registry_path = Path('scripts/installer/registry.yaml')
    with open(registry_path) as f:
        data = yaml.safe_load(f)
    assert data is not None
    assert 'tools' in data

def test_registry_has_essential_tools():
    """Test that registry includes essential tools"""
    registry_path = Path('scripts/installer/registry.yaml')
    with open(registry_path) as f:
        data = yaml.safe_load(f)

    tools = data['tools']
    assert 'nmap' in tools
    assert tools['nmap']['tier'] == 'essential'
    assert tools['nmap']['category'] == 'network'
