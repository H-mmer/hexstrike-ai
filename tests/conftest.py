"""
Pytest configuration and fixtures
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def sample_target():
    """Sample target for testing"""
    return "example.com"


@pytest.fixture
def sample_port():
    """Sample port for testing"""
    return 8888
