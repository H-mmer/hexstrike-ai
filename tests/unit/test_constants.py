"""
Tests for configuration constants
"""

import pytest
from core.constants import API_PORT, API_HOST, COMMAND_TIMEOUT, CACHE_SIZE, CACHE_TTL


def test_api_port():
    """Test API port configuration"""
    assert isinstance(API_PORT, int)
    assert 1024 <= API_PORT <= 65535


def test_api_host():
    """Test API host configuration"""
    assert isinstance(API_HOST, str)
    assert len(API_HOST) > 0


def test_command_timeout():
    """Test command timeout"""
    assert isinstance(COMMAND_TIMEOUT, int)
    assert COMMAND_TIMEOUT > 0


def test_cache_config():
    """Test cache configuration"""
    assert isinstance(CACHE_SIZE, int)
    assert isinstance(CACHE_TTL, int)
    assert CACHE_SIZE > 0
    assert CACHE_TTL > 0
