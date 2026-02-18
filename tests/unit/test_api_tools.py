"""
Tests for API Security Tools
"""

import pytest


def test_api_tools_module_import():
    """Test API tools can be imported"""
    from tools.api import api_discovery, api_auth, api_fuzzing, api_monitoring
    assert api_discovery is not None
    assert api_auth is not None


def test_bearer_token_analyzer():
    """Test bearer token analysis"""
    from tools.api.api_auth import bearer_token_analyzer

    # Test with sample JWT
    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
    result = bearer_token_analyzer(sample_jwt)

    assert result['success'] == True
    assert result['type'] == 'JWT'


def test_jwt_hack():
    """Test JWT decoding"""
    from tools.api.api_auth import jwt_hack

    sample_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.test"
    result = jwt_hack(sample_jwt)

    assert result['success'] == True
    assert 'decoded_payload' in result


def test_api_injection_scanner():
    """Test API injection scanner with mock target"""
    from tools.api.api_fuzzing import api_injection_scanner

    # This will fail to connect but tests the function structure
    result = api_injection_scanner("http://invalid-test-target.local")
    assert 'vulnerabilities' in result
