"""
Tests for Mobile Security Tools
"""

import pytest
from tools.mobile.apk_tools import check_mobile_tools
from tools.mobile.ios_tools import check_ios_tools


def test_mobile_tools_module_import():
    """Test mobile tools can be imported"""
    from tools.mobile import apk_tools, ios_tools, mobile_network, mobile_exploit
    assert apk_tools is not None
    assert ios_tools is not None


def test_check_mobile_tools():
    """Test mobile tools availability checker"""
    available = check_mobile_tools()
    assert isinstance(available, dict)
    assert 'apktool' in available
    assert 'jadx' in available


def test_check_ios_tools():
    """Test iOS tools availability checker"""
    available = check_ios_tools()
    assert isinstance(available, dict)
    assert isinstance(available.get('class-dump'), bool)


def test_mobile_exploit_generator():
    """Test mobile exploit template generator"""
    from tools.mobile.mobile_exploit import mobile_exploit_generator

    result = mobile_exploit_generator('android', 'intent_hijacking')
    assert result['success'] == True
    assert 'exploit_code' in result
    assert 'Intent' in result['exploit_code']
