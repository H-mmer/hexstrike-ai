"""
Tests for Wireless Security Tools
"""

import pytest


def test_wireless_tools_module_import():
    """Test wireless tools can be imported"""
    from tools.wireless import wifi_tools, bluetooth_tools, rf_tools
    assert wifi_tools is not None
    assert bluetooth_tools is not None
    assert rf_tools is not None


def test_wifi_tool_structure():
    """Test WiFi tool function signatures"""
    from tools.wireless.wifi_tools import wifite2_attack, bettercap_wifi

    # Test function exists and has proper signature
    assert callable(wifite2_attack)
    assert callable(bettercap_wifi)


def test_bluetooth_tool_structure():
    """Test Bluetooth tool function signatures"""
    from tools.wireless.bluetooth_tools import bluez_scan, btlejack_sniff

    assert callable(bluez_scan)
    assert callable(btlejack_sniff)


def test_rf_tool_structure():
    """Test RF tool function signatures"""
    from tools.wireless.rf_tools import rtl_sdr_scan, hackrf_sweep, gqrx_analyze

    assert callable(rtl_sdr_scan)
    assert callable(hackrf_sweep)
    assert callable(gqrx_analyze)

    # Test gqrx returns expected structure
    result = gqrx_analyze(100e6)
    assert result['success'] == True
    assert 'instructions' in result
