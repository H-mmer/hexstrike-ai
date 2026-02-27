# hexstrike_mcp_tools/wireless.py
"""MCP tool registrations for wireless security tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import get_client


def wifi_attack(interface: str, target_bssid: str = "", attack_type: str = "handshake") -> Dict[str, Any]:
    """WiFi security testing using wifite2. attack_type: handshake | deauth | pmkid | all"""
    return get_client().safe_post(
        "api/tools/wireless/wifi-attack",
        {"interface": interface, "target_bssid": target_bssid, "attack_type": attack_type},
    )


def bluetooth_scan(interface: str = "hci0") -> Dict[str, Any]:
    """Bluetooth device scanning and vulnerability assessment."""
    return get_client().safe_post("api/tools/wireless/bluetooth-scan", {"interface": interface})


def rf_analysis(frequency: float = 433.0, device: str = "rtlsdr") -> Dict[str, Any]:
    """RF signal analysis using RTL-SDR or HackRF. device: rtlsdr | hackrf"""
    return get_client().safe_post("api/tools/wireless/rf", {"frequency": frequency, "device": device})
