#!/usr/bin/env python3
"""
HexStrike AI - Mobile Network Tools

Mobile traffic interception and analysis.
"""

import logging
import subprocess
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def setup_mitmproxy_mobile(listen_port: int = 8080, transparent: bool = True) -> Dict[str, Any]:
    """
    Setup mitmproxy for mobile traffic interception

    Args:
        listen_port: Port to listen on
        transparent: Enable transparent mode
    """
    try:
        cmd = ['mitmproxy', '--listen-port', str(listen_port)]

        if transparent:
            cmd.append('--mode transparent')

        # Start in background
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return {
            "success": True,
            "pid": process.pid,
            "listen_port": listen_port,
            "tool": "mitmproxy-mobile"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def burp_mobile_assistant(target_host: str, burp_proxy: str = "127.0.0.1:8080") -> Dict[str, Any]:
    """
    Configure Burp Suite for mobile app testing

    Args:
        target_host: Mobile device IP
        burp_proxy: Burp proxy address
    """
    try:
        # Generate certificate for mobile
        result = {
            "success": True,
            "proxy": burp_proxy,
            "target": target_host,
            "cert_url": f"http://{burp_proxy.split(':')[0]}:8080/cert",
            "instructions": [
                f"1. Configure device proxy to {burp_proxy}",
                "2. Visit http://burp and download CA certificate",
                "3. Install certificate on mobile device",
                "4. Enable SSL/TLS interception"
            ],
            "tool": "burp-mobile-assistant"
        }
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def tcpdump_mobile(interface: str = "any", output_file: str = "mobile_traffic.pcap", duration: int = 60) -> Dict[str, Any]:
    """
    Capture mobile network traffic using tcpdump

    Args:
        interface: Network interface
        output_file: Output PCAP file
        duration: Capture duration in seconds
    """
    try:
        cmd = ['tcpdump', '-i', interface, '-w', output_file, '-G', str(duration)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)

        return {
            "success": result.returncode == 0,
            "output_file": output_file,
            "interface": interface,
            "duration": duration,
            "tool": "tcpdump-mobile"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def wireshark_android(device_id: Optional[str] = None, output_file: str = "android_traffic.pcap") -> Dict[str, Any]:
    """
    Capture Android device traffic using adb and Wireshark

    Args:
        device_id: Android device ID (adb devices)
        output_file: Output PCAP file
    """
    try:
        # Start tcpdump on Android device
        adb_cmd = ['adb']
        if device_id:
            adb_cmd.extend(['-s', device_id])

        adb_cmd.extend(['shell', 'tcpdump', '-w', '/sdcard/capture.pcap'])

        process = subprocess.Popen(adb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return {
            "success": True,
            "pid": process.pid,
            "device": device_id or "default",
            "output_file": output_file,
            "instructions": [
                "Traffic capture started on Android device",
                "Stop capture: adb shell killall tcpdump",
                f"Pull capture: adb pull /sdcard/capture.pcap {output_file}"
            ],
            "tool": "wireshark-android"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
