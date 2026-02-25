# hexstrike_mcp_tools/mobile.py
"""MCP tool registrations for mobile security tools."""
from typing import Dict, Any
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def apk_analyze(apk_path: str) -> Dict[str, Any]:
    """Full APK analysis using apktool, jadx, and androguard. apk_path: path to the APK file."""
    return get_client().safe_post("api/tools/mobile/apk-analyze", {"apk_path": apk_path})


@mcp.tool()
def ios_analyze(ipa_path: str) -> Dict[str, Any]:
    """iOS IPA analysis using ipa-analyzer and class-dump. ipa_path: path to the IPA file."""
    return get_client().safe_post("api/tools/mobile/ios-analyze", {"ipa_path": ipa_path})


@mcp.tool()
def drozer_android_audit(package: str) -> Dict[str, Any]:
    """Android app security audit using Drozer. package: Android app package name (e.g. com.example.app)."""
    return get_client().safe_post("api/tools/mobile/drozer", {"package": package})


@mcp.tool()
def mobile_traffic_intercept(listen_port: int = 8080) -> Dict[str, Any]:
    """Intercept mobile app traffic using mitmproxy. listen_port: port to listen on (default: 8080)."""
    return get_client().safe_post("api/tools/mobile/mitm", {"listen_port": listen_port})
