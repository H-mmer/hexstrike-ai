#!/usr/bin/env python3
"""
HexStrike AI - iOS Analysis Tools

iOS application security testing and reverse engineering.
"""

import logging
import subprocess
import os
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def class_dump(binary_path: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Dump Objective-C class information using class-dump

    Args:
        binary_path: Path to iOS binary
        output_file: Output file for class dump
    """
    try:
        cmd = ['class-dump', binary_path]

        if output_file:
            cmd.extend(['-o', output_file])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        return {
            "success": result.returncode == 0,
            "output": result.stdout if not output_file else output_file,
            "stderr": result.stderr,
            "tool": "class-dump"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def frida_ios_dump(app_id: str, output_dir: str = "./dump") -> Dict[str, Any]:
    """
    Dump decrypted IPA using frida-ios-dump

    Args:
        app_id: iOS app bundle ID
        output_dir: Output directory for decrypted IPA
    """
    try:
        cmd = ['frida-ios-dump', '-o', output_dir, app_id]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        return {
            "success": result.returncode == 0,
            "output_dir": output_dir,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tool": "frida-ios-dump"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def ipa_analyzer(ipa_path: str) -> Dict[str, Any]:
    """
    Analyze IPA file structure and metadata

    Args:
        ipa_path: Path to IPA file
    """
    try:
        import zipfile
        import plistlib

        analysis = {"success": True, "tool": "ipa-analyzer"}

        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            # List all files
            analysis["files"] = zip_ref.namelist()

            # Find Info.plist
            info_plist = [f for f in analysis["files"] if 'Info.plist' in f]
            if info_plist:
                plist_data = zip_ref.read(info_plist[0])
                plist = plistlib.loads(plist_data)
                analysis["bundle_id"] = plist.get('CFBundleIdentifier')
                analysis["version"] = plist.get('CFBundleShortVersionString')
                analysis["min_ios"] = plist.get('MinimumOSVersion')

        return analysis
    except Exception as e:
        return {"success": False, "error": str(e)}


def objection_explore(bundle_id: str, command: Optional[str] = None) -> Dict[str, Any]:
    """
    Runtime mobile exploration using Objection

    Args:
        bundle_id: iOS app bundle ID
        command: Objection command to execute
    """
    try:
        cmd = ['objection', '--gadget', bundle_id, 'explore']

        if command:
            cmd.extend(['--startup-command', command])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tool": "objection"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def hopper_disassemble(binary_path: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Disassemble iOS binary using Hopper

    Args:
        binary_path: Path to iOS binary
        output_file: Output file for disassembly
    """
    try:
        # Hopper is typically GUI-based, using hopper-cli if available
        cmd = ['hopper-cli', '--disassemble', binary_path]

        if output_file:
            cmd.extend(['--output', output_file])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        return {
            "success": result.returncode == 0,
            "output": output_file or "interactive",
            "tool": "hopper"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def cycript_hook(bundle_id: str, script: Optional[str] = None) -> Dict[str, Any]:
    """
    Runtime hooking using Cycript

    Args:
        bundle_id: iOS app bundle ID
        script: Cycript script to execute
    """
    try:
        cmd = ['cycript', '-p', bundle_id]

        if script:
            result = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=60)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "stderr": result.stderr,
            "tool": "cycript"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_ios_tools() -> Dict[str, bool]:
    """Check which iOS analysis tools are available"""
    tools = ['class-dump', 'frida-ios-dump', 'objection', 'hopper-cli', 'cycript']

    available = {}
    for tool in tools:
        try:
            result = subprocess.run([tool, '--version'], capture_output=True, timeout=5)
            available[tool] = result.returncode == 0
        except:
            available[tool] = False

    return available
