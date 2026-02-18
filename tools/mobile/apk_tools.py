#!/usr/bin/env python3
"""
HexStrike AI - APK Analysis Tools

Android application analysis and reverse engineering tools.
"""

import logging
import subprocess
import os
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def apktool_decompile(apk_path: str, output_dir: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    """
    Decompile APK using apktool

    Args:
        apk_path: Path to APK file
        output_dir: Output directory for decompiled files
        force: Force overwrite existing directory
    """
    try:
        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK file not found: {apk_path}"}

        if output_dir is None:
            output_dir = apk_path.replace('.apk', '_decompiled')

        cmd = ['apktool', 'd', apk_path, '-o', output_dir]
        if force:
            cmd.append('-f')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        return {
            "success": result.returncode == 0,
            "output_dir": output_dir,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tool": "apktool"
        }
    except Exception as e:
        logger.error(f"apktool error: {str(e)}")
        return {"success": False, "error": str(e)}


def jadx_decompile(apk_path: str, output_dir: Optional[str] = None, deobf: bool = True) -> Dict[str, Any]:
    """
    Decompile APK to Java source using JADX

    Args:
        apk_path: Path to APK file
        output_dir: Output directory for Java sources
        deobf: Enable deobfuscation
    """
    try:
        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK file not found: {apk_path}"}

        if output_dir is None:
            output_dir = apk_path.replace('.apk', '_jadx')

        cmd = ['jadx', apk_path, '-d', output_dir]
        if deobf:
            cmd.append('--deobf')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        return {
            "success": result.returncode == 0,
            "output_dir": output_dir,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tool": "jadx"
        }
    except Exception as e:
        logger.error(f"jadx error: {str(e)}")
        return {"success": False, "error": str(e)}


def androguard_analyze(apk_path: str, extract_permissions: bool = True) -> Dict[str, Any]:
    """
    Analyze APK using Androguard Python framework

    Args:
        apk_path: Path to APK file
        extract_permissions: Extract permissions and security info
    """
    try:
        from androguard.core.apk import APK

        apk = APK(apk_path)

        analysis = {
            "success": True,
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "tool": "androguard"
        }

        if extract_permissions:
            analysis["permissions"] = apk.get_permissions()
            analysis["activities"] = apk.get_activities()
            analysis["services"] = apk.get_services()
            analysis["receivers"] = apk.get_receivers()
            analysis["providers"] = apk.get_providers()

        return analysis

    except ImportError:
        return {"success": False, "error": "androguard not installed: pip install androguard"}
    except Exception as e:
        logger.error(f"androguard error: {str(e)}")
        return {"success": False, "error": str(e)}


def mobsf_scan(apk_path: str, mobsf_url: str = "http://localhost:8000") -> Dict[str, Any]:
    """
    Scan APK using Mobile Security Framework (MobSF)

    Args:
        apk_path: Path to APK file
        mobsf_url: MobSF server URL
    """
    try:
        import requests

        # Upload APK
        with open(apk_path, 'rb') as f:
            files = {'file': f}
            upload_response = requests.post(
                f"{mobsf_url}/api/v1/upload",
                files=files,
                timeout=300
            )

        if upload_response.status_code != 200:
            return {"success": False, "error": "Upload failed", "status_code": upload_response.status_code}

        upload_data = upload_response.json()
        scan_hash = upload_data.get('hash')

        # Scan APK
        scan_response = requests.post(
            f"{mobsf_url}/api/v1/scan",
            data={'hash': scan_hash},
            timeout=600
        )

        return {
            "success": scan_response.status_code == 200,
            "scan_results": scan_response.json() if scan_response.status_code == 200 else None,
            "hash": scan_hash,
            "tool": "mobsf"
        }

    except ImportError:
        return {"success": False, "error": "requests not installed"}
    except Exception as e:
        logger.error(f"mobsf error: {str(e)}")
        return {"success": False, "error": str(e)}


def dex2jar_convert(apk_path: str, output_jar: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert APK/DEX to JAR using dex2jar

    Args:
        apk_path: Path to APK or DEX file
        output_jar: Output JAR file path
    """
    try:
        if output_jar is None:
            output_jar = apk_path.replace('.apk', '.jar').replace('.dex', '.jar')

        cmd = ['d2j-dex2jar', apk_path, '-o', output_jar]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        return {
            "success": result.returncode == 0,
            "output_jar": output_jar,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tool": "dex2jar"
        }
    except Exception as e:
        logger.error(f"dex2jar error: {str(e)}")
        return {"success": False, "error": str(e)}


def frida_analyze(package_name: str, script_path: Optional[str] = None, device: str = "usb") -> Dict[str, Any]:
    """
    Dynamic analysis using Frida

    Args:
        package_name: Android package name
        script_path: Path to Frida script (optional)
        device: Device type (usb, tcp, etc.)
    """
    try:
        import frida

        # Get device
        if device == "usb":
            dev = frida.get_usb_device()
        else:
            dev = frida.get_remote_device()

        # Attach to process
        session = dev.attach(package_name)

        if script_path and os.path.exists(script_path):
            with open(script_path) as f:
                script_code = f.read()
            script = session.create_script(script_code)
            script.load()

        return {
            "success": True,
            "device": str(dev),
            "package": package_name,
            "tool": "frida"
        }

    except ImportError:
        return {"success": False, "error": "frida not installed: pip install frida frida-tools"}
    except Exception as e:
        logger.error(f"frida error: {str(e)}")
        return {"success": False, "error": str(e)}


def smali_disassemble(dex_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Disassemble DEX to Smali using baksmali

    Args:
        dex_path: Path to DEX file
        output_dir: Output directory for Smali files
    """
    try:
        if output_dir is None:
            output_dir = dex_path.replace('.dex', '_smali')

        cmd = ['baksmali', 'd', dex_path, '-o', output_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        return {
            "success": result.returncode == 0,
            "output_dir": output_dir,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "tool": "baksmali"
        }
    except Exception as e:
        logger.error(f"baksmali error: {str(e)}")
        return {"success": False, "error": str(e)}


# Tool availability check
def check_mobile_tools() -> Dict[str, bool]:
    """Check which mobile analysis tools are available"""
    tools = {
        'apktool': 'apktool',
        'jadx': 'jadx',
        'dex2jar': 'd2j-dex2jar',
        'baksmali': 'baksmali',
        'frida': 'frida'
    }

    available = {}
    for name, cmd in tools.items():
        try:
            result = subprocess.run([cmd, '--version'], capture_output=True, timeout=5)
            available[name] = result.returncode == 0
        except:
            available[name] = False

    # Check Python packages
    try:
        import androguard
        available['androguard'] = True
    except:
        available['androguard'] = False

    return available
