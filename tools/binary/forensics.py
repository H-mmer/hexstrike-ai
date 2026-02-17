#!/usr/bin/env python3
"""Digital Forensics Tools - Simple, focused implementations"""

import subprocess
import os
from typing import Dict, Any, Optional

def autopsy_cli_analyze(case_dir: str, image_path: str) -> Dict[str, Any]:
    """Digital forensics platform - CLI mode"""
    try:
        # Create case if it doesn't exist
        if not os.path.exists(case_dir):
            os.makedirs(case_dir)

        # Use Sleuth Kit for analysis (Autopsy backend)
        cmd = ['fls', '-r', image_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Count files
        file_count = len([line for line in result.stdout.split('\n') if line.strip()])

        return {"success": result.returncode == 0, "files_found": file_count, "output": result.stdout, "tool": "autopsy-cli"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def plaso_timeline(image_path: str, output_file: Optional[str] = None) -> Dict[str, Any]:
    """Timeline analysis with plaso/log2timeline"""
    try:
        if not output_file:
            output_file = image_path + '.plaso'

        # Run log2timeline
        cmd = ['log2timeline.py', output_file, image_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

        # Generate timeline
        timeline_file = output_file + '.csv'
        if os.path.exists(output_file):
            psort_cmd = ['psort.py', '-o', 'l2tcsv', '-w', timeline_file, output_file]
            subprocess.run(psort_cmd, capture_output=True, text=True, timeout=300)

        return {"success": result.returncode == 0, "plaso_file": output_file, "timeline": timeline_file, "tool": "plaso"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def rekall_memory_analyze(memory_dump: str, profile: Optional[str] = None) -> Dict[str, Any]:
    """Memory forensics with Rekall"""
    try:
        # Run Rekall analysis
        if profile:
            cmd = ['rekall', '-f', memory_dump, '--profile', profile, 'pslist']
        else:
            # Auto-detect profile
            cmd = ['rekall', '-f', memory_dump, 'pslist']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        # Parse process list
        processes = []
        for line in result.stdout.split('\n'):
            if '.exe' in line or 'PID' in line:
                processes.append(line.strip())

        return {"success": result.returncode == 0, "processes": processes, "count": len(processes), "tool": "rekall"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def ftk_imager_acquire(source: str, dest: str, image_type: str = "E01") -> Dict[str, Any]:
    """Forensic imaging with FTK Imager CLI"""
    try:
        # Use ewfacquire (libewf) as FTK Imager alternative
        cmd = ['ewfacquire', '-t', dest, '-f', image_type.lower(), source]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        return {"success": result.returncode == 0, "source": source, "destination": dest, "format": image_type, "tool": "ftk-imager-cli"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def dc3dd_image(source: str, dest: str, hash_type: str = "md5") -> Dict[str, Any]:
    """Enhanced dd for forensic imaging"""
    try:
        cmd = ['dc3dd', f'if={source}', f'of={dest}', f'hash={hash_type}', 'log=dc3dd.log']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)

        # Read hash from log
        hash_value = None
        if os.path.exists('dc3dd.log'):
            with open('dc3dd.log', 'r') as f:
                for line in f:
                    if hash_type in line.lower():
                        hash_value = line.split(':')[-1].strip()

        return {"success": result.returncode == 0, "source": source, "dest": dest, "hash": hash_value, "tool": "dc3dd"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def guymager_info(device: str) -> Dict[str, Any]:
    """Forensic imager device info"""
    try:
        # Get device information
        cmd = ['lsblk', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,MODEL', device]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        device_info = {
            "device": device,
            "info": result.stdout
        }

        # Get SMART data if available
        smart_cmd = ['smartctl', '-a', device]
        smart_result = subprocess.run(smart_cmd, capture_output=True, text=True, timeout=30)
        if smart_result.returncode == 0:
            device_info["smart_data"] = smart_result.stdout

        return {"success": result.returncode == 0, "device_info": device_info, "tool": "guymager"}
    except Exception as e:
        return {"success": False, "error": str(e)}
