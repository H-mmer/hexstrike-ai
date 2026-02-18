#!/usr/bin/env python3
"""RF Security Tools"""

import logging
import subprocess
from typing import Dict, Any

logger = logging.getLogger(__name__)


def rtl_sdr_scan(frequency: float = 100e6, sample_rate: int = 2048000) -> Dict[str, Any]:
    """RTL-SDR frequency scanning"""
    try:
        cmd = ['rtl_power', '-f', f'{frequency}M', '-s', str(sample_rate), '-']
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return {
            "success": True,
            "pid": process.pid,
            "frequency": frequency,
            "sample_rate": sample_rate,
            "tool": "rtl-sdr"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def hackrf_sweep(start_freq: float = 1e6, end_freq: float = 6e9) -> Dict[str, Any]:
    """HackRF spectrum sweeping"""
    try:
        cmd = ['hackrf_sweep', '-f', f'{start_freq}:{end_freq}']
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return {
            "success": True,
            "pid": process.pid,
            "range": f"{start_freq/1e6:.1f}MHz - {end_freq/1e9:.1f}GHz",
            "tool": "hackrf-tools"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def gqrx_analyze(center_freq: float = 100e6) -> Dict[str, Any]:
    """GQRX SDR analyzer"""
    try:
        return {
            "success": True,
            "center_frequency": center_freq,
            "mode": "Interactive GUI",
            "instructions": [
                "1. Launch GQRX",
                "2. Select SDR device",
                f"3. Set frequency to {center_freq/1e6:.1f} MHz",
                "4. Adjust gain and demodulation"
            ],
            "tool": "gqrx"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
