#!/usr/bin/env python3
"""API Monitoring Tools"""

import logging
import requests
import time
from typing import Dict, Any

logger = logging.getLogger(__name__)


def api_trace_analyzer(target: str, duration: int = 60) -> Dict[str, Any]:
    """Analyze API traffic patterns"""
    try:
        start_time = time.time()
        traces = []
        
        while time.time() - start_time < duration:
            resp = requests.get(target, timeout=5)
            traces.append({
                "timestamp": time.time(),
                "status": resp.status_code,
                "response_time": resp.elapsed.total_seconds(),
                "headers": dict(resp.headers)
            })
            time.sleep(1)
        
        avg_response_time = sum(t["response_time"] for t in traces) / len(traces)
        
        return {
            "success": True,
            "total_requests": len(traces),
            "avg_response_time": avg_response_time,
            "traces": traces[:10],  # Sample
            "tool": "api-trace-analyzer"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def rate_limit_tester(target: str, requests_per_second: int = 10) -> Dict[str, Any]:
    """Test API rate limiting"""
    try:
        rate_limited = False
        request_count = 0
        
        start = time.time()
        while time.time() - start < 10:  # 10 second test
            resp = requests.get(target, timeout=2)
            request_count += 1
            
            if resp.status_code == 429:
                rate_limited = True
                break
            
            time.sleep(1/requests_per_second)
        
        return {
            "success": True,
            "rate_limit_detected": rate_limited,
            "requests_sent": request_count,
            "rate": f"{requests_per_second}/sec",
            "tool": "rate-limit-tester"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
