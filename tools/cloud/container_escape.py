#!/usr/bin/env python3
"""Container Escape and Security Tools - Simple, focused implementations"""

import subprocess
import json
from typing import Dict, Any, Optional

def deepce_scan(output_file: Optional[str] = None) -> Dict[str, Any]:
    """Docker enumeration and escape detection"""
    try:
        cmd = ['deepce.sh']
        if output_file:
            cmd.extend(['>', output_file])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, shell=True)

        # Parse output for key findings
        findings = []
        for line in result.stdout.split('\n'):
            if 'POTENTIALLY VULNERABLE' in line.upper() or 'DANGEROUS' in line.upper():
                findings.append(line.strip())

        return {"success": result.returncode == 0, "findings": findings, "output": result.stdout, "tool": "deepce"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def amicontained_check() -> Dict[str, Any]:
    """Container introspection and capability check"""
    try:
        cmd = ['amicontained']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # Parse container runtime info
        info = {
            "runtime": "",
            "capabilities": [],
            "namespaces": [],
            "seccomp": ""
        }

        for line in result.stdout.split('\n'):
            if 'Container Runtime:' in line:
                info["runtime"] = line.split(':')[-1].strip()
            elif 'CAP_' in line:
                info["capabilities"].append(line.strip())
            elif 'namespace' in line.lower():
                info["namespaces"].append(line.strip())
            elif 'seccomp' in line.lower():
                info["seccomp"] = line.strip()

        return {"success": result.returncode == 0, "container_info": info, "tool": "amicontained"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def docker_escape_scanner() -> Dict[str, Any]:
    """Docker escape vulnerability scanner"""
    try:
        escape_checks = []

        # Check 1: Privileged mode
        try:
            with open('/proc/self/status', 'r') as f:
                if 'CapEff:\tffffffffffffffff' in f.read():
                    escape_checks.append({"check": "privileged_mode", "vulnerable": True, "risk": "high"})
        except:
            pass

        # Check 2: Docker socket mounted
        import os
        if os.path.exists('/var/run/docker.sock'):
            escape_checks.append({"check": "docker_socket_mounted", "vulnerable": True, "risk": "critical"})

        # Check 3: Writable cgroup
        cgroup_paths = ['/sys/fs/cgroup', '/proc/1/cgroup']
        for path in cgroup_paths:
            if os.path.exists(path) and os.access(path, os.W_OK):
                escape_checks.append({"check": "writable_cgroup", "path": path, "vulnerable": True, "risk": "high"})

        # Check 4: /proc/sys writable
        if os.path.exists('/proc/sys') and os.access('/proc/sys', os.W_OK):
            escape_checks.append({"check": "writable_proc_sys", "vulnerable": True, "risk": "medium"})

        return {"success": True, "escape_vectors": escape_checks, "total_checks": len(escape_checks), "tool": "docker-escape-scanner"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def cdk_evaluate(mode: str = "evaluate") -> Dict[str, Any]:
    """Container penetration toolkit"""
    try:
        cmd = ['cdk', mode]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Parse CDK output
        findings = []
        for line in result.stdout.split('\n'):
            if '[!!!]' in line or '[!]' in line:
                findings.append(line.strip())

        return {"success": result.returncode == 0, "mode": mode, "findings": findings, "output": result.stdout, "tool": "cdk"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def peirates_recon(kubeconfig: Optional[str] = None) -> Dict[str, Any]:
    """Kubernetes penetration testing"""
    try:
        # Peirates interactive mode - run basic recon
        cmd = ['peirates', '-non-interactive']
        if kubeconfig:
            cmd.extend(['-kubeconfig', kubeconfig])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, input='1\n')

        # Parse reconnaissance results
        recon_data = {
            "pods": [],
            "services": [],
            "secrets": [],
            "permissions": []
        }

        for line in result.stdout.split('\n'):
            if 'pod' in line.lower() and 'name' in line.lower():
                recon_data["pods"].append(line.strip())
            elif 'service' in line.lower():
                recon_data["services"].append(line.strip())
            elif 'secret' in line.lower():
                recon_data["secrets"].append(line.strip())
            elif 'permission' in line.lower() or 'rbac' in line.lower():
                recon_data["permissions"].append(line.strip())

        return {"success": result.returncode == 0, "reconnaissance": recon_data, "tool": "peirates"}
    except Exception as e:
        return {"success": False, "error": str(e)}
