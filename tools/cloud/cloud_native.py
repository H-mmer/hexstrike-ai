#!/usr/bin/env python3
"""Cloud-Native Security Tools - Simple, focused implementations"""

import subprocess
import json
from typing import Dict, Any, Optional

def kubescape_scan(target: Optional[str] = None, framework: str = "nsa") -> Dict[str, Any]:
    """Kubernetes security scanner"""
    try:
        if target:
            cmd = ['kubescape', 'scan', 'framework', framework, target, '--format', 'json']
        else:
            cmd = ['kubescape', 'scan', 'framework', framework, '--format', 'json']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"success": result.returncode == 0, "framework": framework, "output": result.stdout, "tool": "kubescape"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def popeye_scan(namespace: Optional[str] = None) -> Dict[str, Any]:
    """Kubernetes cluster sanitizer"""
    try:
        cmd = ['popeye', '--save', '--output-file', '/tmp/popeye-report.json']
        if namespace:
            cmd.extend(['-n', namespace])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        # Read report
        try:
            with open('/tmp/popeye-report.json', 'r') as f:
                report = json.load(f)
        except:
            report = {}

        return {"success": result.returncode == 0, "namespace": namespace, "report": report, "tool": "popeye"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def rbac_police_audit(namespace: Optional[str] = None) -> Dict[str, Any]:
    """RBAC security auditor"""
    try:
        cmd = ['kubectl', 'rbac-lookup', '--output', 'wide']
        if namespace:
            cmd.extend(['-n', namespace])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Parse RBAC bindings
        bindings = []
        for line in result.stdout.split('\n')[1:]:  # Skip header
            if line.strip():
                bindings.append(line.strip())

        return {"success": result.returncode == 0, "namespace": namespace, "bindings": bindings, "tool": "rbac-police"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def kubesec_scan(manifest_file: str) -> Dict[str, Any]:
    """Kubernetes manifest security scanner"""
    try:
        cmd = ['kubesec', 'scan', manifest_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        try:
            scan_results = json.loads(result.stdout)
        except:
            scan_results = result.stdout

        return {"success": result.returncode == 0, "manifest": manifest_file, "results": scan_results, "tool": "kubesec"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def aws_vault_list(profile: Optional[str] = None) -> Dict[str, Any]:
    """AWS credential management and enumeration"""
    try:
        if profile:
            cmd = ['aws-vault', 'exec', profile, '--', 'aws', 'sts', 'get-caller-identity']
        else:
            cmd = ['aws-vault', 'list']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"success": result.returncode == 0, "profile": profile, "output": result.stdout, "tool": "aws-vault"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def azure_security_scan(subscription_id: Optional[str] = None) -> Dict[str, Any]:
    """Azure security scanner"""
    try:
        # Use az cli for security scanning
        if subscription_id:
            cmd = ['az', 'security', 'assessment', 'list', '--subscription', subscription_id, '--output', 'json']
        else:
            cmd = ['az', 'security', 'assessment', 'list', '--output', 'json']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        try:
            assessments = json.loads(result.stdout)
        except:
            assessments = []

        # Count findings by severity
        findings = {"high": 0, "medium": 0, "low": 0}
        for assessment in assessments:
            if isinstance(assessment, dict):
                status = assessment.get('status', {}).get('severity', 'low').lower()
                if status in findings:
                    findings[status] += 1

        return {"success": result.returncode == 0, "subscription": subscription_id, "findings": findings, "tool": "azure-security-scan"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def gcp_firewall_enum(project_id: str) -> Dict[str, Any]:
    """GCP firewall enumeration"""
    try:
        cmd = ['gcloud', 'compute', 'firewall-rules', 'list', '--project', project_id, '--format', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        try:
            firewall_rules = json.loads(result.stdout)
        except:
            firewall_rules = []

        # Analyze rules for security issues
        issues = []
        for rule in firewall_rules:
            if isinstance(rule, dict):
                # Check for overly permissive rules
                if '0.0.0.0/0' in str(rule.get('sourceRanges', [])):
                    issues.append({
                        "rule": rule.get('name'),
                        "issue": "allows_all_ips",
                        "ports": rule.get('allowed', [])
                    })

        return {"success": result.returncode == 0, "project": project_id, "rules_found": len(firewall_rules), "issues": issues, "tool": "gcp-firewall-enum"}
    except Exception as e:
        return {"success": False, "error": str(e)}
