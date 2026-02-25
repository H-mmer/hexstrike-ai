# hexstrike_mcp_tools/cloud.py
"""MCP tool registrations for cloud security tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import mcp, get_client


@mcp.tool()
def trivy_scan(target: str, scan_type: str = "image",
               output_format: str = "json", severity: str = "") -> Dict[str, Any]:
    """Scan a container image or filesystem for vulnerabilities using Trivy.
    scan_type: image, fs, repo"""
    return get_client().safe_post("api/tools/trivy", {
        "target": target, "scan_type": scan_type,
        "output_format": output_format, "severity": severity,
    })


@mcp.tool()
def prowler_scan(provider: str = "aws", profile: str = "",
                 region: str = "", checks: str = "") -> Dict[str, Any]:
    """Run Prowler cloud security assessment. provider: aws, azure, gcp."""
    return get_client().safe_post("api/tools/prowler", {
        "provider": provider, "profile": profile,
        "region": region, "checks": checks,
    })


@mcp.tool()
def kube_hunter_scan(target: str = "", cidr: str = "", active: bool = False) -> Dict[str, Any]:
    """Hunt for Kubernetes security weaknesses with kube-hunter."""
    return get_client().safe_post("api/tools/kube-hunter", {
        "target": target, "cidr": cidr, "active": active,
    })


@mcp.tool()
def kube_bench_check(targets: str = "", version: str = "") -> Dict[str, Any]:
    """Check Kubernetes configuration against CIS benchmarks with kube-bench."""
    return get_client().safe_post("api/tools/kube-bench", {
        "targets": targets, "version": version,
    })


@mcp.tool()
def checkov_scan(directory: str = ".", framework: str = "") -> Dict[str, Any]:
    """Scan IaC files for misconfigurations with Checkov. framework: terraform, k8s, cloudformation."""
    return get_client().safe_post("api/tools/checkov", {
        "directory": directory, "framework": framework,
    })


@mcp.tool()
def terrascan_scan(scan_type: str = "all", iac_dir: str = ".") -> Dict[str, Any]:
    """Scan IaC files for policy violations with Terrascan."""
    return get_client().safe_post("api/tools/terrascan", {
        "scan_type": scan_type, "iac_dir": iac_dir,
    })


@mcp.tool()
def kubescape_assessment(target: str = "cluster", framework: str = "nsa") -> Dict[str, Any]:
    """Assess Kubernetes security posture with Kubescape (NSA/MITRE frameworks)."""
    return get_client().safe_post("api/tools/cloud/kubescape", {
        "target": target, "framework": framework,
    })


@mcp.tool()
def container_escape_check(technique: str = "deepce") -> Dict[str, Any]:
    """Check for container escape vulnerabilities and misconfigurations."""
    return get_client().safe_post("api/tools/cloud/container-escape", {
        "technique": technique,
    })


@mcp.tool()
def kubernetes_rbac_audit(namespace: str = "") -> Dict[str, Any]:
    """Audit Kubernetes RBAC bindings for over-privileged roles and escalation paths."""
    return get_client().safe_post("api/tools/cloud/rbac-audit", {
        "namespace": namespace,
    })
