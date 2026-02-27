"""Cloud security tool routes Blueprint."""
import subprocess
import shutil
import logging
# Cloud targets are image names/paths, not network targets — skip is_valid_target

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
cloud_bp = Blueprint('cloud', __name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_not_found(tool_name: str):
    """Return a standard 'tool not installed' response (503 Service Unavailable)."""
    return jsonify({
        "success": False,
        "error": f"{tool_name} is not installed or not on PATH",
        "output": "",
    }), 503


def _run(cmd: list, timeout: int = 120):
    """Execute a command list and return a JSON-serialisable result dict."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        "success": result.returncode == 0,
        "output": result.stdout,
        "error": result.stderr,
    }


# ---------------------------------------------------------------------------
# trivy
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/trivy', methods=['POST'])
def trivy():
    """Execute Trivy for container/filesystem vulnerability scanning."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('trivy'):
        return _tool_not_found('trivy')
    scan_type = params.get('scan_type', 'image')
    output_format = params.get('output_format', 'json')
    severity = params.get('severity', '')
    cmd = ['trivy', scan_type]
    if output_format:
        cmd.extend(['--format', output_format])
    if severity:
        cmd.extend(['--severity', severity])
    cmd.append(target)
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"trivy error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# prowler
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/prowler', methods=['POST'])
def prowler():
    """Execute Prowler for cloud security assessment."""
    params = request.json or {}
    if not shutil.which('prowler'):
        return _tool_not_found('prowler')
    provider = params.get('provider', 'aws')
    profile = params.get('profile', '')
    region = params.get('region', '')
    checks = params.get('checks', '')
    cmd = ['prowler', provider]
    if profile:
        cmd.extend(['--profile', profile])
    if region:
        cmd.extend(['--region', region])
    if checks:
        cmd.extend(['--checks', checks])
    try:
        return jsonify(_run(cmd, timeout=600))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"prowler error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# kube-hunter
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/kube-hunter', methods=['POST'])
def kube_hunter():
    """Execute kube-hunter for Kubernetes penetration testing."""
    params = request.json or {}
    if not shutil.which('kube-hunter'):
        return _tool_not_found('kube-hunter')
    target = params.get('target', '')
    cidr = params.get('cidr', '')
    active = params.get('active', False)
    cmd = ['kube-hunter', '--report', 'json']
    if target:
        cmd.extend(['--remote', target])
    elif cidr:
        cmd.extend(['--cidr', cidr])
    else:
        cmd.append('--pod')
    if active:
        cmd.append('--active')
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"kube-hunter error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# kube-bench
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/kube-bench', methods=['POST'])
def kube_bench():
    """Execute kube-bench for CIS Kubernetes benchmark checks."""
    params = request.json or {}
    if not shutil.which('kube-bench'):
        return _tool_not_found('kube-bench')
    targets = params.get('targets', '')
    version = params.get('version', '')
    cmd = ['kube-bench', '--json']
    if targets:
        cmd.extend(['--targets', targets])
    if version:
        cmd.extend(['--version', version])
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"kube-bench error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# docker-bench-security
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/docker-bench-security', methods=['POST'])
def docker_bench_security():
    """Execute Docker Bench Security for Docker configuration assessment."""
    params = request.json or {}
    if not shutil.which('docker-bench-security'):
        return _tool_not_found('docker-bench-security')
    checks = params.get('checks', '')
    cmd = ['docker-bench-security']
    if checks:
        cmd.extend(['-c', checks])
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"docker-bench-security error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# scout-suite
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/scout-suite', methods=['POST'])
def scout_suite():
    """Execute Scout Suite for multi-cloud security assessment."""
    params = request.json or {}
    if not shutil.which('scout'):
        return _tool_not_found('scout-suite')
    provider = params.get('provider', 'aws')
    profile = params.get('profile', '')
    services = params.get('services', '')
    cmd = ['scout', provider]
    if profile:
        cmd.extend(['--profile', profile])
    if services:
        cmd.extend(['--services', services])
    try:
        return jsonify(_run(cmd, timeout=600))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"scout-suite error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# cloudmapper
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/cloudmapper', methods=['POST'])
def cloudmapper():
    """Execute CloudMapper for AWS network visualization and analysis."""
    params = request.json or {}
    if not shutil.which('cloudmapper'):
        return _tool_not_found('cloudmapper')
    action = params.get('action', 'collect')
    account = params.get('account', '')
    if not account and action != 'webserver':
        return jsonify({"success": False, "error": "account is required for this action"}), 400
    cmd = ['cloudmapper', action]
    if account:
        cmd.extend(['--account', account])
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"cloudmapper error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# pacu
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/pacu', methods=['POST'])
def pacu():
    """Execute Pacu for AWS exploitation framework."""
    params = request.json or {}
    if not shutil.which('pacu'):
        return _tool_not_found('pacu')
    session_name = params.get('session_name', 'hexstrike_session')
    modules = params.get('modules', '')
    cmd = ['pacu', '--session', session_name]
    if modules:
        cmd.extend(['--module', modules])
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"pacu error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# falco
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/falco', methods=['POST'])
def falco():
    """Execute Falco for runtime security monitoring."""
    params = request.json or {}
    if not shutil.which('falco'):
        return _tool_not_found('falco')
    config_file = params.get('config_file', '/etc/falco/falco.yaml')
    duration = params.get('duration', 60)
    cmd = ['timeout', str(duration), 'falco', '--config', config_file, '--json']
    try:
        return jsonify(_run(cmd, timeout=duration + 10))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"falco error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# checkov
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/checkov', methods=['POST'])
def checkov():
    """Execute Checkov for IaC security scanning."""
    params = request.json or {}
    if not shutil.which('checkov'):
        return _tool_not_found('checkov')
    directory = params.get('directory', '.')
    framework = params.get('framework', '')
    cmd = ['checkov', '-d', directory, '--output', 'json']
    if framework:
        cmd.extend(['--framework', framework])
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"checkov error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# terrascan
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/terrascan', methods=['POST'])
def terrascan():
    """Execute Terrascan for IaC security scanning."""
    params = request.json or {}
    if not shutil.which('terrascan'):
        return _tool_not_found('terrascan')
    scan_type = params.get('scan_type', 'all')
    iac_dir = params.get('iac_dir', '.')
    cmd = ['terrascan', 'scan', '-t', scan_type, '-d', iac_dir, '-o', 'json']
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"terrascan error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: kubescape (cloud_native.py)
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/cloud/kubescape', methods=['POST'])
def cloud_kubescape():
    """Execute Kubescape for Kubernetes security assessment (NSA/MITRE frameworks)."""
    params = request.json or {}
    target = params.get('target', '')
    framework = params.get('framework', 'nsa')
    try:
        from tools.cloud.cloud_native import kubescape_scan
    except ImportError:
        kubescape_scan = None
    if kubescape_scan is not None:
        try:
            result = kubescape_scan(target=target or None, framework=framework)
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"kubescape error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback: direct subprocess
    if not shutil.which('kubescape'):
        return _tool_not_found('kubescape')
    cmd = ['kubescape', 'scan', 'framework', framework, '--format', 'json']
    if target:
        cmd.append(target)
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"kubescape error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: container-escape (container_escape.py)
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/cloud/container-escape', methods=['POST'])
def cloud_container_escape():
    """Execute container escape detection and enumeration tools."""
    params = request.json or {}
    technique = params.get('technique', 'deepce')
    try:
        from tools.cloud.container_escape import deepce_scan
    except ImportError:
        deepce_scan = None
    if deepce_scan is not None:
        try:
            result = deepce_scan()
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"container-escape error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback
    if not shutil.which('deepce.sh') and not shutil.which('amicontained'):
        return _tool_not_found('deepce/amicontained')
    cmd = ['amicontained'] if shutil.which('amicontained') else ['deepce.sh']
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"container-escape error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: rbac-audit (cloud_native.py)
# ---------------------------------------------------------------------------

@cloud_bp.route('/api/tools/cloud/rbac-audit', methods=['POST'])
def cloud_rbac_audit():
    """Audit Kubernetes RBAC bindings and privilege escalation paths."""
    params = request.json or {}
    namespace = params.get('namespace', '')
    try:
        from tools.cloud.cloud_native import rbac_police_audit
    except ImportError:
        rbac_police_audit = None
    if rbac_police_audit is not None:
        try:
            result = rbac_police_audit(namespace=namespace or None)
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"rbac-audit error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback
    if not shutil.which('kubectl'):
        return _tool_not_found('kubectl')
    cmd = ['kubectl', 'get', 'clusterrolebindings', '-o', 'json']
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"rbac-audit error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500
