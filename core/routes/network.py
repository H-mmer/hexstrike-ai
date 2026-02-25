"""Network and reconnaissance tool routes Blueprint."""
import subprocess
import shutil
from flask import Blueprint, request, jsonify
import logging

logger = logging.getLogger(__name__)
network_bp = Blueprint('network', __name__)


def _tool_not_found(tool_name: str):
    """Return a standard 'tool not installed' response."""
    return jsonify({
        "success": False,
        "error": f"{tool_name} is not installed or not on PATH",
        "output": ""
    })


def _run(cmd: list, timeout: int = 120):
    """Execute a command list and return a JSON-serialisable result dict."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        "success": result.returncode == 0,
        "output": result.stdout,
        "error": result.stderr,
    }


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/nmap', methods=['POST'])
def nmap():
    """Execute nmap port scan."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('nmap'):
        return _tool_not_found('nmap')
    scan_type = params.get('scan_type', '-sCV')
    ports = params.get('ports', '')
    additional_args = params.get('additional_args', '-T4 -Pn')
    cmd = ['nmap']
    cmd.extend(scan_type.split())
    if ports:
        cmd.extend(['-p', ports])
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(target)
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"nmap error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# nmap-advanced
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/nmap-advanced', methods=['POST'])
def nmap_advanced():
    """Execute advanced nmap scan with NSE scripts and custom timing."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('nmap'):
        return _tool_not_found('nmap')
    scan_type = params.get('scan_type', '-sS')
    ports = params.get('ports', '')
    timing = params.get('timing', 'T4')
    nse_scripts = params.get('nse_scripts', '')
    os_detection = params.get('os_detection', False)
    version_detection = params.get('version_detection', False)
    aggressive = params.get('aggressive', False)
    stealth = params.get('stealth', False)
    additional_args = params.get('additional_args', '')
    cmd = ['nmap']
    cmd.extend(scan_type.split())
    if ports:
        cmd.extend(['-p', ports])
    if stealth:
        cmd.extend(['-T2', '-f', '--mtu', '24'])
    else:
        cmd.append(f'-{timing}')
    if os_detection:
        cmd.append('-O')
    if version_detection:
        cmd.append('-sV')
    if aggressive:
        cmd.append('-A')
    if nse_scripts:
        cmd.append(f'--script={nse_scripts}')
    elif not aggressive:
        cmd.append('--script=default,discovery,safe')
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(target)
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"nmap-advanced error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# rustscan
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/rustscan', methods=['POST'])
def rustscan():
    """Execute rustscan ultra-fast port scanner."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('rustscan'):
        return _tool_not_found('rustscan')
    ports = params.get('ports', '')
    ulimit = params.get('ulimit', 5000)
    batch_size = params.get('batch_size', 4500)
    scan_timeout = params.get('timeout', 1500)
    additional_args = params.get('additional_args', '')
    cmd = ['rustscan', '-a', target, '--ulimit', str(ulimit), '-b', str(batch_size), '-t', str(scan_timeout)]
    if ports:
        cmd.extend(['-p', ports])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"rustscan error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# masscan
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/masscan', methods=['POST'])
def masscan():
    """Execute masscan high-speed port scanner."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('masscan'):
        return _tool_not_found('masscan')
    ports = params.get('ports', '1-1000')
    rate = params.get('rate', 1000)
    interface = params.get('interface', '')
    banners = params.get('banners', False)
    additional_args = params.get('additional_args', '')
    cmd = ['masscan', target, f'-p{ports}', f'--rate={rate}']
    if interface:
        cmd.extend(['-e', interface])
    if banners:
        cmd.append('--banners')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"masscan error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/amass', methods=['POST'])
def amass():
    """Execute amass subdomain enumeration."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('amass'):
        return _tool_not_found('amass')
    mode = params.get('mode', 'enum')
    passive = params.get('passive', True)
    additional_args = params.get('additional_args', '')
    cmd = ['amass', mode, '-d', domain]
    if passive and mode == 'enum':
        cmd.append('-passive')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"amass error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/subfinder', methods=['POST'])
def subfinder():
    """Execute subfinder passive subdomain enumeration."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('subfinder'):
        return _tool_not_found('subfinder')
    silent = params.get('silent', True)
    all_sources = params.get('all_sources', False)
    additional_args = params.get('additional_args', '')
    cmd = ['subfinder', '-d', domain]
    if silent:
        cmd.append('-silent')
    if all_sources:
        cmd.append('-all')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"subfinder error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/httpx', methods=['POST'])
def httpx():
    """Execute httpx fast HTTP probing."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('httpx'):
        return _tool_not_found('httpx')
    threads = params.get('threads', 50)
    status_code = params.get('status_code', True)
    title = params.get('title', True)
    tech_detect = params.get('tech_detect', False)
    web_server = params.get('web_server', False)
    additional_args = params.get('additional_args', '')
    cmd = ['httpx', '-silent', '-t', str(threads)]
    if status_code:
        cmd.append('-sc')
    if title:
        cmd.append('-title')
    if tech_detect:
        cmd.append('-tech-detect')
    if web_server:
        cmd.append('-server')
    # target can be a URL passed directly via stdin-equivalent flag or -u
    cmd.extend(['-u', target])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"httpx error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# waybackurls
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/waybackurls', methods=['POST'])
def waybackurls():
    """Execute waybackurls historical URL discovery."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('waybackurls'):
        return _tool_not_found('waybackurls')
    get_versions = params.get('get_versions', False)
    no_subs = params.get('no_subs', False)
    additional_args = params.get('additional_args', '')
    cmd = ['waybackurls', domain]
    if get_versions:
        cmd.append('--get-versions')
    if no_subs:
        cmd.append('--no-subs')
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"waybackurls error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# gau
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/gau', methods=['POST'])
def gau():
    """Execute gau (Get All URLs) for URL discovery from multiple sources."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('gau'):
        return _tool_not_found('gau')
    providers = params.get('providers', '')
    include_subs = params.get('include_subs', True)
    blacklist = params.get('blacklist', '')
    additional_args = params.get('additional_args', '')
    cmd = ['gau', domain]
    if providers:
        cmd.extend(['--providers', providers])
    if include_subs:
        cmd.append('--subs')
    if blacklist:
        cmd.extend(['--blacklist', blacklist])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"gau error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# dnsenum
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/dnsenum', methods=['POST'])
def dnsenum():
    """Execute dnsenum DNS enumeration."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('dnsenum'):
        return _tool_not_found('dnsenum')
    dns_server = params.get('dns_server', '')
    wordlist = params.get('wordlist', '')
    additional_args = params.get('additional_args', '--noreverse')
    cmd = ['dnsenum', domain]
    if dns_server:
        cmd.extend(['--dnsserver', dns_server])
    if wordlist:
        cmd.extend(['--file', wordlist])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"dnsenum error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# fierce
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/fierce', methods=['POST'])
def fierce():
    """Execute fierce DNS reconnaissance."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    if not shutil.which('fierce'):
        return _tool_not_found('fierce')
    dns_server = params.get('dns_server', '')
    additional_args = params.get('additional_args', '')
    cmd = ['fierce', '--domain', domain]
    if dns_server:
        cmd.extend(['--dns-servers', dns_server])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"fierce error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# wafw00f
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/wafw00f', methods=['POST'])
def wafw00f():
    """Execute wafw00f WAF detection and fingerprinting."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('wafw00f'):
        return _tool_not_found('wafw00f')
    additional_args = params.get('additional_args', '')
    cmd = ['wafw00f', target]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"wafw00f error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# enum4linux
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/enum4linux', methods=['POST'])
def enum4linux():
    """Execute enum4linux SMB/Windows enumeration."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('enum4linux'):
        return _tool_not_found('enum4linux')
    additional_args = params.get('additional_args', '-a')
    cmd = ['enum4linux']
    if additional_args:
        cmd.extend(additional_args.split())
    cmd.append(target)
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"enum4linux error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# enum4linux-ng
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/enum4linux-ng', methods=['POST'])
def enum4linux_ng():
    """Execute enum4linux-ng advanced SMB enumeration."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('enum4linux-ng'):
        return _tool_not_found('enum4linux-ng')
    username = params.get('username', '')
    password = params.get('password', '')
    domain = params.get('domain', '')
    additional_args = params.get('additional_args', '')
    cmd = ['enum4linux-ng', target]
    if username:
        cmd.extend(['-u', username])
    if password:
        cmd.extend(['-p', password])
    if domain:
        cmd.extend(['-d', domain])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"enum4linux-ng error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# smbmap
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/smbmap', methods=['POST'])
def smbmap():
    """Execute smbmap SMB share enumeration."""
    params = request.json or {}
    host = params.get('host', '') or params.get('target', '')
    if not host:
        return jsonify({"success": False, "error": "host is required"}), 400
    if not shutil.which('smbmap'):
        return _tool_not_found('smbmap')
    username = params.get('username', '')
    password = params.get('password', '')
    domain = params.get('domain', '')
    additional_args = params.get('additional_args', '')
    cmd = ['smbmap', '-H', host]
    if username:
        cmd.extend(['-u', username])
    if password:
        cmd.extend(['-p', password])
    if domain:
        cmd.extend(['-d', domain])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"smbmap error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# netexec (nxc)
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/netexec', methods=['POST'])
def netexec():
    """Execute netexec (nxc) network protocol authentication and enumeration."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('nxc'):
        return _tool_not_found('nxc')
    protocol = params.get('protocol', 'smb')
    username = params.get('username', '')
    password = params.get('password', '')
    hash_value = params.get('hash', '')
    module = params.get('module', '')
    additional_args = params.get('additional_args', '')
    cmd = ['nxc', protocol, target]
    if username:
        cmd.extend(['-u', username])
    if password:
        cmd.extend(['-p', password])
    if hash_value:
        cmd.extend(['-H', hash_value])
    if module:
        cmd.extend(['-M', module])
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"netexec error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# nbtscan
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/nbtscan', methods=['POST'])
def nbtscan():
    """Execute nbtscan NetBIOS name scanner."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('nbtscan'):
        return _tool_not_found('nbtscan')
    verbose = params.get('verbose', False)
    scan_timeout = params.get('timeout', 2)
    additional_args = params.get('additional_args', '')
    cmd = ['nbtscan', '-t', str(scan_timeout)]
    if verbose:
        cmd.append('-v')
    cmd.append(target)
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"nbtscan error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# autorecon
# ---------------------------------------------------------------------------

@network_bp.route('/api/tools/autorecon', methods=['POST'])
def autorecon():
    """Execute autorecon comprehensive automated reconnaissance."""
    params = request.json or {}
    target = params.get('target', '')
    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400
    if not shutil.which('autorecon'):
        return _tool_not_found('autorecon')
    output_dir = params.get('output_dir', '/tmp/autorecon')
    heartbeat = params.get('heartbeat', 60)
    scan_timeout = params.get('timeout', 300)
    additional_args = params.get('additional_args', '')
    cmd = ['autorecon', target, '-o', output_dir, '--heartbeat', str(heartbeat), '--timeout', str(scan_timeout)]
    if additional_args:
        cmd.extend(additional_args.split())
    try:
        return jsonify(_run(cmd, timeout=360))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""})
    except Exception as e:
        logger.error(f"autorecon error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500
