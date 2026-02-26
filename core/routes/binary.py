"""Binary analysis, reverse engineering, and forensics tool routes Blueprint."""
import subprocess
import shutil
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
binary_bp = Blueprint('binary', __name__)

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
# gdb
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/gdb', methods=['POST'])
def gdb():
    """Execute GDB for binary analysis and debugging."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    if not shutil.which('gdb'):
        return _tool_not_found('gdb')
    commands = params.get('commands', '')
    cmd = ['gdb', '-batch']
    if commands:
        cmd.extend(['-ex', commands])
    cmd.append(binary)
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"gdb error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# radare2
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/radare2', methods=['POST'])
def radare2():
    """Execute Radare2 for binary analysis and reverse engineering."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    if not shutil.which('r2'):
        return _tool_not_found('radare2')
    commands = params.get('commands', 'aa;afl')
    cmd = ['r2', '-q', '-c', commands, binary]
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"radare2 error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# ghidra
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/ghidra', methods=['POST'])
def ghidra():
    """Execute Ghidra headless analysis for reverse engineering."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    if not shutil.which('analyzeHeadless'):
        return _tool_not_found('ghidra')
    project_name = params.get('project_name', 'hexstrike_analysis')
    cmd = ['analyzeHeadless', '/tmp/ghidra_projects', project_name,
           '-import', binary, '-deleteProject']
    try:
        return jsonify(_run(cmd, timeout=600))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"ghidra error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# binwalk
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/binwalk', methods=['POST'])
def binwalk():
    """Execute Binwalk for firmware and embedded file analysis."""
    params = request.json or {}
    file_path = params.get('file_path', '') or params.get('file', '')
    if not file_path:
        return jsonify({"success": False, "error": "file_path is required"}), 400
    if not shutil.which('binwalk'):
        return _tool_not_found('binwalk')
    extract = params.get('extract', False)
    cmd = ['binwalk']
    if extract:
        cmd.append('-e')
    cmd.append(file_path)
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"binwalk error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# checksec
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/checksec', methods=['POST'])
def checksec():
    """Check security mitigations of a binary (ASLR, NX, PIE, Canary, RELRO)."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    if not shutil.which('checksec'):
        return _tool_not_found('checksec')
    cmd = ['checksec', f'--file={binary}']
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"checksec error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/strings', methods=['POST'])
def strings():
    """Extract printable strings from a binary file."""
    params = request.json or {}
    file_path = params.get('file_path', '') or params.get('file', '')
    if not file_path:
        return jsonify({"success": False, "error": "file_path is required"}), 400
    if not shutil.which('strings'):
        return _tool_not_found('strings')
    min_len = params.get('min_len', 4)
    cmd = ['strings', '-n', str(min_len), file_path]
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"strings error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# objdump
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/objdump', methods=['POST'])
def objdump():
    """Analyze a binary using objdump disassembly."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    if not shutil.which('objdump'):
        return _tool_not_found('objdump')
    disassemble = params.get('disassemble', True)
    cmd = ['objdump', '-d' if disassemble else '-x', binary]
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"objdump error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# ropgadget
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/ropgadget', methods=['POST'])
def ropgadget():
    """Search for ROP gadgets in a binary using ROPgadget."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    if not shutil.which('ROPgadget'):
        return _tool_not_found('ROPgadget')
    cmd = ['ROPgadget', '--binary', binary]
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"ropgadget error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# volatility3
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/volatility3', methods=['POST'])
def volatility3():
    """Execute Volatility3 for memory forensics."""
    params = request.json or {}
    memory_file = params.get('memory_file', '')
    if not memory_file:
        return jsonify({"success": False, "error": "memory_file is required"}), 400
    plugin = params.get('plugin', '')
    if not plugin:
        return jsonify({"success": False, "error": "plugin is required"}), 400
    if not shutil.which('vol.py') and not shutil.which('vol'):
        return _tool_not_found('volatility3')
    vol_bin = 'vol.py' if shutil.which('vol.py') else 'vol'
    cmd = [vol_bin, '-f', memory_file, plugin]
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"volatility3 error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# foremost
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/foremost', methods=['POST'])
def foremost():
    """Execute Foremost for file carving and recovery."""
    params = request.json or {}
    input_file = params.get('input_file', '')
    if not input_file:
        return jsonify({"success": False, "error": "input_file is required"}), 400
    if not shutil.which('foremost'):
        return _tool_not_found('foremost')
    output_dir = params.get('output_dir', '/tmp/foremost_output')
    cmd = ['foremost', '-o', output_dir, input_file]
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"foremost error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# steghide
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/steghide', methods=['POST'])
def steghide():
    """Execute Steghide for steganography extraction."""
    params = request.json or {}
    cover_file = params.get('cover_file', '')
    if not cover_file:
        return jsonify({"success": False, "error": "cover_file is required"}), 400
    if not shutil.which('steghide'):
        return _tool_not_found('steghide')
    action = params.get('action', 'extract')
    passphrase = params.get('passphrase', '')
    cmd = ['steghide', action, '-sf', cover_file, '-p', passphrase]
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"steghide error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# exiftool
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/exiftool', methods=['POST'])
def exiftool():
    """Extract metadata from files using ExifTool."""
    params = request.json or {}
    file_path = params.get('file_path', '')
    if not file_path:
        return jsonify({"success": False, "error": "file_path is required"}), 400
    if not shutil.which('exiftool'):
        return _tool_not_found('exiftool')
    cmd = ['exiftool', '-json', file_path]
    try:
        return jsonify(_run(cmd, timeout=60))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"exiftool error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# msfvenom
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/msfvenom', methods=['POST'])
def msfvenom():
    """Generate payloads using MSFVenom."""
    params = request.json or {}
    payload = params.get('payload', '')
    if not payload:
        return jsonify({"success": False, "error": "payload is required"}), 400
    if not shutil.which('msfvenom'):
        return _tool_not_found('msfvenom')
    format_type = params.get('format', '')
    output_file = params.get('output_file', '')
    cmd = ['msfvenom', '-p', payload]
    if format_type:
        cmd.extend(['-f', format_type])
    if output_file:
        cmd.extend(['-o', output_file])
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"msfvenom error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# angr
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/angr', methods=['POST'])
def angr():
    """Execute angr symbolic execution for binary analysis."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    # angr is a Python library; invoke via python -c
    cmd = ['python3', '-c',
           f"import angr; p = angr.Project('{binary}', auto_load_libs=False); "
           f"print('Entry:', hex(p.entry)); print('Arch:', p.arch.name)"]
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"angr error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: rizin (enhanced_binary.py)
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/binary/rizin', methods=['POST'])
def binary_rizin():
    """Execute Rizin reverse engineering framework for binary analysis."""
    params = request.json or {}
    binary = params.get('binary', '')
    if not binary:
        return jsonify({"success": False, "error": "binary is required"}), 400
    analysis_depth = params.get('analysis_depth', 'aa')
    try:
        from tools.binary.enhanced_binary import rizin_analyze
    except ImportError:
        rizin_analyze = None
    if rizin_analyze is not None:
        try:
            result = rizin_analyze(binary_path=binary, analysis_depth=analysis_depth)
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"rizin error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback
    if not shutil.which('rizin'):
        return _tool_not_found('rizin')
    cmd = ['rizin', '-q', '-c', f'{analysis_depth};afl', binary]
    try:
        return jsonify(_run(cmd, timeout=180))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"rizin error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: yara (malware_analysis.py)
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/binary/yara', methods=['POST'])
def binary_yara():
    """Execute YARA pattern matching for malware detection."""
    params = request.json or {}
    file_path = params.get('file', '') or params.get('file_path', '')
    if not file_path:
        return jsonify({"success": False, "error": "file is required"}), 400
    rules = params.get('rules', '')
    try:
        from tools.binary.malware_analysis import yara_scan
    except ImportError:
        yara_scan = None
    if yara_scan is not None:
        try:
            result = yara_scan(target_path=file_path, rules_path=rules or None)
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"yara error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback
    if not shutil.which('yara'):
        return _tool_not_found('yara')
    cmd = ['yara']
    if rules:
        cmd.extend([rules, file_path])
    else:
        cmd.extend(['-r', '/usr/share/yara/', file_path])
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"yara error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: floss (malware_analysis.py)
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/binary/floss', methods=['POST'])
def binary_floss():
    """Execute FLOSS for deobfuscated string extraction from malware samples."""
    params = request.json or {}
    file_path = params.get('file', '') or params.get('file_path', '')
    if not file_path:
        return jsonify({"success": False, "error": "file is required"}), 400
    try:
        from tools.binary.malware_analysis import floss_analyze
    except ImportError:
        floss_analyze = None
    if floss_analyze is not None:
        try:
            result = floss_analyze(binary_path=file_path)
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"floss error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback
    if not shutil.which('floss'):
        return _tool_not_found('floss')
    cmd = ['floss', file_path]
    try:
        return jsonify(_run(cmd, timeout=120))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"floss error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500


# ---------------------------------------------------------------------------
# Phase 3: forensics (forensics.py)
# ---------------------------------------------------------------------------

@binary_bp.route('/api/tools/binary/forensics', methods=['POST'])
def binary_forensics():
    """Execute digital forensics analysis using Autopsy CLI (Sleuth Kit backend)."""
    params = request.json or {}
    image_path = params.get('image_path', '')
    if not image_path:
        return jsonify({"success": False, "error": "image_path is required"}), 400
    case_dir = params.get('case_dir', '/tmp/forensics_case')
    try:
        from tools.binary.forensics import autopsy_cli_analyze
    except ImportError:
        autopsy_cli_analyze = None
    if autopsy_cli_analyze is not None:
        try:
            result = autopsy_cli_analyze(case_dir=case_dir, image_path=image_path)
            return jsonify(result)
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
        except Exception as e:
            logger.error(f"forensics error: {e}")
            return jsonify({"success": False, "error": str(e), "output": ""}), 500
    # Fallback: use fls from Sleuth Kit
    if not shutil.which('fls'):
        return _tool_not_found('fls (sleuthkit)')
    cmd = ['fls', '-r', image_path]
    try:
        return jsonify(_run(cmd, timeout=300))
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Command timed out", "output": ""}), 408
    except Exception as e:
        logger.error(f"forensics error: {e}")
        return jsonify({"success": False, "error": str(e), "output": ""}), 500
