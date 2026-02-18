#!/usr/bin/env python3
"""Enhanced Binary Analysis Tools - Simple, focused implementations"""

import subprocess
import os
from typing import Dict, Any, List, Optional

def ida_free_analyze(binary_path: str, output_idb: Optional[str] = None) -> Dict[str, Any]:
    """IDA Free binary analysis"""
    try:
        if not output_idb:
            output_idb = binary_path + '.idb'

        cmd = ['idat64', '-A', '-S', '-o', output_idb, binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"success": result.returncode == 0, "idb_file": output_idb, "tool": "ida-free"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def rizin_analyze(binary_path: str, analysis_depth: str = "aa") -> Dict[str, Any]:
    """Rizin reverse engineering framework"""
    try:
        # Run rizin with analysis commands
        rizin_cmds = f"{analysis_depth};afl;pdf"
        cmd = ['rizin', '-q', '-c', rizin_cmds, binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        # Parse function list
        functions = []
        for line in result.stdout.split('\n'):
            if 'fcn.' in line or 'sym.' in line:
                functions.append(line.strip())

        return {"success": result.returncode == 0, "functions_found": len(functions), "output": result.stdout, "tool": "rizin"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def cutter_analyze(binary_path: str, headless: bool = True) -> Dict[str, Any]:
    """Cutter GUI for rizin"""
    try:
        if headless:
            # Use rizin backend in headless mode
            cmd = ['rizin', '-q', '-c', 'aa;afl;s main;pdf', binary_path]
        else:
            cmd = ['cutter', binary_path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return {"success": result.returncode == 0, "output": result.stdout, "headless": headless, "tool": "cutter"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def binary_ninja_analyze(binary_path: str) -> Dict[str, Any]:
    """Binary Ninja free version analysis"""
    try:
        # Use binaryninja python API if available
        try:
            import binaryninja as binja
            bv = binja.open_view(binary_path)
            functions = [f.name for f in bv.functions]
            return {"success": True, "functions": functions, "count": len(functions), "tool": "binary-ninja-free"}
        except ImportError:
            # Fallback to CLI
            cmd = ['binaryninja', '-script', 'list_functions.py', binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return {"success": result.returncode == 0, "output": result.stdout, "tool": "binary-ninja-free"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def ret_sync_setup(debugger: str = "gdb", target: str = "localhost:9100") -> Dict[str, Any]:
    """Reverse engineering synchronization setup"""
    try:
        # Setup ret-sync plugin
        config = {
            "debugger": debugger,
            "sync_target": target,
            "enabled": True
        }

        # For GDB, source the ret-sync script
        if debugger == "gdb":
            gdb_init = os.path.expanduser("~/.gdbinit")
            sync_cmd = "source /usr/share/ret-sync/ext_gdb/sync.py"
            # Check if already configured
            if os.path.exists(gdb_init):
                with open(gdb_init, 'r') as f:
                    if sync_cmd in f.read():
                        return {"success": True, "message": "ret-sync already configured", "config": config, "tool": "ret-sync"}

        return {"success": True, "config": config, "tool": "ret-sync"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def pwndbg_analyze(binary_path: str, breakpoint: Optional[str] = None) -> Dict[str, Any]:
    """GDB with pwndbg for exploit development"""
    try:
        gdb_cmds = [
            'file ' + binary_path,
            'info functions',
            'checksec'
        ]
        if breakpoint:
            gdb_cmds.insert(1, f'break {breakpoint}')

        cmd = ['gdb', '-batch'] + ['-ex ' + cmd for cmd in gdb_cmds]
        result = subprocess.run(' '.join(cmd), shell=True, capture_output=True, text=True, timeout=60)

        # Parse checksec output
        protections = {
            "canary": "Canary" in result.stdout,
            "nx": "NX" in result.stdout,
            "pie": "PIE" in result.stdout,
            "relro": "RELRO" in result.stdout
        }

        return {"success": result.returncode == 0, "protections": protections, "output": result.stdout, "tool": "pwndbg"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def unicorn_emulate(arch: str, code_bytes: bytes, start_addr: int = 0x1000) -> Dict[str, Any]:
    """CPU emulator framework"""
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_ARCH_ARM, UC_MODE_ARM
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX

        # Map architecture
        arch_map = {
            'x86_64': (UC_ARCH_X86, UC_MODE_64),
            'arm': (UC_ARCH_ARM, UC_MODE_ARM)
        }

        if arch not in arch_map:
            return {"success": False, "error": f"Unsupported architecture: {arch}"}

        arch_const, mode_const = arch_map[arch]
        mu = Uc(arch_const, mode_const)

        # Map memory and write code
        mu.mem_map(start_addr, 2 * 1024 * 1024)
        mu.mem_write(start_addr, code_bytes)

        # Emulate
        mu.emu_start(start_addr, start_addr + len(code_bytes))

        return {"success": True, "emulated_bytes": len(code_bytes), "arch": arch, "tool": "unicorn"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def capstone_disassemble(code_bytes: bytes, arch: str = "x86_64") -> Dict[str, Any]:
    """Disassembly framework"""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM

        # Map architecture
        arch_map = {
            'x86_64': (CS_ARCH_X86, CS_MODE_64),
            'arm': (CS_ARCH_ARM, CS_MODE_ARM)
        }

        if arch not in arch_map:
            return {"success": False, "error": f"Unsupported architecture: {arch}"}

        arch_const, mode_const = arch_map[arch]
        md = Cs(arch_const, mode_const)

        # Disassemble
        instructions = []
        for i in md.disasm(code_bytes, 0x1000):
            instructions.append({
                "address": hex(i.address),
                "mnemonic": i.mnemonic,
                "op_str": i.op_str
            })

        return {"success": True, "instructions": instructions, "count": len(instructions), "arch": arch, "tool": "capstone"}
    except Exception as e:
        return {"success": False, "error": str(e)}
