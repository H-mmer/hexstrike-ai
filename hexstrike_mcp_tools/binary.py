# hexstrike_mcp_tools/binary.py
"""MCP tool registrations for binary analysis, reverse engineering, and forensics tools."""
from typing import Dict, Any, Optional
from hexstrike_mcp_tools import get_client


def gdb_debug(binary: str, commands: str = "") -> Dict[str, Any]:
    """Debug and analyze a binary with GDB. commands: GDB commands to execute (e.g. 'info functions')."""
    return get_client().safe_post("api/tools/gdb", {
        "binary": binary, "commands": commands,
    })


def ghidra_analyze(binary: str, project_name: str = "hexstrike_analysis") -> Dict[str, Any]:
    """Decompile and reverse engineer a binary with Ghidra headless analysis."""
    return get_client().safe_post("api/tools/ghidra", {
        "binary": binary, "project_name": project_name,
    })


def binwalk_scan(file: str, extract: bool = False) -> Dict[str, Any]:
    """Scan firmware or binary for embedded files and signatures using Binwalk."""
    return get_client().safe_post("api/tools/binwalk", {
        "file_path": file, "extract": extract,
    })


def checksec_binary(binary: str) -> Dict[str, Any]:
    """Check security mitigations on a binary (NX, PIE, ASLR, Canary, RELRO)."""
    return get_client().safe_post("api/tools/checksec", {"binary": binary})


def objdump_disassemble(binary: str, disassemble: bool = True) -> Dict[str, Any]:
    """Disassemble or dump headers from a binary using objdump."""
    return get_client().safe_post("api/tools/objdump", {
        "binary": binary, "disassemble": disassemble,
    })


def strings_extract(file_path: str, min_len: int = 4) -> Dict[str, Any]:
    """Extract readable strings from a binary file."""
    return get_client().safe_post("api/tools/strings", {
        "file_path": file_path, "min_len": min_len,
    })


def volatility3_memory(memory_file: str, plugin: str) -> Dict[str, Any]:
    """Perform memory forensics with Volatility3. plugin: e.g. 'windows.pslist', 'linux.pslist'."""
    return get_client().safe_post("api/tools/volatility3", {
        "memory_file": memory_file, "plugin": plugin,
    })


def foremost_carve(input_file: str, output_dir: str = "/tmp/foremost_output") -> Dict[str, Any]:
    """Recover files from disk images or memory dumps using Foremost."""
    return get_client().safe_post("api/tools/foremost", {
        "input_file": input_file, "output_dir": output_dir,
    })


def yara_malware_scan(file: str, rules: str = "") -> Dict[str, Any]:
    """Scan a file for malware patterns using YARA rules."""
    return get_client().safe_post("api/tools/binary/yara", {
        "file": file, "rules": rules,
    })


def floss_string_extract(file: str) -> Dict[str, Any]:
    """Extract deobfuscated strings from a malware binary using FLOSS."""
    return get_client().safe_post("api/tools/binary/floss", {"file": file})


def rizin_analyze(binary: str, analysis_depth: str = "aa") -> Dict[str, Any]:
    """Analyze a binary with the Rizin reverse engineering framework."""
    return get_client().safe_post("api/tools/binary/rizin", {
        "binary": binary, "analysis_depth": analysis_depth,
    })


def forensics_analyze(image_path: str, case_dir: str = "/tmp/forensics_case") -> Dict[str, Any]:
    """Run digital forensics analysis on a disk image using Autopsy/Sleuth Kit."""
    return get_client().safe_post("api/tools/binary/forensics", {
        "image_path": image_path, "case_dir": case_dir,
    })
