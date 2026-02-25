"""CTF competition workflow routes Blueprint."""
import re
import subprocess
import logging
from dataclasses import dataclass, field
from dataclasses import asdict as _asdict
from datetime import datetime
from typing import Dict, Any, List

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
ctf_bp = Blueprint('ctf', __name__)

# ---------------------------------------------------------------------------
# Optional agent imports
# ---------------------------------------------------------------------------

try:
    from agents.ctf_manager import CTFWorkflowManager
    _CTF_MANAGER_AVAILABLE = True
except ImportError:
    _CTF_MANAGER_AVAILABLE = False

try:
    from agents.ctf_tools import CTFToolManager
    _CTF_TOOLS_AVAILABLE = True
except ImportError:
    _CTF_TOOLS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data models (self-contained copies so Blueprint has no server dependency)
# ---------------------------------------------------------------------------

@dataclass
class CTFChallenge:
    """CTF challenge information."""
    name: str
    category: str = "misc"   # web, crypto, pwn, forensics, rev, misc, osint
    description: str = ""
    points: int = 0
    difficulty: str = "unknown"  # easy, medium, hard, insane
    target: str = ""
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return _asdict(self)


# ---------------------------------------------------------------------------
# Module-level singletons (lazy-initialised to avoid import-time failures)
# ---------------------------------------------------------------------------

_ctf_manager = None
_ctf_tools = None


def _get_ctf_manager():
    global _ctf_manager
    if _ctf_manager is None and _CTF_MANAGER_AVAILABLE:
        _ctf_manager = CTFWorkflowManager()
    return _ctf_manager


def _get_ctf_tools():
    global _ctf_tools
    if _ctf_tools is None and _CTF_TOOLS_AVAILABLE:
        _ctf_tools = CTFToolManager()
    return _ctf_tools


# ---------------------------------------------------------------------------
# Lightweight CTFChallengeAutomator fallback (for when server class absent)
# ---------------------------------------------------------------------------

class _SimpleCTFAutomator:
    """Minimal automator used when the full server automator is not available."""

    def auto_solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        mgr = _get_ctf_manager()
        if mgr is None:
            return {"status": "not_available", "error": "CTF manager not available"}
        workflow = mgr.create_ctf_challenge_workflow(challenge)
        return {
            "status": "workflow_generated",
            "challenge": challenge.name,
            "category": challenge.category,
            "workflow_steps": len(workflow.get("strategies", [])),
            "estimated_time": workflow.get("estimated_time", 0),
            "workflow": workflow,
        }


class _SimpleCTFCoordinator:
    """Minimal team coordinator used when the full server class is not available."""

    def optimize_team_strategy(
        self,
        challenges: List[CTFChallenge],
        team_skills: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        mgr = _get_ctf_manager()
        if mgr is None:
            return {"error": "CTF manager not available"}

        assignments: List[Dict[str, Any]] = []
        members = list(team_skills.keys()) if team_skills else ["member_1"]
        for i, ch in enumerate(challenges):
            workflow = mgr.create_ctf_challenge_workflow(ch)
            assignments.append({
                "challenge": ch.name,
                "category": ch.category,
                "assigned_to": members[i % len(members)],
                "workflow": workflow,
            })

        return {
            "total_challenges": len(challenges),
            "team_size": len(team_skills),
            "assignments": assignments,
            "strategy": "round_robin",
        }


_ctf_automator = _SimpleCTFAutomator()
_ctf_coordinator = _SimpleCTFCoordinator()


# ---------------------------------------------------------------------------
# Helper — FileUpload framework (lightweight inline)
# ---------------------------------------------------------------------------

class _FileUploadFramework:
    def create_upload_testing_workflow(self, target_url: str) -> Dict[str, Any]:
        return {
            "target_url": target_url,
            "test_phases": [
                {"phase": "extension_bypass", "tests": ["rename .php -> .php.jpg", "null byte injection"]},
                {"phase": "content_type_bypass", "tests": ["change MIME type", "polyglot files"]},
                {"phase": "directory_traversal", "tests": ["../../../etc/passwd", "..%2F..%2F"]},
            ],
            "estimated_time": 120,
        }

    def generate_test_files(self) -> List[Dict[str, str]]:
        return [
            {"filename": "test.jpg.php", "content_type": "image/jpeg", "purpose": "extension bypass"},
            {"filename": "shell.php%00.jpg", "content_type": "image/jpeg", "purpose": "null byte bypass"},
            {"filename": "polyglot.php", "content_type": "image/gif", "purpose": "polyglot file"},
        ]


_fileupload_framework = _FileUploadFramework()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@ctf_bp.route("/api/ctf/create-challenge-workflow", methods=["POST"])
def create_ctf_challenge_workflow():
    """Create specialized workflow for CTF challenge."""
    try:
        params = request.json or {}
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")

        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400

        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target,
        )

        mgr = _get_ctf_manager()
        if mgr is None:
            return jsonify({"success": False, "error": "CTF agent not available"}), 503

        workflow = mgr.create_ctf_challenge_workflow(challenge)

        logger.info(f"CTF workflow created for {challenge_name} | Category: {category}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating CTF workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@ctf_bp.route("/api/ctf/auto-solve-challenge", methods=["POST"])
def auto_solve_ctf_challenge():
    """Attempt to automatically solve a CTF challenge."""
    try:
        params = request.json or {}
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")

        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400

        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target,
        )

        result = _ctf_automator.auto_solve_challenge(challenge)

        logger.info(f"CTF auto-solve attempted for {challenge_name} | Status: {result.get('status')}")
        return jsonify({
            "success": True,
            "solve_result": result,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in CTF auto-solve: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@ctf_bp.route("/api/ctf/team-strategy", methods=["POST"])
def create_ctf_team_strategy():
    """Create optimal team strategy for CTF competition."""
    try:
        params = request.json or {}
        challenges_data = params.get("challenges", [])
        team_skills = params.get("team_skills", {})

        if not challenges_data:
            return jsonify({"error": "Challenges data is required"}), 400

        challenges = [
            CTFChallenge(
                name=cd.get("name", ""),
                category=cd.get("category", "misc"),
                difficulty=cd.get("difficulty", "unknown"),
                points=cd.get("points", 100),
                description=cd.get("description", ""),
                target=cd.get("target", ""),
            )
            for cd in challenges_data
        ]

        strategy = _ctf_coordinator.optimize_team_strategy(challenges, team_skills)

        logger.info(f"CTF team strategy created | Challenges: {len(challenges)}")
        return jsonify({
            "success": True,
            "strategy": strategy,
            "challenges_count": len(challenges),
            "team_size": len(team_skills),
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error creating CTF team strategy: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@ctf_bp.route("/api/ctf/suggest-tools", methods=["POST"])
def suggest_ctf_tools():
    """Suggest optimal tools for CTF challenge based on description and category."""
    try:
        params = request.json or {}
        description = params.get("description", "")
        category = params.get("category", "misc")

        if not description:
            return jsonify({"error": "Challenge description is required"}), 400

        tools_mgr = _get_ctf_tools()
        if tools_mgr is None:
            return jsonify({"success": False, "error": "CTF tools agent not available"}), 503

        suggested_tools = tools_mgr.suggest_tools_for_challenge(description, category)
        category_tools = tools_mgr.get_category_tools(f"{category}_recon")

        tool_commands = {}
        for tool in suggested_tools:
            try:
                tool_commands[tool] = tools_mgr.get_tool_command(tool, "TARGET")
            except Exception:
                tool_commands[tool] = f"{tool} TARGET"

        logger.info(f"CTF tools suggested | Category: {category} | Tools: {len(suggested_tools)}")
        return jsonify({
            "success": True,
            "suggested_tools": suggested_tools,
            "category_tools": category_tools,
            "tool_commands": tool_commands,
            "category": category,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error suggesting CTF tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@ctf_bp.route("/api/ctf/cryptography-solver", methods=["POST"])
def ctf_cryptography_solver():
    """Advanced cryptography challenge solver with multiple attack methods."""
    try:
        params = request.json or {}
        cipher_text = params.get("cipher_text", "")
        cipher_type = params.get("cipher_type", "unknown")
        key_hint = params.get("key_hint", "")
        known_plaintext = params.get("known_plaintext", "")
        additional_info = params.get("additional_info", "")

        if not cipher_text:
            return jsonify({"error": "Cipher text is required"}), 400

        results: Dict[str, Any] = {
            "cipher_text": cipher_text,
            "cipher_type": cipher_type,
            "analysis_results": [],
            "potential_solutions": [],
            "recommended_tools": [],
            "next_steps": [],
        }

        # Cipher type identification
        if cipher_type == "unknown":
            if re.match(r'^[0-9a-fA-F]+$', cipher_text.replace(' ', '')):
                results["analysis_results"].append("Possible hexadecimal encoding")
                results["recommended_tools"].extend(["hex", "xxd"])

            if re.match(r'^[A-Za-z0-9+/]+=*$', cipher_text.replace(' ', '')):
                results["analysis_results"].append("Possible Base64 encoding")
                results["recommended_tools"].append("base64")

            if len(set(cipher_text.upper().replace(' ', ''))) <= 26:
                results["analysis_results"].append("Possible substitution cipher")
                results["recommended_tools"].extend(["frequency-analysis", "substitution-solver"])

        # Hash identification
        hash_patterns = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
        clean_text = cipher_text.replace(' ', '').replace('\n', '')
        if len(clean_text) in hash_patterns and re.match(r'^[0-9a-fA-F]+$', clean_text):
            hash_type = hash_patterns[len(clean_text)]
            results["analysis_results"].append(f"Possible {hash_type} hash")
            results["recommended_tools"].extend(["hashcat", "john", "hash-identifier"])

        # Frequency analysis
        if cipher_type in ["substitution", "caesar", "vigenere"] or "substitution" in results["analysis_results"]:
            char_freq: Dict[str, int] = {}
            for char in cipher_text.upper():
                if char.isalpha():
                    char_freq[char] = char_freq.get(char, 0) + 1
            if char_freq:
                most_common = max(char_freq, key=lambda k: char_freq[k])
                results["analysis_results"].append(
                    f"Most frequent character: {most_common} ({char_freq[most_common]} occurrences)"
                )
                results["next_steps"].append("Try substituting most frequent character with 'E'")

        # ROT/Caesar
        if cipher_type == "caesar" or len(set(cipher_text.upper().replace(' ', ''))) <= 26:
            results["recommended_tools"].append("rot13")
            results["next_steps"].append("Try all ROT values (1-25)")

        # RSA
        if cipher_type == "rsa" or "rsa" in additional_info.lower():
            results["recommended_tools"].extend(["rsatool", "factordb", "yafu"])
            results["next_steps"].extend([
                "Check if modulus can be factored",
                "Look for small public exponent attacks",
                "Check for common modulus attacks",
            ])

        # Vigenere
        if cipher_type == "vigenere" or "vigenere" in additional_info.lower():
            results["recommended_tools"].append("vigenere-solver")
            results["next_steps"].extend([
                "Perform Kasiski examination for key length",
                "Use index of coincidence analysis",
                "Try common key words",
            ])

        logger.info(f"CTF crypto analysis completed | Type: {cipher_type}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in CTF crypto solver: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@ctf_bp.route("/api/ctf/forensics-analyzer", methods=["POST"])
def ctf_forensics_analyzer():
    """Advanced forensics challenge analyzer with multiple investigation techniques."""
    try:
        params = request.json or {}
        file_path = params.get("file_path", "")
        analysis_type = params.get("analysis_type", "comprehensive")
        extract_hidden = params.get("extract_hidden", True)
        check_steganography = params.get("check_steganography", True)

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        results: Dict[str, Any] = {
            "file_path": file_path,
            "analysis_type": analysis_type,
            "file_info": {},
            "metadata": {},
            "hidden_data": [],
            "steganography_results": [],
            "recommended_tools": [],
            "next_steps": [],
        }

        # Basic file analysis
        try:
            file_result = subprocess.run(
                ["file", file_path], capture_output=True, text=True, timeout=30
            )
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()
                file_type = file_result.stdout.lower()
                if "image" in file_type:
                    results["recommended_tools"].extend(["exiftool", "steghide", "stegsolve", "zsteg"])
                    results["next_steps"].extend([
                        "Extract EXIF metadata",
                        "Check for steganographic content",
                        "Analyze color channels separately",
                    ])
                elif "audio" in file_type:
                    results["recommended_tools"].extend(["audacity", "sonic-visualizer", "spectrum-analyzer"])
                    results["next_steps"].extend([
                        "Analyze audio spectrum",
                        "Check for hidden data in audio channels",
                        "Look for DTMF tones or morse code",
                    ])
                elif "pdf" in file_type:
                    results["recommended_tools"].extend(["pdfinfo", "pdftotext", "binwalk"])
                    results["next_steps"].extend([
                        "Extract text and metadata",
                        "Check for embedded files",
                        "Analyze PDF structure",
                    ])
                elif "zip" in file_type or "archive" in file_type:
                    results["recommended_tools"].extend(["unzip", "7zip", "binwalk"])
                    results["next_steps"].extend([
                        "Extract archive contents",
                        "Check for password protection",
                        "Look for hidden files",
                    ])
        except Exception as e:
            results["file_info"]["error"] = str(e)

        # Metadata extraction
        try:
            exif_result = subprocess.run(
                ["exiftool", file_path], capture_output=True, text=True, timeout=30
            )
            if exif_result.returncode == 0:
                results["metadata"]["exif"] = exif_result.stdout
        except Exception as e:
            results["metadata"]["exif_error"] = str(e)

        # Binwalk analysis
        if extract_hidden:
            try:
                binwalk_result = subprocess.run(
                    ["binwalk", "-e", file_path], capture_output=True, text=True, timeout=60
                )
                if binwalk_result.returncode == 0:
                    results["hidden_data"].append({
                        "tool": "binwalk",
                        "output": binwalk_result.stdout,
                    })
            except Exception as e:
                results["hidden_data"].append({"tool": "binwalk", "error": str(e)})

        # Steganography checks
        if check_steganography:
            steg_tools = ["steghide", "zsteg", "outguess"]
            for tool in steg_tools:
                try:
                    if tool == "steghide":
                        steg_result = subprocess.run(
                            [tool, "info", file_path], capture_output=True, text=True, timeout=30
                        )
                    elif tool == "zsteg":
                        steg_result = subprocess.run(
                            [tool, "-a", file_path], capture_output=True, text=True, timeout=30
                        )
                    else:
                        steg_result = subprocess.run(
                            [tool, "-r", file_path, "/tmp/outguess_output"],
                            capture_output=True, text=True, timeout=30,
                        )
                    if steg_result.returncode == 0 and steg_result.stdout.strip():
                        results["steganography_results"].append({
                            "tool": tool, "output": steg_result.stdout
                        })
                except Exception as e:
                    results["steganography_results"].append({"tool": tool, "error": str(e)})

        # Strings analysis
        try:
            strings_result = subprocess.run(
                ["strings", file_path], capture_output=True, text=True, timeout=30
            )
            if strings_result.returncode == 0:
                interesting = [
                    line.strip()
                    for line in strings_result.stdout.split("\n")
                    if any(kw in line.lower() for kw in ["flag", "password", "key", "secret", "http", "ftp"])
                ]
                if interesting:
                    results["hidden_data"].append({
                        "tool": "strings",
                        "interesting_strings": interesting[:20],
                    })
        except Exception as e:
            results["hidden_data"].append({"tool": "strings", "error": str(e)})

        logger.info(f"CTF forensics analysis completed | File: {file_path}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in CTF forensics analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@ctf_bp.route("/api/ctf/binary-analyzer", methods=["POST"])
def ctf_binary_analyzer():
    """Advanced binary analysis for reverse engineering and pwn challenges."""
    try:
        params = request.json or {}
        binary_path = params.get("binary_path", "")
        analysis_depth = params.get("analysis_depth", "comprehensive")
        check_protections = params.get("check_protections", True)
        find_gadgets = params.get("find_gadgets", True)

        if not binary_path:
            return jsonify({"error": "Binary path is required"}), 400

        results: Dict[str, Any] = {
            "binary_path": binary_path,
            "analysis_depth": analysis_depth,
            "file_info": {},
            "security_protections": {},
            "interesting_functions": [],
            "strings_analysis": {},
            "gadgets": [],
            "recommended_tools": [],
            "exploitation_hints": [],
        }

        # Basic file information
        try:
            file_result = subprocess.run(
                ["file", binary_path], capture_output=True, text=True, timeout=30
            )
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()
                file_output = file_result.stdout.lower()
                if "x86-64" in file_output or "x86_64" in file_output:
                    results["file_info"]["architecture"] = "x86_64"
                elif "i386" in file_output or "80386" in file_output:
                    results["file_info"]["architecture"] = "i386"
                elif "arm" in file_output:
                    results["file_info"]["architecture"] = "ARM"
                results["recommended_tools"].extend(["gdb-peda", "radare2", "ghidra"])
        except Exception as e:
            results["file_info"]["error"] = str(e)

        # Security protections
        if check_protections:
            try:
                checksec_result = subprocess.run(
                    ["checksec", "--file", binary_path], capture_output=True, text=True, timeout=30
                )
                if checksec_result.returncode == 0:
                    results["security_protections"]["checksec"] = checksec_result.stdout
                    output = checksec_result.stdout.lower()
                    if "no canary found" in output:
                        results["exploitation_hints"].append(
                            "Stack canary disabled - buffer overflow exploitation possible"
                        )
                    if "nx disabled" in output:
                        results["exploitation_hints"].append(
                            "NX disabled - shellcode execution on stack possible"
                        )
                    if "no pie" in output:
                        results["exploitation_hints"].append(
                            "PIE disabled - fixed addresses, ROP/ret2libc easier"
                        )
                    if "no relro" in output:
                        results["exploitation_hints"].append(
                            "RELRO disabled - GOT overwrite attacks possible"
                        )
            except Exception as e:
                results["security_protections"]["error"] = str(e)

        # Strings analysis
        try:
            strings_result = subprocess.run(
                ["strings", binary_path], capture_output=True, text=True, timeout=30
            )
            if strings_result.returncode == 0:
                interesting_categories: Dict[str, List[str]] = {
                    "functions": [],
                    "format_strings": [],
                    "file_paths": [],
                    "potential_flags": [],
                    "system_calls": [],
                }
                for string in strings_result.stdout.split("\n"):
                    string = string.strip()
                    if not string:
                        continue
                    if any(func in string for func in ["printf", "scanf", "gets", "strcpy", "system", "execve"]):
                        interesting_categories["functions"].append(string)
                    if "%" in string and any(fmt in string for fmt in ["%s", "%d", "%x", "%n"]):
                        interesting_categories["format_strings"].append(string)
                    if string.startswith("/") or "\\" in string:
                        interesting_categories["file_paths"].append(string)
                    if any(kw in string.lower() for kw in ["flag", "ctf", "key", "password"]):
                        interesting_categories["potential_flags"].append(string)
                    if string in ["sh", "bash", "/bin/sh", "/bin/bash", "cmd.exe"]:
                        interesting_categories["system_calls"].append(string)
                results["strings_analysis"] = interesting_categories

                dangerous_funcs = ["gets", "strcpy", "sprintf", "scanf"]
                found_dangerous = [
                    f for f in dangerous_funcs
                    if any(f in s for s in interesting_categories["functions"])
                ]
                if found_dangerous:
                    results["exploitation_hints"].append(
                        f"Dangerous functions found: {', '.join(found_dangerous)} - potential buffer overflow"
                    )
                if any("%n" in s for s in interesting_categories["format_strings"]):
                    results["exploitation_hints"].append(
                        "Format string with %n found - potential format string vulnerability"
                    )
        except Exception as e:
            results["strings_analysis"] = {"error": str(e)}

        # ROP gadgets
        if find_gadgets and analysis_depth in ["comprehensive", "deep"]:
            try:
                rop_result = subprocess.run(
                    ["ROPgadget", "--binary", binary_path, "--only", "pop|ret"],
                    capture_output=True, text=True, timeout=60,
                )
                if rop_result.returncode == 0:
                    useful_gadgets = [
                        line.strip()
                        for line in rop_result.stdout.split("\n")
                        if "pop" in line and "ret" in line
                    ]
                    results["gadgets"] = useful_gadgets[:20]
                    if useful_gadgets:
                        results["exploitation_hints"].append(
                            f"Found {len(useful_gadgets)} ROP gadgets - ROP chain exploitation possible"
                        )
                        results["recommended_tools"].append("ropper")
            except Exception as e:
                results["gadgets"] = [f"Error finding gadgets: {str(e)}"]

        # Function analysis
        if analysis_depth in ["comprehensive", "deep"]:
            try:
                objdump_result = subprocess.run(
                    ["objdump", "-t", binary_path], capture_output=True, text=True, timeout=30
                )
                if objdump_result.returncode == 0:
                    functions = [
                        parts[-1]
                        for line in objdump_result.stdout.split("\n")
                        if "F .text" in line
                        for parts in [line.split()]
                        if len(parts) >= 6
                    ]
                    results["interesting_functions"] = functions[:50]
            except Exception as e:
                results["interesting_functions"] = [f"Error analyzing functions: {str(e)}"]

        if results["exploitation_hints"]:
            results["recommended_tools"].extend(["pwntools", "gdb-peda", "one-gadget"])
        if "format string" in str(results["exploitation_hints"]).lower():
            results["recommended_tools"].append("format-string-exploiter")

        logger.info(f"CTF binary analysis completed | Binary: {binary_path}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in CTF binary analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
