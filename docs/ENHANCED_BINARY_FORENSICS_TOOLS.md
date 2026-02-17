# Enhanced Binary Analysis & Digital Forensics Tools

HexStrike AI Phase 3: Advanced binary analysis, malware analysis, and digital forensics tools.

## Enhanced Binary Analysis (8 tools)

### ida-free
IDA Free binary analysis and disassembly.
```python
from tools.binary.enhanced_binary import ida_free_analyze
result = ida_free_analyze("/path/to/binary", output_idb="analysis.idb")
```

### rizin
Reverse engineering framework (successor to radare2).
```python
from tools.binary.enhanced_binary import rizin_analyze
result = rizin_analyze("/path/to/binary", analysis_depth="aaa")
print(f"Found {result['functions_found']} functions")
```

### cutter
GUI for rizin with advanced analysis features.

### binary-ninja-free
Binary analysis platform with free version support.

### ret-sync
Reverse engineering synchronization between debugger and disassembler.

### pwndbg
Enhanced GDB plugin for exploit development.
```python
from tools.binary.enhanced_binary import pwndbg_analyze
result = pwndbg_analyze("/path/to/binary", breakpoint="main")
print(f"Protections: {result['protections']}")
```

### unicorn
CPU emulator framework for binary analysis.
```python
from tools.binary.enhanced_binary import unicorn_emulate
code_bytes = b"\x48\x35\xef\xbe\xad\xde"  # x86_64 shellcode
result = unicorn_emulate("x86_64", code_bytes)
```

### capstone
Disassembly framework supporting multiple architectures.
```python
from tools.binary.enhanced_binary import capstone_disassemble
code_bytes = b"\x55\x48\x89\xe5"  # x86_64: push rbp; mov rbp, rsp
result = capstone_disassemble(code_bytes, arch="x86_64")
for insn in result['instructions']:
    print(f"{insn['address']}: {insn['mnemonic']} {insn['op_str']}")
```

## Malware Analysis (6 tools)

### cuckoo-sandbox
Automated malware analysis sandbox.
```python
from tools.binary.malware_analysis import cuckoo_sandbox_submit
result = cuckoo_sandbox_submit("malware.exe", timeout=120)
print(f"Task ID: {result['task_id']}")
```

### yara
Pattern matching engine for malware detection.
```python
from tools.binary.malware_analysis import yara_scan
result = yara_scan("/path/to/sample", rules_path="malware.yar")
print(f"Matches: {result['count']}")
```

### pestudio
Static malware analysis (PE file analysis).
```python
from tools.binary.malware_analysis import pestudio_analyze
result = pestudio_analyze("sample.exe")
print(f"Suspicious imports: {result['analysis']['imports']}")
```

### strings-extended
Enhanced string extraction with categorization.
```python
from tools.binary.malware_analysis import strings_extended
result = strings_extended("malware.exe", min_length=4, encoding="all")
print(f"URLs found: {result['strings']['urls']}")
print(f"IPs found: {result['strings']['ips']}")
```

### floss
FireEye Labs Obfuscated String Solver.
```python
from tools.binary.malware_analysis import floss_analyze
result = floss_analyze("obfuscated_malware.exe")
```

### hollows-hunter
Process hollowing and injection detection.
```python
from tools.binary.malware_analysis import hollows_hunter_scan
result = hollows_hunter_scan(scan_all=True)
print(f"Detections: {result['count']}")
```

## Digital Forensics (6 tools)

### autopsy-cli
Digital forensics platform (Sleuth Kit backend).
```python
from tools.binary.forensics import autopsy_cli_analyze
result = autopsy_cli_analyze("case_dir", "disk.img")
print(f"Files found: {result['files_found']}")
```

### plaso
Super timeline analysis (log2timeline).
```python
from tools.binary.forensics import plaso_timeline
result = plaso_timeline("disk.img", output_file="timeline.plaso")
print(f"Timeline: {result['timeline']}")
```

### rekall
Memory forensics framework.
```python
from tools.binary.forensics import rekall_memory_analyze
result = rekall_memory_analyze("memory.dump", profile="Win7SP1x64")
print(f"Processes: {result['count']}")
```

### ftk-imager-cli
Forensic imaging with FTK Imager.
```python
from tools.binary.forensics import ftk_imager_acquire
result = ftk_imager_acquire("/dev/sda", "evidence.E01", image_type="E01")
```

### dc3dd
Enhanced dd for forensic imaging with hashing.
```python
from tools.binary.forensics import dc3dd_image
result = dc3dd_image("/dev/sda", "disk.img", hash_type="md5")
print(f"Hash: {result['hash']}")
```

### guymager
Forensic imager with device information.
```python
from tools.binary.forensics import guymager_info
result = guymager_info("/dev/sda")
print(result['device_info']['info'])
```

## Usage Examples

### Complete Binary Analysis
```python
from tools.binary.enhanced_binary import rizin_analyze, pwndbg_analyze, capstone_disassemble

# 1. Static analysis with rizin
rizin_result = rizin_analyze("/path/to/binary", analysis_depth="aaa")

# 2. Check security protections
pwndbg_result = pwndbg_analyze("/path/to/binary")
print(f"ASLR: {pwndbg_result['protections']['pie']}")
print(f"NX: {pwndbg_result['protections']['nx']}")

# 3. Disassemble specific code
with open("/path/to/binary", "rb") as f:
    code = f.read(100)
capstone_result = capstone_disassemble(code, arch="x86_64")
```

### Malware Investigation
```python
from tools.binary.malware_analysis import yara_scan, strings_extended, pestudio_analyze, cuckoo_sandbox_submit

# 1. YARA signature scan
yara_result = yara_scan("suspicious.exe", rules_path="malware_rules.yar")

# 2. String analysis
strings_result = strings_extended("suspicious.exe", min_length=6)
print(f"Found {len(strings_result['strings']['urls'])} URLs")

# 3. PE analysis
pe_result = pestudio_analyze("suspicious.exe")

# 4. Dynamic analysis (if suspicious)
if yara_result['count'] > 0:
    cuckoo_task = cuckoo_sandbox_submit("suspicious.exe", timeout=180)
    print(f"Sandbox task: {cuckoo_task['task_id']}")
```

### Digital Forensics Investigation
```python
from tools.binary.forensics import dc3dd_image, plaso_timeline, rekall_memory_analyze

# 1. Acquire disk image
disk_img = dc3dd_image("/dev/sda", "evidence.img", hash_type="sha256")
print(f"Disk hash: {disk_img['hash']}")

# 2. Create timeline
timeline = plaso_timeline("evidence.img")
print(f"Timeline created: {timeline['timeline']}")

# 3. Memory analysis
memory_result = rekall_memory_analyze("memory.dump")
for proc in memory_result['processes']:
    print(proc)
```

### Incident Response Workflow
```python
from tools.binary.forensics import guymager_info, dc3dd_image, autopsy_cli_analyze
from tools.binary.malware_analysis import hollows_hunter_scan

# 1. Check for process injection
injection_scan = hollows_hunter_scan(scan_all=True)
if injection_scan['count'] > 0:
    print("⚠️ Process injection detected!")

# 2. Acquire system information
device_info = guymager_info("/dev/sda")

# 3. Create forensic image
forensic_img = dc3dd_image("/dev/sda", "incident_evidence.img", hash_type="sha256")

# 4. Analyze filesystem
autopsy_result = autopsy_cli_analyze("incident_case", "incident_evidence.img")
```

## Tool Count
**20 enhanced binary analysis and forensics tools** across reverse engineering, malware analysis, and digital forensics domains.

## Safety Notice
⚠️ **WARNING**: Malware analysis tools should ONLY be used in isolated environments:
- Use virtual machines with snapshots
- Disable network access for malware execution
- Never analyze malware on production systems
- Follow proper chain of custody for forensic evidence

These tools are for authorized security research and incident response only.
