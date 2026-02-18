# Mobile Security Tools

HexStrike AI Phase 2: Mobile application security testing tools for Android and iOS.

## Android APK Analysis (8 tools)

### apktool
Decompile and recompile Android APK files.
```python
from tools.mobile.apk_tools import apktool_decompile
result = apktool_decompile("app.apk", output_dir="./decompiled")
```

### jadx
Convert DEX to Java source code.
```python
from tools.mobile.apk_tools import jadx_decompile
result = jadx_decompile("app.apk", deobf=True)
```

### androguard
Python-based Android app analysis.
```python
from tools.mobile.apk_tools import androguard_analyze
result = androguard_analyze("app.apk", extract_permissions=True)
```

### mobsf
Mobile Security Framework - automated static/dynamic analysis.
```python
from tools.mobile.apk_tools import mobsf_scan
result = mobsf_scan("app.apk", mobsf_url="http://localhost:8000")
```

### dex2jar
Convert DEX to JAR format for analysis.

### frida
Dynamic instrumentation framework.

### baksmali/smali
Disassemble/assemble Dalvik bytecode.

### jd-gui
Java decompiler (GUI-based).

## iOS Analysis (6 tools)

### class-dump
Extract Objective-C class information from Mach-O binaries.

### frida-ios-dump
Dump decrypted iOS applications.

### ipa-analyzer
Analyze IPA file structure and metadata.

### objection
Runtime mobile exploration toolkit.

### hopper
Binary disassembler and decompiler.

### cycript
Runtime hooking for iOS apps.

## Mobile Network Analysis (4 tools)

### mitmproxy-mobile
Man-in-the-middle proxy for mobile traffic.

### burp-mobile-assistant
Configure Burp Suite for mobile app testing.

### tcpdump-mobile
Packet capture for mobile devices.

### wireshark-android
Android device traffic capture via ADB.

## Mobile Exploitation (2 tools)

### drozer
Android security assessment framework.
```python
from tools.mobile.mobile_exploit import drozer_scan
result = drozer_scan("com.example.app")
```

### needle
iOS security testing framework.

## Usage Examples

### Complete Android Analysis
```python
# Decompile APK
apk_result = apktool_decompile("app.apk")

# Extract Java source
java_result = jadx_decompile("app.apk")

# Analyze with Androguard
analysis = androguard_analyze("app.apk")
print(f"Package: {analysis['package_name']}")
print(f"Permissions: {analysis['permissions']}")

# Security scan with Drozer
security = drozer_scan(analysis['package_name'])
```

### iOS Application Testing
```python
# Analyze IPA
ipa_info = ipa_analyzer("app.ipa")

# Extract classes
classes = class_dump("app.ipa/Payload/App.app/App")

# Runtime exploration
objection_explore(ipa_info['bundle_id'])
```

## Tool Count
**20 mobile security tools** across Android, iOS, network, and exploitation categories.
