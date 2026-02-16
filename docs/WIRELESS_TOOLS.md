# Wireless Security Tools

HexStrike AI Phase 2: WiFi, Bluetooth, and RF security testing.

## WiFi Security (8 tools)

### wifite2
Automated WiFi attack tool.
```python
from tools.wireless.wifi_tools import wifite2_attack
result = wifite2_attack("wlan0", target_ssid="TargetNetwork")
```

### airgeddon
Multi-use bash script for WiFi auditing.

### fluxion
Evil twin attack framework.

### wifi-pumpkin
Rogue access point framework with MITM capabilities.

### bettercap
Network attack and monitoring framework.

### reaver
WPS PIN brute force attack.

### pixie-dust
Offline WPS PIN attack (Pixiewps).

### cowpatty
WPA-PSK dictionary attack.

## Bluetooth Security (4 tools)

### bluez-tools
Bluetooth device scanning and enumeration.
```python
from tools.wireless.bluetooth_tools import bluez_scan
devices = bluez_scan()
```

### blueborne-scanner
Scan for BlueBorne vulnerabilities (CVE-2017-0781, CVE-2017-0782).

### crackle
Crack Bluetooth Low Energy encryption.

### btlejack
Sniff Bluetooth LE connections.

## RF Security (3 tools)

### rtl-sdr
Software-defined radio for RTL2832U devices.
```python
from tools.wireless.rf_tools import rtl_sdr_scan
result = rtl_sdr_scan(frequency=100e6)
```

### hackrf-tools
HackRF One SDR toolkit for spectrum analysis.

### gqrx
Interactive SDR receiver and analyzer.

## Usage Examples

### WiFi Penetration Testing
```python
from tools.wireless.wifi_tools import wifite2_attack, reaver_wps

# Automated attack
wifite_result = wifite2_attack("wlan0mon")

# WPS attack
wps_result = reaver_wps("wlan0mon", bssid="AA:BB:CC:DD:EE:FF", channel=6)
```

### Bluetooth Security Assessment
```python
from tools.wireless.bluetooth_tools import bluez_scan, blueborne_scanner

# Scan for devices
devices = bluez_scan()

# Test for BlueBorne
for device in devices['devices']:
    vulns = blueborne_scanner(device['address'])
    if vulns['vulnerabilities']:
        print(f"Vulnerable device: {device['name']}")
```

### RF Spectrum Analysis
```python
from tools.wireless.rf_tools import rtl_sdr_scan, hackrf_sweep

# RTL-SDR scan
rtl_result = rtl_sdr_scan(frequency=433e6, sample_rate=2048000)

# HackRF sweep
hackrf_result = hackrf_sweep(start_freq=1e6, end_freq=6e9)
```

## Tool Count
**15 wireless security tools** across WiFi, Bluetooth, and RF domains.

## Safety Notice
⚠️ **WARNING**: Wireless attacks may be illegal without explicit authorization.
Only use these tools on networks you own or have written permission to test.
