# Enhanced Network & Cloud Security Tools

HexStrike AI Phase 3: Advanced network, cloud-native, and container security tools.

## Advanced Network Security (8 tools)

### scapy
Packet crafting and manipulation framework.
```python
from tools.network.advanced_network import scapy_packet_craft
result = scapy_packet_craft("192.168.1.1", packet_type="ICMP")
```

### zmap
Ultra-fast network-wide scanner (millions of packets per second).
```python
from tools.network.advanced_network import zmap_scan
result = zmap_scan("10.0.0.0/8", port=80, rate=10000)
print(f"Found {result['count']} hosts")
```

### naabu
High-speed port scanner written in Go.

### udp-proto-scanner
UDP protocol scanner for DNS, SNMP, NTP, and other services.

### ipv6-toolkit
IPv6 security testing (alive6, dos-new-ip6, fake_router6).

### vlan-hopper
VLAN hopping attack using DTP (Dynamic Trunking Protocol).

### cisco-torch
Cisco device security scanner (fingerprinting, brute force).

### snmp-check
SNMP enumeration for network devices.

## Cloud-Native Security (7 tools)

### kubescape
Kubernetes security scanner based on NSA/CISA frameworks.
```python
from tools.cloud.cloud_native import kubescape_scan
result = kubescape_scan(framework="nsa")
```

### popeye
Kubernetes cluster sanitizer - detect misconfigurations and best practice violations.

### rbac-police
Kubernetes RBAC security auditor.

### kubesec
Kubernetes manifest security scanner (YAML/JSON validation).

### aws-vault
AWS credential management and enumeration.
```python
from tools.cloud.cloud_native import aws_vault_list
result = aws_vault_list(profile="production")
```

### azure-security-scan
Azure security assessment using az cli.

### gcp-firewall-enum
GCP firewall rule enumeration and misconfiguration detection.

## Container Escape & Security (5 tools)

### deepce
Docker enumeration, privilege escalation, and container escape detection.
```python
from tools.cloud.container_escape import deepce_scan
result = deepce_scan(output_file="deepce_report.txt")
print(f"Findings: {result['findings']}")
```

### amicontained
Container runtime introspection (capabilities, namespaces, seccomp).

### docker-escape-scanner
Docker escape vulnerability scanner (checks for privileged mode, docker socket, cgroup access).
```python
from tools.cloud.container_escape import docker_escape_scanner
result = docker_escape_scanner()
print(f"Escape vectors: {result['escape_vectors']}")
```

### cdk
Container penetration toolkit (evaluate, run, auto-escape).

### peirates
Kubernetes penetration testing framework.

## Usage Examples

### Network Reconnaissance
```python
from tools.network.advanced_network import zmap_scan, naabu_scan, snmp_check

# 1. Fast network discovery
hosts = zmap_scan("192.168.1.0/24", port=80, rate=5000)

# 2. Comprehensive port scanning
for host in hosts['hosts_found']:
    ports = naabu_scan(host, ports="1-65535", rate=1000)

# 3. SNMP enumeration
snmp_info = snmp_check(host, community="public")
```

### Kubernetes Security Assessment
```python
from tools.cloud.cloud_native import kubescape_scan, popeye_scan, rbac_police_audit

# 1. Security framework scan
nsa_compliance = kubescape_scan(framework="nsa")

# 2. Cluster sanitization
issues = popeye_scan(namespace="production")

# 3. RBAC audit
rbac_findings = rbac_police_audit(namespace="production")
```

### Container Escape Testing
```python
from tools.cloud.container_escape import docker_escape_scanner, amicontained_check, deepce_scan

# 1. Check container capabilities
container_info = amicontained_check()
print(f"Runtime: {container_info['container_info']['runtime']}")

# 2. Scan for escape vectors
escape_vectors = docker_escape_scanner()
for vector in escape_vectors['escape_vectors']:
    if vector['vulnerable']:
        print(f"⚠️ {vector['check']}: {vector['risk']} risk")

# 3. Comprehensive enumeration
deepce_results = deepce_scan()
```

### Cloud Security Scanning
```python
from tools.cloud.cloud_native import aws_vault_list, azure_security_scan, gcp_firewall_enum

# AWS
aws_profiles = aws_vault_list()

# Azure
azure_issues = azure_security_scan(subscription_id="xxx")
print(f"High severity: {azure_issues['findings']['high']}")

# GCP
gcp_fw = gcp_firewall_enum(project_id="my-project")
print(f"Firewall issues: {gcp_fw['issues']}")
```

## Tool Count
**20 enhanced network and cloud security tools** across advanced networking, cloud-native, and container security domains.

## Safety Notice
⚠️ **WARNING**: Network scanning and container escape testing may:
- Trigger IDS/IPS alerts
- Violate cloud provider terms of service
- Cause service disruptions

Only use on authorized infrastructure with proper permissions.
