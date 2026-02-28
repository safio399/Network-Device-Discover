# Network Device Discovery Tool v1.0

A safe, non-intrusive Python tool for discovering devices on your local network using ARP and ICMP (ping) sweeps. No port scanning - just basic network presence detection.

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![Version](https://img.shields.io/badge/version-1.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20|%20macOS%20|%20Linux-lightgrey.svg)

## 📋 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Output Formats](#-output-formats)
- [Configuration Options](#-configuration-options)
- [How It Works](#-how-it-works)
- [Tips & Tricks](#-tips--tricks)
- [Troubleshooting](#-troubleshooting)
- [Security & Ethics](#-security--ethics)
- [Requirements](#-requirements)
- [Future Features](#-future-features)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

## 🎯 Features

### Current Features (v1.0)
- **Safe Discovery Methods**: ARP who-has (if available) and ICMP ping sweeps
- **Multi-Platform**: Works on Windows, macOS, and Linux
- **No Root Required**: ICMP uses system ping, ARP works without root on most systems
- **Name Resolution**: 
  - Reverse DNS lookups
  - NetBIOS name resolution (optional)
  - OS fallback methods (`ping -a`, `nslookup`, `getent`, etc.)
- **Performance**: 
  - Concurrent scanning with rate limiting
  - Configurable timeouts and concurrency (up to 128 threads)
- **Output Formats**: Timestamped CSV and JSON files
- **Auto-Detection**: Automatically detects your local subnet
- **Safe by Default**: No port scanning, rate-limited, requires confirmation
- **Dry Run Mode**: Test without sending any network packets

## 📦 Installation

### Basic Installation (Standard Library Only)
```bash
# Clone the repository
git clone https://github.com/yourusername/network-device-discovery.git
cd network-device-discovery

# No additional dependencies required for ICMP-only mode


With Scapy (Recommended for ARP Sweep)
bash
# Install optional dependency for faster ARP discovery
pip install scapy

Verify Installation

# Check Python version
python --version

# Test the script (dry run)
python discover_devices.py --dry-run

🚀 Quick Start
Basic Usage
# Auto-detect subnet and scan (requires confirmation)
python discover_devices.py

# Auto-confirm permission and scan
python discover_devices.py --yes

# Scan with both ARP and ICMP (ARP requires scapy)
python discover_devices.py --yes --method both

# ICMP only scan with custom concurrency
python discover_devices.py --yes --method icmp --concurrency 100
💡 Usage Examples
Basic Scans
# Simple scan with defaults
python discover_devices.py --yes

# Verbose output (see what's happening)
python discover_devices.py --yes --verbose

# Quiet mode (minimal output)
python discover_devices.py --yes --quiet

Advanced Scans
# Scan with NetBIOS name lookup (more human-readable names)
python discover_devices.py --yes --netbios

# Specify a custom subnet
python discover_devices.py --yes --subnet 192.168.1.0/24

# High-performance scan (100 concurrent workers, 200ms rate limit)
python discover_devices.py --yes --method icmp --concurrency 100 --rate 0.2

# Fast scan for large networks
python discover_devices.py --yes --method icmp --concurrency 200 --rate 0.05 --timeout 0.8

# Comprehensive scan with all features
python discover_devices.py --yes --method both --netbios --verbose
# Scan with NetBIOS name lookup (more human-readable names)
python discover_devices.py --yes --netbios

# Specify a custom subnet
python discover_devices.py --yes --subnet 192.168.1.0/24

# High-performance scan (100 concurrent workers, 200ms rate limit)
python discover_devices.py --yes --method icmp --concurrency 100 --rate 0.2

# Fast scan for large networks
python discover_devices.py --yes --method icmp --concurrency 200 --rate 0.05 --timeout 0.8

# Comprehensive scan with all features
python discover_devices.py --yes --method both --netbios --verbose
Testing and Simulation

# Dry run (simulates scan without sending packets)
python discover_devices.py --dry-run --verbose

# Test with different timeouts
python discover_devices.py --yes --timeout 2.0 --dns-timeout 2.5

# Test NetBIOS resolution only
python discover_devices.py --yes --method icmp --netbios
📊 Output Formats
CSV Output (devices-YYYYMMDD-HHMMSS.csv)

timestamp,ip,hostname,mac,method
20231215-143022,192.168.1.1,router.local,00:11:22:33:44:55,ARP,reverse-DNS
20231215-143022,192.168.1.101,office-pc,aa:bb:cc:dd:ee:ff,ICMP,NetBIOS
20231215-143022,192.168.1.102,,,ICMP
20231215-143022,192.168.1.105,smart-tv,11:22:33:44:55:66,ARP

JSON Output (devices-YYYYMMDD-HHMMSS.json)
[
  {
    "timestamp": "20231215-143022",
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "mac": "00:11:22:33:44:55",
    "method": "ARP,reverse-DNS"
  },
  {
    "timestamp": "20231215-143022",
    "ip": "192.168.1.101",
    "hostname": "office-pc",
    "mac": "aa:bb:cc:dd:ee:ff",
    "method": "ICMP,NetBIOS"
  },
  {
    "timestamp": "20231215-143022",
    "ip": "192.168.1.102",
    "hostname": "",
    "mac": "",
    "method": "ICMP"
  }
]

⚙️ Configuration Options
Option	Description	Default	Example
--yes	Skip permission confirmation	False	--yes
--method	Discovery method (both/arp/icmp)	both	--method arp
--netbios	Attempt NetBIOS name lookup	False	--netbios
--subnet	Override subnet CIDR	Auto-detect	--subnet 192.168.1.0/24
--concurrency	Max concurrent threads	128	--concurrency 50
--timeout	Per-host discovery timeout (sec)	1.5	--timeout 2.0
--dns-timeout	Reverse DNS timeout (sec)	1.5	--dns-timeout 2.0
--netbios-timeout	NetBIOS query timeout (sec)	2.0	--netbios-timeout 3.0
--rate	Delay between tasks (sec)	0.0	--rate 0.1
--verbose	Detailed output	False	--verbose
--quiet	Minimal output	False	--quiet
--dry-run	Simulate scan (no traffic)	False	--dry-run

🔍 How It Works
Step-by-Step Process
Network Detection:

Determines your local IPv4 address using UDP connect trick

Automatically detects subnet mask via OS tools (ipconfig/ip/ifconfig)

Falls back to /24 if detection fails

Host Discovery:

ARP Sweep: Broadcasts ARP who-has requests (requires scapy)

ICMP Sweep: Concurrent ping sweeps using system ping

Both methods can be used together for maximum coverage

Name Resolution (in order of preference):

Reverse DNS lookup

NetBIOS name query (if enabled)

OS fallback methods (ping -a, nslookup, getent, host)

Output Generation:

Creates timestamped CSV and JSON files

Sorts devices by IP address

Records discovery method for each device

Platform-Specific Behavior
Windows: Uses ipconfig, ping -n, nbtstat -A

Linux: Uses ip, ifconfig, ping -c, nmblookup

macOS: Uses ifconfig, ping -c, nmblookup

💡 Tips & Tricks
Performance Optimization

# For large networks (/16 or larger)
python discover_devices.py --yes --method icmp --concurrency 250 --rate 0.01 --timeout 0.8

# For small networks with many devices
python discover_devices.py --yes --method both --concurrency 50 --rate 0.0

# Balance speed and reliability
python discover_devices.py --yes --method both --concurrency 100 --rate 0.1 --timeout 1.0

# Best for Windows networks (more NetBIOS names)
python discover_devices.py --yes --netbios

# Best for corporate networks (DNS-heavy)
python discover_devices.py --yes --dns-timeout 2.0

# Maximum name resolution attempts
python discover_devices.py --yes --netbios --dns-timeout 2.0 --verbose

🛡️ Security & Ethics
Important Considerations
This tool is designed for:

Network administrators managing their own networks

Educational purposes (learning about network discovery)

Troubleshooting connectivity issues

Inventory management on trusted networks

Legal Notice
⚠️ WARNING: Unauthorized scanning may be:

Against your organization's policies

Illegal in some jurisdictions

Considered intrusive by network owners

Always ensure you have explicit permission before scanning any network that you do not own or manage.

Safety Features
No port scanning (only presence detection)

Rate limiting to avoid network flooding

Configurable timeouts to minimize impact

Explicit user confirmation required by default

Dry-run mode for testing

📋 Requirements
Minimum Requirements
Python 3.6 or higher

Network access to the target subnet

50MB free disk space (for logs)

Optional Requirements
scapy for ARP discovery (pip install scapy)

nmblookup for NetBIOS on Linux/macOS

Administrative/root privileges for ARP on some systems

Supported Platforms
Windows: 7, 8, 10, 11 (x86/x64)

Linux: All major distributions (Ubuntu, Debian, RHEL, CentOS, etc.)

macOS: 10.14 (Mojave) and newer (Intel/Apple Silicon)

🚧 Future Features (Roadmap)
Planned for v1.1
MAC address vendor lookup (OUI database)

Service fingerprinting (optional, opt-in)

Export to additional formats (XML, YAML)

Configuration file support

Continuous monitoring mode

Planned for v1.2
Web interface for results visualization

Network topology mapping

Device type detection (router, printer, PC, etc.)

Historical data tracking and trends

Planned for v2.0
IPv6 support

SNMP discovery for network devices

Plugin system for custom discovery methods

Database backend (SQLite/PostgreSQL)

REST API for integration

🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Version 1.0 - First stable release with core features
More features coming soon!

Disclaimer: This tool is for legitimate network management and educational purposes only. Users are responsible for complying with applicable laws and obtaining necessary permissions before use. The authors assume no liability for misuse or unauthorized scanning.


📝 License
MIT

Copyright (c) 2024 Network Device Discovery Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

🙏 Acknowledgments
Inspired by various network discovery tools (nmap, arp-scan, fping)

Uses Python's standard library where possible for maximum compatibility

Special thanks to the scapy project for excellent packet manipulation

Community contributors and testers

Network administrators who provided feedback
