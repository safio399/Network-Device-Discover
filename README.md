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
