#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Device Discovery (Safe ARP/ICMP) - Python 3

This script discovers devices on the same local IPv4 network and logs each device's
hostname (if resolvable) and IP address to timestamped CSV and JSON files.

It performs safe ARP and/or ICMP-based discovery (no port scanning).

Dependencies:
- Standard library only by default.
- Optional: scapy for faster ARP sweep (recommended but not required).

Install optional dependency:
  pip install scapy

Usage:
  python discover_devices.py [--yes] [--method both|arp|icmp] [--netbios]
                             [--subnet CIDR] [--concurrency N]
                             [--timeout SECONDS] [--dns-timeout SECONDS]
                             [--rate SECONDS] [--verbose | --quiet]
                             [--dry-run]

Examples:
  - Default (auto-detect subnet, ARP if scapy is available; otherwise ICMP):
      python discover_devices.py --yes

  - ICMP only with 100 workers, 0.2s rate limit:
      python discover_devices.py --yes --method icmp --concurrency 100 --rate 0.2

  - ARP only (requires scapy; admin/privileged recommended):
      python discover_devices.py --yes --method arp

  - Include optional NetBIOS name lookup (Windows uses 'nbtstat', Linux/mac tries 'nmblookup'):
      python discover_devices.py --yes --netbios

  - Override subnet:
      python discover_devices.py --yes --subnet 192.168.1.0/24

  - Dry-run test mode (simulates a tiny subnet without sending any packets):
      python discover_devices.py --dry-run --verbose

Outputs:
  - devices-YYYYMMDD-HHMMSS.csv  (columns: timestamp, ip, hostname, mac, method)
  - devices-YYYYMMDD-HHMMSS.json (array of objects with same fields)

Cross-platform notes:
  - Windows/macOS/Linux supported.
  - ICMP via system 'ping' is used to avoid raw socket privileges.
  - ARP with scapy may require admin/root privileges and a working layer-2 interface.
  - NetBIOS lookup:
      * Windows: uses 'nbtstat -A IP'
      * Linux/macOS: tries 'nmblookup -A IP' if available; otherwise skipped.

Safety:
  - No port scanning or intrusive probing.
  - Rate-limited and concurrency-controlled.
  - Prints a warning and requires explicit user confirmation before scanning.

How it works (brief):
  1) Determines local IPv4 and subnet CIDR by inspecting OS network config.
  2) Discovers live hosts via:
     - ARP sweep (if scapy available and/or chosen) and/or
     - ICMP ping sweep using system 'ping'
  3) Attempts reverse DNS for each responsive IP; optionally NetBIOS name lookup.
  4) Writes results to CSV and JSON with timestamped filenames.

"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Try importing scapy for optional ARP sweep
_SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, conf, get_if_addr, srp  # type: ignore
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False


@dataclass
class DeviceRecord:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    methods: Set[str] = field(default_factory=set)

    def to_csv_row(self, timestamp_str: str) -> List[str]:
        return [
            timestamp_str,
            self.ip,
            self.hostname or "",
            self.mac or "",
            ",".join(sorted(self.methods)) if self.methods else "",
        ]

    def to_json_obj(self, timestamp_str: str) -> Dict[str, str]:
        return {
            "timestamp": timestamp_str,
            "ip": self.ip,
            "hostname": self.hostname or "",
            "mac": self.mac or "",
            "method": ",".join(sorted(self.methods)) if self.methods else "",
        }


def confirm_permission_or_exit(preconfirmed: bool = False) -> None:
    print("WARNING: This script will perform a safe ARP/ICMP discovery on your local network.")
    print("Only proceed if you have permission to scan the network. No port scanning will occur.")
    if preconfirmed:
        print("Permission pre-confirmed via --yes.")
        return
    response = input("Do you confirm you have permission to perform this discovery? [y/N]: ").strip().lower()
    if response not in ("y", "yes"):
        print("Permission not confirmed. Exiting.")
        sys.exit(1)


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def run_command(cmd: List[str], timeout: Optional[float] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            shell=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 255, "", str(e)


def get_local_ipv4_and_netmask() -> Tuple[str, Optional[str]]:
    """
    Returns (local_ipv4, netmask) where netmask is dotted-quad if found; else None.
    We use a UDP "connect" trick to determine the outbound interface's IPv4.
    Then parse OS tools to match netmask for that IP.
    """
    # Discover local IP via UDP connect trick
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        # Fallback: hostname resolution
        local_ip = socket.gethostbyname(socket.gethostname())
    finally:
        try:
            s.close()
        except Exception:
            pass

    # Attempt to find netmask via OS tooling
    netmask = None
    system = platform.system().lower()

    try:
        if system == "windows":
            # ipconfig parsing
            code, out, _ = run_command(["ipconfig"])
            if code == 0:
                adapter_blocks = re.split(r"\r?\n\r?\n", out)
                for block in adapter_blocks:
                    if local_ip in block:
                        # Try both "Subnet Mask" and "Prefix Length"
                        m = re.search(r"Subnet Mask[.\s:]*([\d\.]+)", block, re.IGNORECASE)
                        if m:
                            netmask = m.group(1).strip()
                            break
                        m2 = re.search(r"Prefix Length[.\s:]*([0-9]+)", block, re.IGNORECASE)
                        if m2:
                            prefix_len = int(m2.group(1))
                            netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
                            break
        else:
            # Prefer `ip` if available
            code, out, _ = run_command(["ip", "-o", "-f", "inet", "addr", "show"])
            if code == 0 and out.strip():
                # Example line: 2: enp0s3    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
                for line in out.splitlines():
                    m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\b", line)
                    if m:
                        ip = m.group(1)
                        prefix_len = int(m.group(2))
                        if ip == local_ip:
                            netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
                            break
            if netmask is None:
                # Fallback to ifconfig parsing
                code, out, _ = run_command(["ifconfig"])
                if code == 0:
                    # Different formats across BSD/macOS/Linux
                    # Find the block that contains our local IP
                    blocks = re.split(r"\n(?=\S)", out)  # split on interface headers
                    for block in blocks:
                        if local_ip in block:
                            # Look for netmask in hex (macOS) or dotted quad (Linux)
                            m_hex = re.search(r"netmask\s+0x([0-9a-fA-F]+)", block)
                            if m_hex:
                                hexmask = int(m_hex.group(1), 16)
                                netmask = socket.inet_ntoa(hexmask.to_bytes(4, byteorder="big"))
                                break
                            m_dot = re.search(r"netmask\s+(\d+\.\d+\.\d+\.\d+)", block)
                            if m_dot:
                                netmask = m_dot.group(1)
                                break
    except Exception:
        netmask = None

    return local_ip, netmask


def autodetect_subnet() -> ipaddress.IPv4Network:
    local_ip, netmask = get_local_ipv4_and_netmask()
    if not local_ip:
        raise RuntimeError("Unable to determine local IPv4 address.")
    if not netmask:
        # Safe default if netmask detection fails: /24 on local interface
        logging.warning("Could not detect netmask; defaulting to /24 for %s", local_ip)
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return net
    net = ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False)
    return net


def generate_ip_list(subnet: ipaddress.IPv4Network, exclude_ips: Optional[Set[str]] = None) -> List[str]:
    ips = []
    for ip in subnet.hosts():
        s = str(ip)
        if exclude_ips and s in exclude_ips:
            continue
        ips.append(s)
    return ips


def ping_once(ip: str, timeout: float) -> bool:
    # This type alias ensures mypy-like tools don't complain if available; not strictly needed at runtime.
    pass  # replaced below
# The above is a stub to aid editors; real function is defined next with correct signature.


def ping_host(ip: str, timeout: float) -> bool:
    """
    ICMP echo using system 'ping' command. Returns True if host responds.
    - Windows: ping -n 1 -w <ms>
    - Linux:   ping -c 1 -W <sec>
    - macOS:   ping -c 1 with process timeout fallback; also try -W <ms> if supported.
    """
    system = platform.system().lower()
    if system == "windows":
        # -n 1 one echo, -w timeout (ms)
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        code, out, _ = run_command(cmd, timeout=timeout + 1.5)
        if code == 0 and re.search(r"(TTL=|ttl=)\d+", out):
            return True
        return False
    else:
        # Try Linux style first: -c 1 -W <sec>
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
        code, out, err = run_command(cmd, timeout=timeout + 1.5)
        if code == 0 and re.search(r"(ttl=)\d+", out, re.IGNORECASE):
            return True
        # Fallback: macOS sometimes expects -W in ms or doesn't support it; rely on process timeout
        cmd = ["ping", "-c", "1", ip]
        code, out, _ = run_command(cmd, timeout=timeout + 1.5)
        if code == 0 and re.search(r"(ttl=)\d+", out, re.IGNORECASE):
            return True
        return False


def reverse_dns(ip: str, dns_timeout: float) -> Optional[str]:
    # Temporarily set default timeout
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(dns_timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(original_timeout)


def netbios_name_lookup(ip: str, timeout: float, logger: logging.Logger) -> Optional[str]:
    """
    Optional NetBIOS/SMB name lookup using OS tools:
      - Windows: nbtstat -A IP
      - Linux/macOS: nmblookup -A IP (if available)
    Returns a NetBIOS name if found, else None.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["nbtstat", "-A", ip]
        code, out, _ = run_command(cmd, timeout=timeout + 1.0)
        if code == 0 and out:
            # Look for a <00> UNIQUE or <20> fields; parse first name line
            # Example line: "MYHOST           <00>  UNIQUE      Registered"
            for line in out.splitlines():
                m = re.search(r"^\s*([A-Za-z0-9\-_.$]{1,32})\s+<\w{2}>\s+\w+", line)
                if m:
                    name = m.group(1).strip()
                    if name and name.upper() != "WORKGROUP":
                        return name
    else:
        # Check if nmblookup exists
        code, _, _ = run_command(["which", "nmblookup"])
        if code == 0:
            cmd = ["nmblookup", "-A", ip]
            code2, out, _ = run_command(cmd, timeout=timeout + 1.0)
            if code2 == 0 and out:
                for line in out.splitlines():
                    # Example: "MYHOST           <00> -         M <ACTIVE>"
                    m = re.search(r"^\s*([A-Za-z0-9\-_.$]{1,32})\s+<\w{2}>\s", line)
                    if m:
                        name = m.group(1).strip()
                        if name and name.upper() != "WORKGROUP":
                            return name
        else:
            logger.debug("nmblookup not found; skipping NetBIOS lookup for %s", ip)
    return None


def system_guess_hostname(ip: str, timeout: float, logger: logging.Logger) -> Optional[str]:
    """
    Try OS command fallbacks to infer a hostname when rDNS/NetBIOS fail.
      - Windows: ping -a, nslookup
      - Linux/macOS: getent hosts, host, nslookup
    Returns hostname or None.
    """
    system = platform.system().lower()

    def _first_non_ip(token: str) -> Optional[str]:
        token = token.strip().strip("[]()")
        try:
            ipaddress.ip_address(token)
            return None
        except Exception:
            return token if token else None

    if system == "windows":
        # ping -a tries to resolve name
        code, out, _ = run_command(["ping", "-a", "-n", "1", "-w", str(int(timeout * 1000)), ip], timeout=timeout + 1.0)
        if code == 0 and out:
            # Example: Pinging MYPC [10.0.0.5] with 32 bytes of data:
            m = re.search(r"Pinging\s+(.+?)\s+\[\s*%s\s*\]" % re.escape(ip), out, re.IGNORECASE)
            if m:
                candidate = _first_non_ip(m.group(1))
                if candidate:
                    return candidate
        # nslookup
        code, out, _ = run_command(["nslookup", ip], timeout=timeout + 1.0)
        if out:
            # Look for "name =" or first non-IP token after "Name:"
            m = re.search(r"Name:\s*(.+)", out, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip().rstrip(".")
                if candidate and candidate != ip:
                    return candidate
            m2 = re.search(r"name\s*=\s*([^\s]+)", out, re.IGNORECASE)
            if m2:
                candidate = m2.group(1).strip().rstrip(".")
                if candidate and candidate != ip:
                    return candidate
    else:
        # getent hosts
        code, out, _ = run_command(["getent", "hosts", ip], timeout=timeout + 0.5)
        if code == 0 and out:
            # Format: "IP hostname alias..."
            parts = out.strip().split()
            if len(parts) >= 2:
                candidate = parts[1].strip().rstrip(".")
                if candidate and candidate != ip:
                    return candidate
        # host
        code, out, _ = run_command(["host", ip], timeout=timeout + 0.5)
        if code == 0 and out:
            # Example: "56.22.111.10.in-addr.arpa domain name pointer mypc.local."
            m = re.search(r"pointer\s+([^\s]+)\.", out, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip()
                if candidate and candidate != ip:
                    return candidate
        # nslookup
        code, out, _ = run_command(["nslookup", ip], timeout=timeout + 0.5)
        if out:
            m = re.search(r"name\s*=\s*([^\s]+)", out, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip().rstrip(".")
                if candidate and candidate != ip:
                    return candidate
    return None


def arp_sweep_with_scapy(subnet: ipaddress.IPv4Network, timeout: float, logger: logging.Logger) -> Dict[str, str]:
    """
    Perform ARP who-has broadcast to the subnet using scapy.
    Returns dict: ip -> mac for responders.
    """
    ip_cidr = str(subnet)
    logger.info("Starting ARP sweep via scapy on %s ...", ip_cidr)
    # Scapy configuration tweaks: don't resolve names, quiet output
    conf.verb = 0  # type: ignore
    # Build ARP request
    arp = ARP(pdst=ip_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    # Send and receive
    try:
        answered, _ = srp(packet, timeout=timeout, retry=0)  # type: ignore
    except PermissionError:
        logger.warning("Insufficient privileges for raw sockets. ARP sweep skipped.")
        return {}
    except Exception as e:
        logger.warning("ARP sweep failed: %s", e)
        return {}

    results: Dict[str, str] = {}
    for sent, received in answered:
        try:
            ip = received.psrc
            mac = received.hwsrc
            if ip and mac:
                results[ip] = mac
        except Exception:
            continue
    logger.info("ARP sweep complete. %d host(s) responded.", len(results))
    return results


def icmp_sweep(
    ips: Iterable[str],
    timeout: float,
    concurrency: int,
    rate: float,
    logger: logging.Logger,
) -> Set[str]:
    """
    ICMP sweep using system 'ping' concurrently with rate limiting.
    Returns set of responsive IPs.
    """
    logger.info("Starting ICMP sweep of %d IPs with concurrency=%d, rate=%.3fs ...", len(list(ips)) if not isinstance(ips, list) else len(ips), concurrency, rate)
    responsive: Set[str] = set()
    lock = threading.Lock()

    def worker(ip: str) -> None:
        alive = ping_host(ip, timeout=timeout)
        if alive:
            with lock:
                responsive.add(ip)

    # Convert to list to avoid consuming generator multiple times
    ip_list = list(ips)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures: List[concurrent.futures.Future] = []
        for ip in ip_list:
            futures.append(executor.submit(worker, ip))
            if rate > 0.0:
                time.sleep(rate)
        # Wait for completion
        for f in concurrent.futures.as_completed(futures):
            _ = f  # allow exceptions to surface here

    logger.info("ICMP sweep complete. %d host(s) responded.", len(responsive))
    return responsive


def resolve_hostnames(
    ips: Iterable[str],
    dns_timeout: float,
    enable_netbios: bool,
    netbios_timeout: float,
    logger: logging.Logger,
) -> Dict[str, Dict[str, Optional[str]]]:
    """
    For each IP, attempt reverse DNS and optionally NetBIOS.
    Returns mapping: ip -> {"rdns": hostname_or_none, "netbios": hostname_or_none}
    """
    results: Dict[str, Dict[str, Optional[str]]] = {}
    ips_list = list(ips)

    def resolve_one(ip: str) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
        rdns = reverse_dns(ip, dns_timeout)
        nb = None
        if enable_netbios:
            nb = netbios_name_lookup(ip, netbios_timeout, logger)
        sys_name = None
        if not rdns and not nb:
            # As a last resort try OS tools; keep it lightweight
            sys_name = system_guess_hostname(ip, dns_timeout, logger)
        return ip, rdns, nb, sys_name

    # modest parallelism for name lookups to avoid hammering DNS
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, max(4, len(ips_list)))) as ex:
        futures = [ex.submit(resolve_one, ip) for ip in ips_list]
        for fut in concurrent.futures.as_completed(futures):
            ip, rdns, nb, sys_name = fut.result()
            results[ip] = {"rdns": rdns, "netbios": nb, "system": sys_name}
    return results


def write_outputs(devices: List[DeviceRecord], timestamp_str: str, logger: logging.Logger) -> Tuple[str, str]:
    csv_name = f"devices-{timestamp_str}.csv"
    json_name = f"devices-{timestamp_str}.json"

    # CSV
    with open(csv_name, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "hostname", "mac", "method"])
        for d in devices:
            writer.writerow(d.to_csv_row(timestamp_str))

    # JSON
    with open(json_name, "w", encoding="utf-8") as f:
        json.dump([d.to_json_obj(timestamp_str) for d in devices], f, indent=2)

    logger.info("Wrote %s and %s", csv_name, json_name)
    return csv_name, json_name


def simulate_discovery(logger: logging.Logger) -> List[DeviceRecord]:
    """
    Dry-run simulation over documentation network 192.0.2.0/30.
    Generates a couple of fake devices deterministically.
    """
    timestamp = int(time.time()) % 1000
    fake_ips = ["192.0.2.1", "192.0.2.2"]
    records: List[DeviceRecord] = []
    for idx, ip in enumerate(fake_ips, start=1):
        rec = DeviceRecord(
            ip=ip,
            hostname=f"sim-device-{idx}",
            mac=f"02:00:00:00:00:{idx:02x}",
            methods={"ICMP", "reverse-DNS"},
        )
        records.append(rec)
    logger.info("Dry-run produced %d simulated devices.", len(records))
    return records


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Discover devices on the local network via ARP/ICMP and log to CSV/JSON.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--yes", action="store_true",
                   help="Non-interactive confirmation that you have permission to scan.")
    p.add_argument("--method", choices=["both", "arp", "icmp"], default="both",
                   help="Discovery method to use (ARP requires scapy).")
    p.add_argument("--netbios", action="store_true",
                   help="Attempt NetBIOS/SMB name lookup per IP (optional).")
    p.add_argument("--subnet", type=str, default=None,
                   help="Override subnet CIDR (e.g., 192.168.1.0/24). Default: auto-detect.")
    p.add_argument("--concurrency", type=int, default=128,
                   help="Max concurrent ICMP pings or name lookups.")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Per-host discovery timeout in seconds (ARP/ICMP).")
    p.add_argument("--dns-timeout", type=float, default=1.5,
                   help="Per-host reverse DNS timeout in seconds.")
    p.add_argument("--rate", type=float, default=0.0,
                   help="Seconds to sleep between scheduling discovery tasks (rate limit).")
    p.add_argument("--netbios-timeout", type=float, default=2.0,
                   help="Per-host NetBIOS query timeout in seconds.")
    p.add_argument("--verbose", action="store_true", help="Verbose output.")
    p.add_argument("--quiet", action="store_true", help="Quiet output.")
    p.add_argument("--dry-run", action="store_true",
                   help="Simulate a small subnet without sending network traffic.")
    return p


def configure_logging(verbose: bool, quiet: bool) -> logging.Logger:
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    if quiet:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    return logging.getLogger("discover")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    logger = configure_logging(args.verbose, args.quiet)

    confirm_permission_or_exit(preconfirmed=args.yes)

    # Warn about scapy availability vs method
    if args.method in ("both", "arp") and not _SCAPY_AVAILABLE:
        logger.warning("scapy not available; ARP sweep will be skipped. Install with: pip install scapy")

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if args.dry_run:
        devices = simulate_discovery(logger)
        write_outputs(devices, timestamp, logger)
        return

    # Determine subnet
    if args.subnet:
        try:
            subnet = ipaddress.ip_network(args.subnet, strict=False)
        except Exception as e:
            logger.error("Invalid --subnet: %s", e)
            sys.exit(2)
    else:
        try:
            subnet = autodetect_subnet()
        except Exception as e:
            logger.error("Failed to autodetect subnet: %s", e)
            sys.exit(2)

    # Exclude self IP from target list
    try:
        local_ip, _ = get_local_ipv4_and_netmask()
    except Exception:
        local_ip = None
    exclude: Set[str] = set()
    if local_ip:
        exclude.add(local_ip)

    ip_targets = generate_ip_list(subnet, exclude_ips=exclude)
    if not ip_targets:
        logger.error("No hosts found in subnet %s", str(subnet))
        sys.exit(3)

    # Discovery
    ip_to_mac: Dict[str, str] = {}
    responsive_icmp: Set[str] = set()

    if args.method in ("both", "arp") and _SCAPY_AVAILABLE:
        try:
            ip_to_mac = arp_sweep_with_scapy(subnet, timeout=args.timeout, logger=logger)
        except Exception as e:
            logger.warning("ARP sweep failed: %s", e)

    if args.method in ("both", "icmp") or (args.method in ("both", "arp") and not _SCAPY_AVAILABLE):
        # For ICMP sweep, include all subnet hosts; ARP might already have some
        try:
            responsive_icmp = icmp_sweep(
                ip_targets,
                timeout=args.timeout,
                concurrency=max(1, args.concurrency),
                rate=max(0.0, args.rate),
                logger=logger,
            )
        except Exception as e:
            logger.warning("ICMP sweep failed: %s", e)

    # Merge discovered hosts
    discovered_ips: Set[str] = set(responsive_icmp) | set(ip_to_mac.keys())

    if not discovered_ips:
        logger.warning("No responsive hosts discovered.")
    else:
        logger.info("Discovered %d unique host(s). Resolving names ...", len(discovered_ips))

    # Resolve hostnames (reverse DNS and optional NetBIOS)
    name_map = resolve_hostnames(
        discovered_ips,
        dns_timeout=args.dns_timeout,
        enable_netbios=args.netbios,
        netbios_timeout=args.netbios_timeout,
        logger=logger,
    ) if discovered_ips else {}

    # Build device records
    records: Dict[str, DeviceRecord] = {}
    for ip in discovered_ips:
        rec = records.get(ip) or DeviceRecord(ip=ip)
        if ip in ip_to_mac:
            rec.mac = ip_to_mac[ip]
            rec.methods.add("ARP")
        if ip in responsive_icmp:
            rec.methods.add("ICMP")
        # Choose hostname preference: NetBIOS over rDNS if available (often more human-friendly on LAN)
        names = name_map.get(ip, {})
        nb_name = names.get("netbios")
        rdns_name = names.get("rdns")
        if nb_name:
            rec.hostname = nb_name
            rec.methods.add("NetBIOS")
        elif rdns_name:
            rec.hostname = rdns_name
            rec.methods.add("reverse-DNS")
        records[ip] = rec

    # Sort by IP
    sorted_devices = sorted(records.values(), key=lambda d: tuple(int(x) for x in d.ip.split(".")))

    # Write outputs
    write_outputs(sorted_devices, timestamp, logger)

    # Final summary
    if sorted_devices:
        logger.info("Discovery complete: %d device(s).", len(sorted_devices))
    else:
        logger.info("Discovery complete: 0 devices.")


# --- Fix minor typing stub for editors ---
def ping_once(ip: str, timeout: float) -> bool:
    return ping_host(ip, timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(130)



