#!/usr/bin/env python3
"""Best-effort IPv4 device discovery for the local Wi-Fi/LAN.

Uses only Python's standard library and the operating system's ping/ARP tools.
Devices that ignore ping, are isolated by the access point, or are asleep may
not appear. Run on the computer connected to the Wi-Fi network you want to scan.
"""

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import uuid


def run(command, timeout=5):
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            errors="replace", check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def local_ipv4():
    """Ask the routing table which local IPv4 address reaches the internet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))  # TEST-NET address; no packet is sent.
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_gateway():
    system = platform.system()
    if system == "Windows":
        output = run(["route", "print", "-4"])
        match = re.search(r"^\s*0\.0\.0\.0\s+([\d.]+)\s+0\.0\.0\.0", output, re.M)
    elif system == "Darwin":
        output = run(["route", "-n", "get", "default"])
        match = re.search(r"^\s*gateway:\s*([\d.]+)", output, re.M)
    else:
        output = run(["ip", "route", "show", "default"])
        match = re.search(r"\bdefault\s+via\s+([\d.]+)", output)
    return match.group(1) if match else None


def own_mac():
    # uuid.getnode() returns the active hardware address when available.
    value = uuid.getnode()
    if value >> 40 & 1:  # Python sets this bit when it had to invent a value.
        return "unknown"
    return ":".join(f"{(value >> shift) & 0xff:02X}" for shift in range(40, -1, -8))


def network_mask_for(ip):
    system = platform.system()
    if system == "Windows":
        output = run(["ipconfig", "/all"])
        blocks = re.split(r"\r?\n\s*\r?\n", output)
        for block in blocks:
            ipv4 = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", block, re.I)
            mask = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", block, re.I)
            if ipv4 and mask and ipv4.group(1).split("(")[0].strip() == ip:
                try:
                    return ipaddress.IPv4Network(f"{ip}/{mask.group(1)}", strict=False)
                except ValueError:
                    pass
    elif system == "Darwin":
        output = run(["ifconfig"])
        # Each inet line includes its dotted IPv4 address and hexadecimal mask.
        for line in output.splitlines():
            found = re.search(r"\binet\s+(\d+(?:\.\d+){3}).*\bnetmask\s+(0x[0-9a-fA-F]+)", line)
            if found and found.group(1) == ip:
                try:
                    mask = ipaddress.IPv4Address(int(found.group(2), 16))
                    return ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                except ValueError:
                    pass
    else:
        output = run(["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"])
        for found in re.finditer(r"\binet\s+(\d+(?:\.\d+){3}/\d+)", output):
            if found.group(1).split("/")[0] == ip:
                try:
                    return ipaddress.IPv4Network(found.group(1), strict=False)
                except ValueError:
                    pass
        # Older/minimal Linux installations may not have the `ip` utility.
        output = run(["ifconfig"])
        for line in output.splitlines():
            found = re.search(r"\binet\s+(?:addr:)?(\d+(?:\.\d+){3}).*?(?:netmask\s+(\d+(?:\.\d+){3})|Mask:(\d+(?:\.\d+){3}))", line)
            if found and found.group(1) == ip:
                try:
                    return ipaddress.IPv4Network(f"{ip}/{found.group(2) or found.group(3)}", strict=False)
                except ValueError:
                    pass
    return None


def ping(ip):
    system = platform.system()
    if system == "Windows":
        command = ["ping", "-n", "1", "-w", "700", str(ip)]
    elif system == "Darwin":
        command = ["ping", "-n", "-c", "1", "-W", "1000", str(ip)]
    else:
        command = ["ping", "-n", "-c", "1", "-W", "1", str(ip)]
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


def arp_entries():
    system = platform.system()
    output = run(["arp", "-a"])
    if not output and system == "Linux":
        output = run(["ip", "neigh", "show"])
    entries = {}
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    mac_pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
    for line in output.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        if ip_match and mac_match:
            try:
                address = str(ipaddress.IPv4Address(ip_match.group()))
            except ipaddress.AddressValueError:
                continue
            entries[address] = mac_match.group().replace("-", ":").upper()
    return entries


def main():
    ip = local_ipv4()
    if not ip or ip.startswith("169.254."):
        sys.exit("Could not determine a usable local IPv4 address. Connect to Wi-Fi and try again.")

    network = network_mask_for(ip)
    if network is None:
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        print("Warning: could not read the subnet mask; scanning the guessed /24 subnet.")

    hosts = list(network.hosts())
    if len(hosts) > 4094:
        sys.exit(f"Subnet {network} has too many addresses ({len(hosts)}); refusing a broad scan.")

    gateway = default_gateway()
    print(f"Scanning {network} (this can take a little while)...")
    if gateway:
        ping(ipaddress.IPv4Address(gateway))
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(ping, hosts))

    found = arp_entries()
    # The computer itself is not guaranteed to be listed in its ARP cache.
    found[ip] = own_mac()
    if gateway and gateway not in found:
        found[gateway] = "unknown (gateway did not answer ARP)"
    devices = [(address, mac) for address, mac in found.items()
               if ipaddress.IPv4Address(address) in network]
    devices.sort(key=lambda row: ipaddress.IPv4Address(row[0]))
    print("\nIP address       MAC address")
    print("----------------  -----------------")
    for address, mac in devices:
        print(f"{address:<16}  {mac}")
    print(f"\nListed {len(devices)} device(s), including this computer and the default gateway when detected.")
    print("This is best-effort: devices that do not respond to ping or are isolated may be missing.")


if __name__ == "__main__":
    main()
