"""
ARP-based Network Device Discovery Module for NetVisor Agent.

Sends ARP requests to discover devices on the local network,
resolves hostnames via DNS, and identifies vendors from MAC addresses.
Requires Administrator/root privileges for raw packet access.
"""

import socket
import struct
import logging
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from scapy.all import ARP, Ether, srp, conf

logger = logging.getLogger("netvisor.agent.discovery")

# --- Vendor lookup (optional dependency) ---
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    try:
        _mac_lookup.update_vendors()
        logger.info("MAC vendor database updated successfully.")
    except Exception:
        logger.warning("Could not update MAC vendor DB; using cached data.")
    _HAS_VENDOR_LOOKUP = True
except ImportError:
    _mac_lookup = None
    _HAS_VENDOR_LOOKUP = False
    logger.warning(
        "mac-vendor-lookup not installed. Vendor identification disabled. "
        "Install with: pip install mac-vendor-lookup"
    )


def _get_local_subnet() -> Optional[str]:
    """Auto-detect the local subnet in CIDR notation (e.g. 192.168.1.0/24)."""
    try:
        # Connect to a public DNS to determine the default interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Assume /24 subnet — covers most home/small-office networks
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception as e:
        logger.error(f"Could not auto-detect local subnet: {e}")
        return None


def _resolve_netbios_name(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Query a host's NetBIOS name via UDP port 137 (Node Status Request).
    No external dependencies (replaces impacket.nmb.NetBIOS).
    Returns the hostname string or None on failure.
    """
    # NetBIOS Node Status Request packet
    # Transaction ID (2 bytes) + Flags + Questions + etc.
    transaction_id = b'\x80\x01'
    flags = b'\x00\x00'  # query
    questions = b'\x00\x01'
    answers = b'\x00\x00'
    authority = b'\x00\x00'
    additional = b'\x00\x00'

    # Wildcard name: "*" encoded as NetBIOS name (32 bytes of encoded name)
    # "*" = 0x2A, padded with spaces (0x20) to 16 bytes, then each byte
    # is split into two nibbles + 'A' (0x41)
    name_bytes = b'\x2A' + b'\x20' * 15
    encoded = b''
    for byte in name_bytes:
        encoded += bytes([((byte >> 4) & 0x0F) + 0x41])
        encoded += bytes([(byte & 0x0F) + 0x41])

    # Length-prefixed encoded name + null terminator
    qname = bytes([32]) + encoded + b'\x00'

    # Question type NBSTAT (0x0021) and class IN (0x0001)
    qtype = b'\x00\x21'
    qclass = b'\x00\x01'

    packet = transaction_id + flags + questions + answers + authority + additional + qname + qtype + qclass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) < 57:
            return None

        # Parse response: skip header (12 bytes) + question section,
        # find the number of names
        # Jump to answer data: after header + repeated qname + type + class + TTL + data_length
        offset = 12
        # Skip the name field in the answer
        while offset < len(data) and data[offset] != 0:
            offset += 1
        offset += 1  # null terminator
        offset += 10  # type(2) + class(2) + TTL(4) + data_length(2)

        if offset >= len(data):
            return None

        num_names = data[offset]
        offset += 1

        # First name entry: 15 bytes name + 1 byte suffix + 2 bytes flags
        if offset + 18 <= len(data) and num_names > 0:
            name = data[offset:offset + 15].decode('ascii', errors='ignore').strip()
            if name and name != '*':
                return name

        return None
    except (socket.timeout, OSError, UnicodeDecodeError):
        return None


def _resolve_hostname(ip: str) -> str:
    """Resolve an IP to a hostname. Tries DNS first, then NetBIOS fallback."""
    # Try reverse DNS first
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname:
            return hostname
    except (socket.herror, socket.timeout, OSError):
        pass

    # Fallback: try NetBIOS name query (works for Windows devices)
    try:
        nb_name = _resolve_netbios_name(ip)
        if nb_name:
            return nb_name
    except Exception:
        pass

    return "Unknown"


def _lookup_vendor(mac: str) -> str:
    """Look up the vendor/manufacturer from a MAC address."""
    if not _HAS_VENDOR_LOOKUP or _mac_lookup is None:
        return "Unknown"
    try:
        return _mac_lookup.lookup(mac)
    except (KeyError, ValueError):
        return "Unknown"


def _infer_device_type(hostname: str, vendor: str) -> str:
    """Best-effort device type inference from hostname and vendor strings."""
    combined = f"{hostname} {vendor}".lower()

    phone_keywords = ["iphone", "android", "pixel", "galaxy", "oneplus", "xiaomi", "huawei", "oppo", "realme"]
    if any(kw in combined for kw in phone_keywords):
        return "Smartphone"

    if any(kw in combined for kw in ["ipad", "tablet", "kindle", "fire"]):
        return "Tablet"

    if any(kw in combined for kw in ["tv", "roku", "chromecast", "firestick", "fire tv", "lg-webos", "samsung-tv"]):
        return "Smart TV"

    if any(kw in combined for kw in ["echo", "alexa", "google-home", "homepod", "nest"]):
        return "Smart Speaker"

    if any(kw in combined for kw in ["printer", "canon", "hp-print", "epson", "brother"]):
        return "Printer"

    if any(kw in combined for kw in ["camera", "ring", "wyze", "arlo", "hikvision", "dahua"]):
        return "Camera"

    router_keywords = ["router", "gateway", "tp-link", "netgear", "asus", "linksys", "d-link", "ubiquiti", "mikrotik"]
    if any(kw in combined for kw in router_keywords):
        return "Router/AP"

    if any(kw in combined for kw in ["desktop", "workstation"]):
        return "Desktop"

    if any(kw in combined for kw in ["laptop", "macbook", "thinkpad", "surface"]):
        return "Laptop"

    if any(kw in combined for kw in ["apple", "mac"]):
        return "Apple Device"

    if any(kw in combined for kw in ["raspberr", "arduino", "esp32", "esp8266"]):
        return "IoT Device"

    return "Unknown"


def _infer_os_family(hostname: str, vendor: str) -> str:
    """Best-effort OS family inference from hostname and vendor strings."""
    combined = f"{hostname} {vendor}".lower()

    if any(kw in combined for kw in ["apple", "iphone", "ipad", "mac", "airpods"]):
        return "Apple/iOS"
    if any(kw in combined for kw in ["android", "pixel", "galaxy", "xiaomi", "oneplus", "oppo", "realme", "huawei"]):
        return "Android"
    if any(kw in combined for kw in ["windows", "msft", "microsoft", "surface"]):
        return "Windows"
    if any(kw in combined for kw in ["linux", "ubuntu", "raspberr", "debian"]):
        return "Linux"

    return "Unknown"


class NetworkScanner:
    """
    ARP-based network scanner.

    Discovers devices on the local subnet, resolves hostnames concurrently,
    identifies MAC vendors, and infers device types.
    """

    def __init__(self, target_ip: Optional[str] = None, timeout: int = 3, max_workers: int = 20):
        self.target_ip = target_ip or _get_local_subnet()
        self.timeout = timeout
        self.max_workers = max_workers

        if not self.target_ip:
            raise RuntimeError(
                "Could not determine target network. "
                "Pass target_ip explicitly, e.g. '192.168.1.0/24'"
            )

        logger.info(f"NetworkScanner initialized for subnet: {self.target_ip}")

    def scan(self) -> List[dict]:
        """
        Perform a single ARP scan of the target network.

        Returns a list of dicts, each with keys:
            ip, mac, hostname, vendor, device_type, os_family, is_online
        """
        logger.info(f"Starting ARP scan on {self.target_ip} ...")

        try:
            arp = ARP(pdst=self.target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered, _ = srp(ether / arp, timeout=self.timeout, verbose=0)
        except PermissionError:
            logger.error(
                "Permission denied: ARP scanning requires Administrator/root. "
                "Run the agent with elevated privileges."
            )
            return []
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            return []

        if not answered:
            logger.info("ARP scan complete — no devices responded.")
            return []

        logger.info(f"ARP scan got {len(answered)} responses. Resolving details...")

        # Collect raw results
        raw_devices = []
        for sent, received in answered:
            raw_devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc.upper(),
            })

        # Concurrent hostname resolution
        devices = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dev = {
                executor.submit(_resolve_hostname, dev["ip"]): dev
                for dev in raw_devices
            }
            for future in as_completed(future_to_dev):
                dev = future_to_dev[future]
                hostname = future.result()
                vendor = _lookup_vendor(dev["mac"])
                device_type = _infer_device_type(hostname, vendor)
                os_family = _infer_os_family(hostname, vendor)

                devices.append({
                    "ip": dev["ip"],
                    "mac": dev["mac"],
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": device_type,
                    "os_family": os_family,
                    "is_online": True,
                })

        logger.info(f"Scan complete. Discovered {len(devices)} device(s).")
        return devices


class PeriodicScanner:
    """Runs NetworkScanner at a configurable interval in a background thread."""

    def __init__(self, scanner: NetworkScanner, interval: int = 120, on_scan_complete=None):
        self.scanner = scanner
        self.interval = interval
        self.on_scan_complete = on_scan_complete
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the periodic scanning thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("PeriodicScanner is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="PeriodicScanner")
        self._thread.start()
        logger.info(f"PeriodicScanner started (interval={self.interval}s)")

    def stop(self):
        """Signal the periodic scanner to stop."""
        self._stop_event.set()
        logger.info("PeriodicScanner stop requested.")

    def _run(self):
        # Run first scan immediately
        self._do_scan()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.interval)
            if not self._stop_event.is_set():
                self._do_scan()

    def _do_scan(self):
        try:
            devices = self.scanner.scan()
            if self.on_scan_complete and devices:
                self.on_scan_complete(devices)
        except Exception as e:
            logger.error(f"Periodic scan failed: {e}", exc_info=True)
