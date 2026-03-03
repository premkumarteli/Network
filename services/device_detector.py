import socket
import concurrent.futures
import subprocess
import re
from scapy.all import ARP, Ether, srp

class DeviceDetector:

    def __init__(self, network=None):
        self.network = network

    # ---------------------------
    # 1️⃣ ACTIVE ARP SCAN
    # ---------------------------
    def arp_scan(self, network=None):
        target_network = network or self.network
        if not target_network:
            return []
        print(f"\n[+] Scanning network: {target_network}")
        devices = []
        try:
            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=2, verbose=0)[0]

            for sent, received in result:
                devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc.lower()
                })
        except Exception as e:
            print(f"[-] Error during ARP scan: {e}")

        return devices

    # ---------------------------
    # 1.5️⃣ PASSIVE ARP PARSING
    # ---------------------------
    def parse_arp_table(self):
        """Parses the local system's ARP table (Windows/Linux)."""
        arp_results = {}
        try:
            # Run 'arp -a' command
            cmd = ["arp", "-a"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(errors="ignore")
            
            # Simple regex search for IP and MAC
            # Matches formats like (192.168.1.1) at 00:11:22:33:44:55 on Linux
            # Matches formats like 192.168.1.1 00-11-22-33-44-55 on Windows
            pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})')
            
            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    arp_results[ip] = mac
        except Exception as e:
            print(f"[-] Error parsing ARP table: {e}")
            
        return arp_results

    # ---------------------------
    # 2️⃣ NETBIOS NAME RESOLUTION
    # ---------------------------
    def get_netbios_name(self, ip):
        netbios_query = (
            b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)

        try:
            sock.sendto(netbios_query, (ip, 137))
            data, _ = sock.recvfrom(1024)

            if len(data) > 57:
                num_names = data[56]
                offset = 57

                for _ in range(num_names):
                    name = data[offset:offset+15].decode(errors="ignore").strip()
                    if name and name != "*":
                        return name
                    offset += 18
        except:
            pass
        finally:
            sock.close()

        return None

    # ---------------------------
    # 3️⃣ DNS FALLBACK
    # ---------------------------
    def get_dns_name(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    # ---------------------------
    # 4️⃣ PORT FINGERPRINTING
    # ---------------------------
    def detect_device_type(self, ip):
        common_ports = {
            445: "Windows Device",
            22: "Linux/Unix Device",
            80: "Web Device",
            443: "Secure Web Device",
            9100: "Printer",
            502: "PLC / Industrial Device"
        }

        for port, device_type in common_ports.items():
            try:
                sock = socket.socket()
                sock.settimeout(0.3)
                sock.connect((ip, port))
                sock.close()
                return device_type
            except:
                continue

        return "Unknown Type"

    # ---------------------------
    # 5️⃣ MAC VENDOR CHECK
    # ---------------------------
    def detect_virtual_mac(self, mac):
        first_octet = int(mac.split(":")[0], 16)
        if first_octet & 2:
            return " (Locally Administered / Virtual)"
        return ""

    # ---------------------------
    # 6️⃣ FULL DISCOVERY
    # ---------------------------
    def full_scan(self, network=None):
        devices = self.arp_scan(network)
        final_results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = {}

            for device in devices:
                ip = device["ip"]
                futures[executor.submit(self.resolve_device, device)] = device

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                final_results.append(result)

        return final_results

    def resolve_device(self, device):
        ip = device["ip"]
        mac = device["mac"]

        name = self.get_netbios_name(ip)
        if not name:
            name = self.get_dns_name(ip)
        if not name:
            name = "Unknown-Device"

        device_type = self.detect_device_type(ip)
        mac_note = self.detect_virtual_mac(mac)

        return {
            "name": name,
            "ip": ip,
            "mac": mac + mac_note,
            "type": device_type
        }


# ---------------------------
# 🚀 MAIN
# ---------------------------
if __name__ == "__main__":

    network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()

    scanner = DeviceDetector(network_range)
    results = scanner.full_scan()

    print("\n" + "-" * 90)
    print(f"{'NAME':<25} | {'IP ADDRESS':<15} | {'MAC ADDRESS':<30} | {'TYPE'}")
    print("-" * 90)

    for dev in results:
        print(f"{dev['name']:<25} | {dev['ip']:<15} | {dev['mac']:<30} | {dev['type']}")

    print("-" * 90)
    print(f"\nTotal Devices Found: {len(results)}")