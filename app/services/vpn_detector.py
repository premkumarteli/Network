import ipaddress

class VPNDetector:
    def __init__(self):
        self.suspicious_ranges = [
            "103.1.2.0/24",
            "45.2.3.0/24",
        ]
        self.suspicious_ports = {
            1194,  # OpenVPN
            1197,
            1198,
            1723,  # PPTP
            1701,  # L2TP
            500,   # IPsec/IKE
            4500,  # IPsec NAT-T
            51820, # WireGuard
        }
        self.suspicious_keywords = {
            "vpn",
            "proxy",
            "openvpn",
            "wireguard",
            "ipsec",
            "nord",
            "expressvpn",
            "surfshark",
            "protonvpn",
            "mullvad",
            "windscribe",
            "tunnelbear",
            "privatevpn",
            "hidemy",
        }

    def is_suspicious_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.suspicious_ranges:
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except:
            pass
        return False

    def _normalize_host(self, host):
        if not host:
            return ""
        return str(host).strip().lower()

    def analyze_vpn(self, src_ip, dst_ip, port, host: str | None = None):
        score = 0
        reasons = []
        if self.is_suspicious_ip(dst_ip):
            score += 20
            reasons.append("Traffic to known VPN/Proxy range")
        if int(port or 0) in self.suspicious_ports:
            score += 12
            reasons.append("VPN protocol port detected")

        normalized_host = self._normalize_host(host)
        if normalized_host and any(keyword in normalized_host for keyword in self.suspicious_keywords):
            score += 10
            reasons.append("VPN/proxy keyword in hostname")

        return min(score, 40), "; ".join(reasons)

vpn_detector = VPNDetector()
