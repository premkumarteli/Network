import ipaddress

class VPNDetector:
    def __init__(self):
        self.suspicious_ranges = ["103.1.2.0/24", "45.2.3.0/24"]

    def is_suspicious_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.suspicious_ranges:
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except:
            pass
        return False

    def analyze_vpn(self, src_ip, dst_ip, port):
        score = 0
        reason = ""
        if self.is_suspicious_ip(dst_ip):
            score += 15
            reason = "Traffic to known VPN/Proxy range"
        if str(port) in ["1194", "500", "4500"]:
            score += 10
            reason = "VPN Protocol Port detected"
        return score, reason

vpn_detector = VPNDetector()
