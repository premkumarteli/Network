import ipaddress

class VPNDetector:
    def __init__(self):
        # Example suspicious ranges (In production, load from a database or API)
        self.suspicious_ranges = [
            # Dummy examples
            "103.1.2.0/24",
            "45.2.3.0/24"
        ]

    def is_suspicious_ip(self, ip):
        """Checks if IP belongs to known VPN/suspicious ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.suspicious_ranges:
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except:
            pass
        return False

    def analyze_vpn(self, src_ip, dst_ip, port):
        """
        Returns: score, reason
        """
        score = 0
        reason = ""
        
        # 1. Destination IP Check
        if self.is_suspicious_ip(dst_ip):
            score += 15
            reason = "Traffic to known VPN/Proxy range"
            
        # 2. Port patterns (common VPN ports)
        if port in ["1194", "443", "500", "4500", "1701"]:
            # port 443 is common for everything, so we need more context
            # but 1194 (OpenVPN) or 500/4500 (IPsec) are stronger flags
            if port in ["1194", "500", "4500"]:
                score += 10
                reason = "VPN Protocol Port detected"
                
        return score, reason
