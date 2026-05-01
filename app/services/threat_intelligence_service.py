import re
from typing import Optional

class ThreatIntelligenceService:
    def __init__(self):
        # Basic suspicious keywords and TLDs
        self.suspicious_keywords = [
            "malware", "phishing", "spyware", "trojan", "keylogger",
            "bit.ly", "tinyurl.com", "cutt.ly", # URL shorteners can be suspicious in corporate env
            "free-prize", "account-verify", "login-update"
        ]
        
        self.suspicious_tlds = [".zip", ".mov", ".top", ".xyz", ".buzz", ".monster"]
        
        # known malicious domains (sample for student project)
        self.blacklist = {
            "example-malware.com",
            "suspicious-site.net",
            "evil-tracking.org"
        }

    def check_threat(self, event: dict) -> dict:
        """
        Analyzes a web event for potential threats.
        Returns a dict with 'risk_level' (safe, yellow, red) and 'threat_msg'.
        """
        base_domain = event.get("base_domain", "").lower()
        url = event.get("page_url", "").lower()
        
        # 1. Blacklist Check
        if base_domain in self.blacklist:
            return {"risk_level": "red", "threat_msg": "Blacklisted Malicious Domain"}
            
        # 2. Keyword & TLD Analysis
        for kw in self.suspicious_keywords:
            if kw in url:
                return {"risk_level": "yellow", "threat_msg": f"Suspicious Keyword Detected: {kw}"}
                
        for tld in self.suspicious_tlds:
            if base_domain.endswith(tld):
                return {"risk_level": "yellow", "threat_msg": f"Suspicious TLD Detected: {tld}"}
                
        # 3. Anomaly: High Event Count (Aggregated)
        event_count = event.get("event_count", 1)
        if event_count > 50:
            return {"risk_level": "yellow", "threat_msg": "High Request Frequency (Possible Tunneling)"}
            
        # 4. Content Type Anomaly
        content_type = event.get("content_type", "")
        if content_type and "application/x-msdownload" in content_type:
            return {"risk_level": "red", "threat_msg": "Executable Download Detected"}

        return {"risk_level": "safe", "threat_msg": None}

# Global singleton
threat_intel = ThreatIntelligenceService()
