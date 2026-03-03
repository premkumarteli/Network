import math
import collections
import logging

logger = logging.getLogger("netvisor.detection.dns")

class DNSAnalyzer:
    def __init__(self):
        # Whitelist of common apex domains
        self.whitelist = {"google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "cloudfront.net", "akamai.net"}

    def calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
        counter = collections.Counter(text)
        total = len(text)
        return -sum((count/total) * math.log2(count/total) for count in counter.values())

    def is_dga(self, domain: str) -> bool:
        """Simple DGA detection based on entropy and length."""
        parts = domain.split('.')
        if not parts: return False
        longest_part = max(parts, key=len)
        
        entropy = self.calculate_entropy(longest_part)
        
        # Heuristic: high entropy in a long domain part
        if len(longest_part) > 15 and entropy > 4.2:
            return True
        return False

    def analyze(self, domain: str) -> float:
        """
        Returns a normalized dns_score (0-1).
        """
        if any(w in domain for w in self.whitelist):
            return 0.0
            
        score = 0.0
        
        # 1. Entropy/DGA check
        if self.is_dga(domain):
            score += 0.6
            
        # 2. Length check
        if len(domain) > 50:
            score += 0.2
            
        # 3. Numeric content
        digits = sum(c.isdigit() for c in domain)
        if digits > 5:
            score += 0.2
            
        return min(1.0, score)

dns_analyzer = DNSAnalyzer()
