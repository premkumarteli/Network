import collections
import math

class RuleEngine:
    def __init__(self, risk_threshold=6):
        self.risk_threshold = risk_threshold
        # Top benign domains to skip heavy processing
        self.whitelist = {"google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com"}

    def calculate_entropy(self, text):
        if not text: return 0
        counter = collections.Counter(text)
        total = len(text)
        return -sum((count/total) * math.log2(count/total) for count in counter.values())

    def analyze(self, domain):
        """
        Analyze logic migrated from detector.py
        Returns: (score, entropy)
        """
        score = 0
        parts = domain.split('.')
        longest_part = max(parts, key=len) if parts else domain
        
        if any(w in domain for w in self.whitelist):
            return 0, 0

        # Heuristic 1: Length
        if len(longest_part) > 25: score += 2
        
        # Heuristic 2: Digit Count
        if sum(c.isdigit() for c in longest_part) > 5: score += 2
        
        # Heuristic 3: Entropy
        ent = self.calculate_entropy(longest_part)
        if ent > 4.5: score += 3
        
        return score, ent
