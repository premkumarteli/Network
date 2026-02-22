import time
import collections

class AnomalyEngine:
    def __init__(self):
        # In-memory session state for behavioral tracking
        self.ip_counts = collections.defaultdict(int)
        self.nx_counts = collections.defaultdict(int)
        self.unique_domains = collections.defaultdict(set)
        self.start_time = time.time()

    def analyze_behavior(self, src_ip, domain, rcode=0, baseline=None):
        """
        Stateful analysis compared against baseline.
        Returns: score
        """
        score = 0
        
        # 1. Error Rate Tracking (NXDOMAIN)
        if rcode != 0:
            self.nx_counts[src_ip] += 1
            if self.nx_counts[src_ip] > 10:
                score += 2
        
        # 2. Volume and Variety
        self.ip_counts[src_ip] += 1
        self.unique_domains[src_ip].add(domain)
        
        if len(self.unique_domains[src_ip]) > 50:
            score += 3
            
        # 3. Baseline Comparison (if provided)
        elapsed = time.time() - self.start_time
        if elapsed > 60: # At least 1 minute of data for rate calc
            rate = self.ip_counts[src_ip] / (elapsed / 60) # QPM
            
            if baseline:
                # If rate is 5x the baseline, trigger anomaly
                if baseline.avg_packet_rate > 0 and rate > (baseline.avg_packet_rate * 5):
                    score += 5
            else:
                # Default heuristic if no baseline exists
                if rate > 100: score += 2

        # Reset counters every 5 minutes to prevent memory bloat and stale spikes
        if time.time() - self.start_time > 300:
            self.reset_counters()
            
        return score

    def reset_counters(self):
        self.ip_counts.clear()
        self.nx_counts.clear()
        self.unique_domains.clear()
        self.start_time = time.time()
