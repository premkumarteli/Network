import os
import pickle
import math
import numpy as np
import threading
from collections import Counter
from sklearn.ensemble import RandomForestClassifier

class DNSThreatClassifier:
    def __init__(self, model_path="services/ml/models/dns_threat_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.lock = threading.Lock()
        
        # Ensure model directory exists
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                    print("[+] ML Model Loaded Successfully")
            except Exception as e:
                print(f"[-] Failed to load model: {e}")
        else:
            print("[!] No model found. Training initial model...")
            self.train_initial_model()

    def extract_features(self, domain):
        """Extract lexical features from domain"""
        if not domain: return [0, 0, 0, 0, 0]
        
        domain = domain.lower()
        parts = domain.split('.')
        main_part = parts[0] if parts else domain
        
        length = len(main_part)
        entropy = self.calculate_entropy(main_part)
        digit_count = sum(c.isdigit() for c in main_part)
        digit_ratio = digit_count / length if length > 0 else 0
        vowel_count = sum(1 for c in main_part if c in 'aeiou')
        vowel_ratio = vowel_count / length if length > 0 else 0
        subdomain_count = len(parts) - 1
        
        # New features
        consecutive_consonants = self._max_consecutive_consonants(main_part)
        
        return [length, entropy, digit_ratio, vowel_ratio, subdomain_count, consecutive_consonants]

    def _max_consecutive_consonants(self, text):
        max_c = 0
        current = 0
        vowels = set('aeiou')
        for char in text:
            if char.isalpha() and char not in vowels:
                current += 1
                max_c = max(max_c, current)
            else:
                current = 0
        return max_c

    def calculate_entropy(self, text):
        if not text: return 0
        counter = Counter(text)
        total = len(text)
        return -sum((count/total) * math.log2(count/total) for count in counter.values())

    def train_initial_model(self):
        """Train a lightweight initial model avoiding external dependencies if possible"""
        # Feature Vector: [length, entropy, digit_ratio, vowel_ratio, subdomain_count]
        
        # Benign Samples (Google, Facebook, etc.)
        X_benign = [
            [6, 1.9, 0.0, 0.5, 1, 1], # google
            [8, 2.5, 0.0, 0.5, 1, 2], # facebook
            [7, 2.8, 0.0, 0.3, 1, 2], # youtube
            [6, 2.6, 0.0, 0.3, 1, 1], # amazon
            [9, 2.9, 0.0, 0.4, 2, 3], # wikipedia
            [4, 2.0, 0.0, 0.5, 1, 1], # bing
        ]
        y_benign = [0] * len(X_benign)

        # Malicious/DGA Samples (High entropy, random digits)
        X_malicious = [
            [15, 3.8, 0.2, 0.1, 1, 6], # a1b2c3d4e5f6g7
            [20, 4.2, 0.3, 0.1, 1, 8], # 9876543210qwerty
            [12, 3.5, 0.0, 0.0, 3, 7], # xklqwpzjv.com
            [18, 3.9, 0.5, 0.1, 2, 9], # 1234567890abcdef.net
            [25, 4.5, 0.1, 0.1, 4, 10], # super-long-random-string
        ]
        y_malicious = [1] * len(X_malicious)

        X = np.array(X_benign + X_malicious)
        y = np.array(y_benign + y_malicious)

        clf = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
        clf.fit(X, y)
        
        with self.lock:
            self.model = clf
            with open(self.model_path, "wb") as f:
                pickle.dump(clf, f)
        print("[+] Initial ML Model Trained & Saved")

    def predict_risk(self, domain):
        """Returns risk probability (0.0 - 1.0)"""
        if not self.model: return 0.0
        
        try:
            features = np.array([self.extract_features(domain)])
            with self.lock:
                prob = self.model.predict_proba(features)[0][1] # Probability of class 1 (Malicious)
            return prob
        except Exception:
            # print(f"Prediction Error: {e}")
            return 0.0

# Singleton Instance
ml_engine = DNSThreatClassifier()