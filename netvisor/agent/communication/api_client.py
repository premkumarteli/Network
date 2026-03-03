import requests
import logging

logger = logging.getLogger("netvisor.agent.api")

class APIClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-API-Key": api_key}

    def register(self, payload):
        return requests.post(f"{self.base_url}/agents/register", json=payload, headers=self.headers, timeout=10).json()

    def heartbeat(self, payload):
        return requests.post(f"{self.base_url}/agents/heartbeat", json=payload, headers=self.headers, timeout=5).json()

    def upload_flows(self, flows):
        return requests.post(f"{self.base_url}/flows/batch", json=flows, headers=self.headers, timeout=10)
