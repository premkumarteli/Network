import requests
import logging

logger = logging.getLogger("netvisor.agent.api")


class APIClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-API-Key": api_key}

    def register(self, payload):
        return requests.post(
            f"{self.base_url}/collect/register",
            json=payload, headers=self.headers, timeout=10
        ).json()

    def heartbeat(self, payload):
        return requests.post(
            f"{self.base_url}/collect/heartbeat",
            json=payload, headers=self.headers, timeout=5
        ).json()

    def upload_flows(self, flows):
        return requests.post(
            f"{self.base_url}/collect/flow/batch",
            json=flows, headers=self.headers, timeout=10
        )

    def upload_devices(self, devices):
        """Upload ARP-discovered devices to the backend."""
        return requests.post(
            f"{self.base_url}/collect/devices/batch",
            json=devices, headers=self.headers, timeout=15
        )
