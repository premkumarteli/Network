import logging
from .packet_capture import PacketCapture
from .flow_engine import FlowEngine

logger = logging.getLogger("netvisor.gateway")

class NetVisorGateway:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key
        self.flow_engine = FlowEngine()
        self.capture = PacketCapture(callback=self.flow_engine.process_packet)

    def start(self):
        logger.info("[+] NetVisor Gateway Metadata Inspector starting...")
        self.capture.start()

if __name__ == "__main__":
    # Placeholder initialization
    gateway = NetVisorGateway("http://localhost:8000/api/v1", "soc-gateway-key")
    gateway.start()
