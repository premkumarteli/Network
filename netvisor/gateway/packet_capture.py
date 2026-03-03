from scapy.all import sniff
import logging

class PacketCapture:
    def __init__(self, callback):
        self.callback = callback

    def start(self, interface=None):
        logging.info(f"[*] Starting packet capture on {interface or 'default interface'}")
        sniff(iface=interface, prn=self.callback, store=False)
