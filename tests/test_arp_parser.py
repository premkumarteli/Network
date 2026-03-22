import sys
import os
import socket
import unittest
from unittest.mock import patch
from types import SimpleNamespace

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.device_detector import DeviceDetector

class TestARPParser(unittest.TestCase):
    def setUp(self):
        self.detector = DeviceDetector()
        self.sample_output = """
Interface: 192.168.56.1 --- 0xb
  Internet Address      Physical Address      Type
  192.168.56.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 172.26.162.96 --- 0x10
  Internet Address      Physical Address      Type
  172.26.162.166        ce-9f-d4-29-c8-85     dynamic
  172.26.162.191        14-d4-24-33-31-4f     dynamic
  172.26.162.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.102.18        01-00-5e-7f-66-12     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
"""

    @patch('platform.system', return_value='Windows')
    @patch('subprocess.check_output')
    def test_parse_arp_table(self, mock_subprocess, mock_platform):
        mock_subprocess.return_value = self.sample_output.encode()
        
        arp_map = self.detector.parse_arp_table()
        
        # Expected dynamic/unicast IPs
        self.assertIn('172.26.162.166', arp_map)
        self.assertIn('172.26.162.191', arp_map)
        
        # Expected filtered IPs (broadcast/multicast)
        self.assertNotIn('192.168.56.255', arp_map)
        self.assertNotIn('224.0.0.22', arp_map)
        self.assertNotIn('255.255.255.255', arp_map)
        
        # Check normalization
        self.assertEqual(arp_map['172.26.162.166'], 'ce:9f:d4:29:c8:85')
        self.assertEqual(arp_map['172.26.162.191'], '14:d4:24:33:31:4f')
        
        print("\n[SUCCESS] ARP Parsing and Filtering Logic Verified.")
        print(f"Discovered {len(arp_map)} valid unicast devices.")

    @patch("psutil.net_if_addrs")
    def test_infer_local_network_uses_interface_netmask(self, mock_net_if_addrs):
        mock_net_if_addrs.return_value = {
            "Ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="10.128.88.96",
                    netmask="255.255.255.0",
                )
            ]
        }

        detector = DeviceDetector(local_ip="10.128.88.96")
        self.assertEqual(detector.infer_local_network(), "10.128.88.0/24")

    def test_collect_arp_candidates_merges_active_and_passive_sources(self):
        detector = DeviceDetector(local_ip="10.128.88.96")
        detector.parse_arp_table = lambda: {
            "10.128.88.131": "aa:bb:cc:dd:ee:01",
            "10.128.88.96": "aa:bb:cc:dd:ee:ff",
        }
        detector.arp_scan = lambda network=None: [
            {"ip": "10.128.88.172", "mac": "aa:bb:cc:dd:ee:02"},
            {"ip": "224.0.0.22", "mac": "01:00:5e:00:00:16"},
        ]

        candidates = detector.collect_arp_candidates("10.128.88.0/24")

        self.assertEqual(
            candidates,
            {
                "10.128.88.131": "aa:bb:cc:dd:ee:01",
                "10.128.88.172": "aa:bb:cc:dd:ee:02",
            },
        )

if __name__ == '__main__':
    unittest.main()

