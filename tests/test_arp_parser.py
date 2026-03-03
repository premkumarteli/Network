import sys
import os
import unittest
from unittest.mock import patch

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.device_detector import DeviceDetector

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

if __name__ == '__main__':
    unittest.main()
