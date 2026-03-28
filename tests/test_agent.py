import sys
from unittest.mock import MagicMock

# Mock external dependencies before they are imported in agent.py
mock_scapy = MagicMock()
sys.modules['scapy'] = mock_scapy
sys.modules['scapy.all'] = mock_scapy

mock_requests = MagicMock()
sys.modules['requests'] = mock_requests

mock_colorama = MagicMock()
sys.modules['colorama'] = mock_colorama

import pytest
from unittest.mock import patch
from agent import NetworkAgent

@pytest.fixture
def mock_agent():
    # Mocking internal methods that have side effects
    with patch('agent.threading.Thread'), \
         patch('agent.requests.post'), \
         patch('agent.NetworkAgent._register_agent'), \
         patch('agent.NetworkAgent._init_local_log'), \
         patch('agent.NetworkAgent._get_all_local_ips', return_value=['127.0.0.1']), \
         patch('agent.socket.gethostname', return_value='test-host'):
        agent = NetworkAgent(config_path="non_existent.json")
        yield agent

def test_resolve_vendor_known_oui(mock_agent):
    """Test resolve_vendor with known MAC prefixes."""
    assert mock_agent.resolve_vendor("00:0c:29:11:22:33") == "VMware"
    assert mock_agent.resolve_vendor("08:00:27:aa:bb:cc") == "Oracle/VirtualBox"
    assert mock_agent.resolve_vendor("b8:27:eb:11:22:33") == "Raspberry Pi"

def test_resolve_vendor_case_insensitive(mock_agent):
    """Test resolve_vendor with different cases."""
    assert mock_agent.resolve_vendor("00:0C:29:11:22:33") == "VMware"
    assert mock_agent.resolve_vendor("00:0c:29:AA:BB:CC") == "VMware"

def test_resolve_vendor_unknown_oui(mock_agent):
    """Test resolve_vendor with unknown MAC prefixes."""
    assert mock_agent.resolve_vendor("ff:ff:ff:11:22:33") == "Unknown"
    assert mock_agent.resolve_vendor("12:34:56:78:90:ab") == "Unknown"

def test_resolve_vendor_empty_or_none(mock_agent):
    """Test resolve_vendor with empty or None input."""
    assert mock_agent.resolve_vendor("") == "Unknown"
    assert mock_agent.resolve_vendor(None) == "Unknown"

def test_resolve_vendor_short_mac(mock_agent):
    """Test resolve_vendor with shorter than expected input."""
    assert mock_agent.resolve_vendor("00:0c:29") == "VMware"
    assert mock_agent.resolve_vendor("00:0c") == "Unknown"
