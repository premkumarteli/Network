from app.utils.network import (
    classify_ip_scope,
    is_rfc1918_device_ip,
    is_unicast_mac,
    normalize_ip,
    normalize_mac,
)


def test_rfc1918_device_ip_is_strict_to_supported_lan_ranges():
    assert is_rfc1918_device_ip("10.10.10.10") is True
    assert is_rfc1918_device_ip("172.16.1.25") is True
    assert is_rfc1918_device_ip("192.168.1.10") is True
    assert is_rfc1918_device_ip("172.15.1.25") is False
    assert is_rfc1918_device_ip("169.254.1.10") is False
    assert is_rfc1918_device_ip("8.8.8.8") is False


def test_ip_scope_classification_separates_internal_external_and_control():
    assert classify_ip_scope("10.128.88.96") == "internal"
    assert classify_ip_scope("8.8.8.8") == "external"
    assert classify_ip_scope("255.255.255.255") == "control"
    assert classify_ip_scope("224.0.0.1") == "control"
    assert classify_ip_scope("not-an-ip") == "invalid"


def test_mac_normalization_and_unicast_filtering():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert is_unicast_mac("aa:bb:cc:dd:ee:ff") is True
    assert is_unicast_mac("ff:ff:ff:ff:ff:ff") is False
    assert normalize_ip(" 10.0.0.5 ") == "10.0.0.5"
