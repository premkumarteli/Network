from agent.device_detector import DeviceDetector


def test_parse_ping_hostname_windows_output():
    detector = DeviceDetector()
    output = "Pinging LAB-DESKTOP [192.168.1.24] with 32 bytes of data:"

    assert detector._parse_ping_hostname(output, "192.168.1.24") == "LAB-DESKTOP"


def test_resolve_hostname_uses_first_valid_strategy(monkeypatch):
    detector = DeviceDetector()

    monkeypatch.setattr(detector, "get_dns_name", lambda ip: None)
    monkeypatch.setattr(detector, "get_netbios_name", lambda ip: "OFFICE-PRINTER")
    monkeypatch.setattr(detector, "get_nbtstat_name", lambda ip: "SHOULD-NOT-BE-USED")
    monkeypatch.setattr(detector, "get_ping_name", lambda ip: "SHOULD-NOT-BE-USED")

    assert detector.resolve_hostname("192.168.1.50") == "OFFICE-PRINTER"


def test_normalize_hostname_rejects_ip_like_names():
    detector = DeviceDetector()

    assert detector._normalize_hostname("192-168-1-40", "192.168.1.40") is None
    assert detector._normalize_hostname("printer-room.local", "192.168.1.41") == "printer-room"


def test_extract_xml_name_reads_upnp_friendly_name():
    detector = DeviceDetector()
    xml_text = """
    <root>
        <device>
            <friendlyName>Living-Room-TV</friendlyName>
        </device>
    </root>
    """

    assert detector._extract_xml_name(xml_text, "192.168.1.90") == "Living-Room-TV"


def test_get_chromecast_name_prefers_device_name(monkeypatch):
    detector = DeviceDetector()
    payload = '{"device_info": {"name": "Bedroom TV"}}'

    monkeypatch.setattr(detector, "_http_get_text", lambda url, timeout=1.5: payload)

    assert detector.get_chromecast_name("192.168.1.91") == "Bedroom TV"


def test_get_upnp_name_uses_cached_discovery_locations(monkeypatch):
    detector = DeviceDetector()
    xml_text = """
    <root>
        <device>
            <friendlyName>Family Room TV</friendlyName>
        </device>
    </root>
    """

    monkeypatch.setattr(
        detector,
        "_discover_upnp_locations",
        lambda: {"192.168.1.92": ["http://192.168.1.92:1400/xml/device_description.xml"]},
    )
    monkeypatch.setattr(detector, "_http_get_text", lambda url, timeout=1.2: xml_text)

    assert detector.get_upnp_name("192.168.1.92") == "Family Room TV"

