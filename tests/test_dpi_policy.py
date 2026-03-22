from agent.dpi.policy import InspectionPolicy


def test_policy_normalizes_process_and_domain_allowlists():
    policy = InspectionPolicy.from_payload(
        {
            "inspection_enabled": True,
            "allowed_processes": [" Chrome.exe ", "msedge.exe", "chrome.exe"],
            "allowed_domains": ["https://www.youtube.com/watch?v=1", "api.openai.com", "youtube.com"],
            "snippet_max_bytes": 999,
        },
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
    )

    assert policy.inspection_enabled is True
    assert policy.allowed_processes == ["chrome.exe", "msedge.exe"]
    assert policy.allowed_domains == ["youtube.com", "openai.com"]
    assert policy.snippet_max_bytes == 256


def test_policy_matches_base_domain_and_process():
    policy = InspectionPolicy.from_payload(
        {
            "inspection_enabled": True,
            "allowed_processes": ["chrome.exe"],
            "allowed_domains": ["youtube.com"],
        },
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
    )

    assert policy.allows_process("CHROME.EXE")
    assert policy.allows_domain("m.youtube.com")
    assert not policy.allows_process("msedge.exe")
    assert not policy.allows_domain("github.com")
