import queue
from pathlib import Path

from agent.dpi.event_buffer import EventBuffer
from agent.dpi.policy import InspectionPolicy


def _policy():
    return InspectionPolicy.from_payload(
        {
            "inspection_enabled": True,
            "allowed_processes": ["chrome.exe"],
            "allowed_domains": ["youtube.com"],
        },
        agent_id="AGENT-1",
        device_ip="10.0.0.5",
    )


def _context():
    return {
        "agent_id": "AGENT-1",
        "device_ip": "10.0.0.5",
        "organization_id": "default-org-id",
    }


class FakeProtector:
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        return b"protected:" + data

    def unprotect(self, data: bytes) -> bytes:
        return data.removeprefix(b"protected:")


class FakeApiClient:
    def request(self, method, url, *, json_body=None, params=None, timeout=10):
        raise AssertionError("Network uploads are not expected in this unit test")


def test_event_buffer_spools_when_queue_is_full(tmp_path):
    buffer = EventBuffer(
        runtime_dir=Path(tmp_path),
        upload_url="http://localhost/upload",
        api_client=FakeApiClient(),
        get_policy=_policy,
        get_context=_context,
        protector=FakeProtector(),
    )
    buffer.queue = queue.Queue(maxsize=1)
    buffer.queue.put_nowait({"placeholder": True})

    buffer.enqueue(
        {
            "process_name": "chrome.exe",
            "browser_name": "Chrome",
            "page_url": "https://www.youtube.com/watch?v=abc123",
            "base_domain": "youtube.com",
            "page_title": "Example Video",
            "content_category": "video",
            "content_id": "abc123",
        }
    )

    metrics = buffer.metrics_snapshot()
    assert metrics["spooled_event_count"] == 1
    assert buffer.spool_file.exists()
    assert "https://www.youtube.com/watch?v=abc123" not in buffer.spool_file.read_text(encoding="utf-8")


def test_event_buffer_records_drop_reason_for_blocked_domain(tmp_path):
    buffer = EventBuffer(
        runtime_dir=Path(tmp_path),
        upload_url="http://localhost/upload",
        api_client=FakeApiClient(),
        get_policy=_policy,
        get_context=_context,
        protector=FakeProtector(),
    )

    prepared = buffer._prepare_event(
        {
            "process_name": "chrome.exe",
            "browser_name": "Chrome",
            "page_url": "https://github.com/openai/openai-python",
            "base_domain": "github.com",
            "page_title": "Repo",
        }
    )

    assert prepared is None
    metrics = buffer.metrics_snapshot()
    assert metrics["dropped_event_count"] == 1
    assert metrics["drop_reasons"]["domain_not_allowed"] == 1
