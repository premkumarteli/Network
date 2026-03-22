from types import SimpleNamespace

from agent.dpi import mitm_addon


class FakeHeaders(dict):
    def items(self):
        return super().items()


def test_extract_page_title_prefers_html_title():
    html = "<html><head><title>Example Title</title></head><body></body></html>"
    assert mitm_addon.extract_page_title(html) == "Example Title"


def test_extract_site_metadata_youtube_returns_video_id():
    category, content_id = mitm_addon.extract_site_metadata(
        "https://www.youtube.com/watch?v=abc123&list=PL1",
        "Example Video",
    )

    assert category == "video"
    assert content_id == "abc123"


def test_build_event_extracts_browser_title_and_url(monkeypatch):
    monkeypatch.setattr(mitm_addon, "ALLOWED_DOMAINS", {"youtube.com"})
    flow = SimpleNamespace(
        request=SimpleNamespace(
            pretty_host="www.youtube.com",
            pretty_url="https://www.youtube.com/watch?v=abc123",
            method="GET",
            headers=FakeHeaders({"User-Agent": "Mozilla/5.0 Chrome/123.0"}),
            raw_content=b"",
        ),
        response=SimpleNamespace(
            headers=FakeHeaders({"Content-Type": "text/html"}),
            content=b"<html><head><title>Cool Video</title></head></html>",
            status_code=200,
        ),
    )

    event = mitm_addon.build_event(flow)

    assert event is not None
    assert event["browser_name"] == "Chrome"
    assert event["process_name"] == "chrome.exe"
    assert event["page_title"] == "Cool Video"
    assert event["content_id"] == "abc123"


def test_build_event_maps_edge_to_msedge_process(monkeypatch):
    monkeypatch.setattr(mitm_addon, "ALLOWED_DOMAINS", {"github.com"})
    flow = SimpleNamespace(
        request=SimpleNamespace(
            pretty_host="github.com",
            pretty_url="https://github.com/openai/openai-python",
            method="GET",
            headers=FakeHeaders({"User-Agent": "Mozilla/5.0 Edg/123.0"}),
            raw_content=b"",
        ),
        response=SimpleNamespace(
            headers=FakeHeaders({"Content-Type": "text/html"}),
            content=b"<html><head><title>Repo</title></head></html>",
            status_code=200,
        ),
    )

    event = mitm_addon.build_event(flow)

    assert event is not None
    assert event["browser_name"] == "Edge"
    assert event["process_name"] == "msedge.exe"
