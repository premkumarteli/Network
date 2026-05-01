import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.api.dpi import DpiEventEmitter

@pytest.mark.anyio
async def test_dpi_event_emitter_payload_alignment():
    emitter = DpiEventEmitter()
    
    # Mock data representing a raw event from the agent/db
    mock_event = {
        "device_ip": "192.168.1.50",
        "process_name": "chrome.exe",
        "browser_name": "Google Chrome",
        "base_domain": "google.com",
        "page_url": "https://www.google.com/search?q=test+query",
        "page_title": "test query - Google Search",
        "content_category": "search",
        "last_seen": "2026-03-25 13:00:00",
        "search_query": "test query"
    }
    
    with patch("app.api.dpi.emit_event", new_callable=AsyncMock) as mock_emit:
        await emitter.emit(mock_event)
        
        # Verify emit_event was called
        assert mock_emit.called
        event_name, payload = mock_emit.call_args[0]
        
        assert event_name == "dpi_event"
        
        # Verify payload fields match frontend expectations
        assert payload["device_ip"] == "192.168.1.50"
        assert payload["process_name"] == "chrome.exe"
        assert payload["browser_name"] == "Google Chrome"
        assert payload["domain"] == "google.com"
        assert payload["page_url"] == "https://www.google.com/search?q=test+query"
        assert payload["page_title"] == "test query - Google Search"
        assert payload["content_category"] == "search"
        assert payload["timestamp"] == "2026-03-25 13:00:00"
        assert payload["search_query"] == "test query"

@pytest.mark.anyio
async def test_dpi_event_emitter_youtube_title_extraction():
    emitter = DpiEventEmitter()
    
    mock_event = {
        "device_ip": "192.168.1.50",
        "process_name": "chrome.exe",
        "base_domain": "youtube.com",
        "page_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "page_title": "YouTube", # Generic title often found initially
        "last_seen": "2026-03-25 13:00:00"
    }
    
    with patch("app.api.dpi.emit_event", new_callable=AsyncMock) as mock_emit:
        await emitter.emit(mock_event)
        
        assert mock_emit.called
        _, payload = mock_emit.call_args[0]
        
        # Verify YouTube title extraction worked
        assert payload["page_title"] == "YouTube Video (dQw4w9WgXcQ)"


@pytest.mark.anyio
async def test_dpi_event_emitter_extracts_bing_query():
    emitter = DpiEventEmitter()
    mock_event = {
        "device_ip": "192.168.1.50",
        "process_name": "msedge.exe",
        "browser_name": "Edge",
        "base_domain": "bing.com",
        "page_url": "https://www.bing.com/search?q=netvisor+dpi",
        "page_title": "netvisor dpi - Search",
        "content_category": "search",
        "last_seen": "2026-03-25 13:00:00",
    }

    with patch("app.api.dpi.emit_event", new_callable=AsyncMock) as mock_emit:
        await emitter.emit(mock_event)

        assert mock_emit.called
        _, payload = mock_emit.call_args[0]
        assert payload["search_query"] == "netvisor dpi"


@pytest.mark.anyio
async def test_dpi_event_emitter_keeps_tabs_separate_when_page_urls_differ():
    emitter = DpiEventEmitter()
    base_event = {
        "device_ip": "192.168.1.50",
        "process_name": "chrome.exe",
        "browser_name": "Google Chrome",
        "base_domain": "example.com",
        "page_title": "Example",
        "content_category": "web",
        "last_seen": "2026-03-25 13:00:00",
    }

    with patch("app.api.dpi.emit_event", new_callable=AsyncMock) as mock_emit:
        await emitter.emit({**base_event, "page_url": "https://example.com/tab-1"})
        await emitter.emit({**base_event, "page_url": "https://example.com/tab-2"})

        assert mock_emit.call_count == 2
