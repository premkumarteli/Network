import pytest
import requests

BASE_URL = "http://127.0.0.1:8000"

def test_system_health():
    """Verify that the system health endpoint is reachable."""
    try:
        response = requests.get(f"{BASE_URL}/api/v1/health/status", timeout=5)
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        pytest.skip("Server is not reachable at http://127.0.0.1:8000")

def test_stats_endpoint_requires_auth():
    """Verify that the stats endpoint requires authentication."""
    try:
        response = requests.get(f"{BASE_URL}/api/v1/dashboard/overview", timeout=5)
        assert response.status_code in [401, 403]
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        pytest.skip("Server is not reachable")

def test_login_page_exists():
    """Verify that the root route responds even if frontend assets are not built."""
    try:
        response = requests.get(BASE_URL, timeout=5)
        assert response.status_code == 200
        body = response.text.lower()
        assert "<html" in body or "frontend build not found" in body
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        pytest.skip("Server is not reachable")

