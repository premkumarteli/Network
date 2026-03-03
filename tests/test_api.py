import pytest
import requests

BASE_URL = "http://127.0.0.1:8000"

def test_system_health():
    """Verify that the system health endpoint is reachable."""
    try:
        response = requests.get(f"{BASE_URL}/api/system-health", timeout=5)
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    except requests.exceptions.ConnectionError:
        pytest.skip("Server is not running at http://127.0.0.1:8000")

def test_stats_endpoint_requires_auth():
    """Verify that the stats endpoint requires authentication."""
    try:
        response = requests.get(f"{BASE_URL}/api/stats", timeout=5)
        # Assuming it returns 401/403 or redirects to login
        assert response.status_code in [401, 403, 302]
    except requests.exceptions.ConnectionError:
        pytest.skip("Server is not running")

def test_login_page_exists():
    """Verify that the main frontend/login page is served."""
    try:
        response = requests.get(BASE_URL, timeout=5)
        assert response.status_code == 200
        assert "<html" in response.text.lower()
    except requests.exceptions.ConnectionError:
        pytest.skip("Server is not running")
