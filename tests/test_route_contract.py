from app.api.router import api_router


FRONTEND_API_CONTRACT = {
    ("POST", "/auth/login"),
    ("POST", "/auth/register"),
    ("POST", "/auth/logout"),
    ("GET", "/auth/me"),
    ("GET", "/health/status"),
    ("GET", "/devices/"),
    ("GET", "/alerts/"),
    ("GET", "/alerts/ranking"),
    ("GET", "/dashboard/overview"),
    ("GET", "/dashboard/activity"),
    ("GET", "/dashboard/traffic-history"),
    ("GET", "/dashboard/device-stats"),
    ("GET", "/web/activity"),
    ("GET", "/web/activity/groups"),
    ("GET", "/apps/summary"),
    ("GET", "/analytics/overview"),
    ("GET", "/analytics/export"),
    ("GET", "/dpi/status"),
    ("GET", "/apps/{app_name}/devices"),
    ("GET", "/dpi/apps/{app_name}"),
    ("GET", "/logs/flows"),
    ("GET", "/logs/stats"),
    ("GET", "/web/devices/{device_ip}/activity"),
    ("GET", "/web/devices/{device_ip}/activity/groups"),
    ("GET", "/web/devices/{device_ip}/status"),
    ("POST", "/web/policies/{agent_id}"),
    ("GET", "/system/admin-stats"),
    ("GET", "/system/status"),
    ("GET", "/system/logs"),
    ("POST", "/system/settings/maintenance"),
    ("POST", "/system/settings/monitoring"),
    ("POST", "/system/actions/scan"),
    ("POST", "/system/reset-data"),
    ("GET", "/agents/"),
    ("GET", "/agents/{agent_id}"),
}


def test_frontend_api_contract_matches_backend_routes():
    backend_routes = set()
    for route in api_router.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", []) or []
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            backend_routes.add((method, path))

    missing = sorted(FRONTEND_API_CONTRACT - backend_routes)
    assert not missing, f"Frontend API contract is missing backend routes: {missing}"
