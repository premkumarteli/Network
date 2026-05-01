from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..core.config import settings
from ..core.dependencies import require_org_admin, request_rate_limit
from ..db.session import get_db_connection
from ..services.alert_service import alert_service
from ..services.release_service import release_service
from ..services.system_service import system_service

router = APIRouter()

admin_mutation_rate_limit = request_rate_limit(
    limit=settings.ADMIN_MUTATION_RATE_LIMIT_PER_MINUTE,
    window_seconds=60,
    bucket="admin_mutation",
)


class ToggleRequest(BaseModel):
    active: bool


@router.get("/admin-stats")
async def get_admin_stats(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        return system_service.get_admin_stats(conn)
    finally:
        conn.close()


@router.get("/status")
async def get_system_status(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        runtime = system_service.get_runtime_status(conn)
        return {
            "active": runtime["active"],
            "maintenance_mode": runtime["maintenance_mode"],
            "runtime": runtime,
            "release": release_service.snapshot(),
            "backup": system_service.latest_backup_status(),
            "backup_retention": system_service.backup_retention_status(),
        }
    finally:
        conn.close()


@router.get("/release")
async def get_release_status(current_user: dict = Depends(require_org_admin)):
    return {
        "release": release_service.snapshot(),
        "backup": system_service.latest_backup_status(),
        "backup_retention": system_service.backup_retention_status(),
    }


@router.get("/logs")
async def get_system_logs(current_user: dict = Depends(require_org_admin), limit: int = 20):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        recent_alerts = alert_service.get_alerts(conn, organization_id=org_id, limit=limit * 2)
        vpn_alerts = [
            alert
            for alert in recent_alerts
            if (alert.get("breakdown", {}).get("vpn_score", 0) or 0) > 0.3
            or "Possible VPN/Proxy Usage" in alert.get("breakdown", {}).get("reasons", [])
        ][:limit]
        return {
            "admin": system_service.list_logs(conn, organization_id=org_id, limit=limit),
            "vpn": vpn_alerts,
        }
    finally:
        conn.close()


@router.post("/settings/maintenance")
async def set_maintenance_mode(
    payload: ToggleRequest,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        return system_service.set_maintenance(
            conn,
            active=payload.active,
            username=current_user.get("username", "admin"),
            organization_id=current_user.get("organization_id"),
        )
    finally:
        conn.close()


@router.post("/settings/monitoring")
async def set_monitoring_state(
    payload: ToggleRequest,
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        return system_service.set_monitoring(
            conn,
            active=payload.active,
            username=current_user.get("username", "admin"),
            organization_id=current_user.get("organization_id"),
        )
    finally:
        conn.close()


@router.post("/actions/scan")
async def trigger_scan(
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        return system_service.trigger_scan(
            conn,
            username=current_user.get("username", "admin"),
            organization_id=current_user.get("organization_id"),
        )
    finally:
        conn.close()


@router.post("/reset-data")
async def reset_data(
    _rate_limited: bool = Depends(admin_mutation_rate_limit),
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        return system_service.reset_operational_data(
            conn,
            username=current_user.get("username", "admin"),
            organization_id=current_user.get("organization_id"),
        )
    finally:
        conn.close()
