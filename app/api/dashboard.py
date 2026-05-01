from fastapi import APIRouter, Depends

from ..core.dependencies import get_current_user, require_org_admin
from ..db.session import get_db_connection
from ..services.dashboard_service import dashboard_service

router = APIRouter()


@router.get("/overview")
async def get_dashboard_overview(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return dashboard_service.get_overview_stats(conn, organization_id=org_id)
    finally:
        conn.close()


@router.get("/activity")
async def get_dashboard_activity(
    current_user: dict = Depends(require_org_admin),
    limit: int = 50,
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return dashboard_service.get_recent_activity(conn, organization_id=org_id, limit=limit)
    finally:
        conn.close()
@router.get("/traffic-history")
async def get_traffic_history(
    current_user: dict = Depends(require_org_admin),
    hours: int = 24
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return dashboard_service.get_traffic_history(conn, hours=hours, organization_id=org_id)
    finally:
        conn.close()


@router.get("/device-stats")
async def get_device_stats(
    current_user: dict = Depends(require_org_admin),
    limit: int = 5
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return dashboard_service.get_device_activity_stats(conn, limit=limit, organization_id=org_id)
    finally:
        conn.close()
