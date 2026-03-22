from urllib.parse import unquote

from fastapi import APIRouter, Depends

from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..services.application_service import application_service

router = APIRouter()


@router.get("/summary")
async def get_apps_summary(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return application_service.get_application_summary(conn, organization_id=org_id)
    finally:
        conn.close()


@router.get("/{app_name}/devices")
async def get_app_devices(app_name: str, current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        decoded_name = unquote(app_name)
        return {
            "application": decoded_name,
            "devices": application_service.get_application_devices(
                conn,
                app_name=decoded_name,
                organization_id=org_id,
            ),
        }
    finally:
        conn.close()
