from fastapi import APIRouter, Depends
from typing import List
from ..core.dependencies import get_current_user, require_org_admin
from ..db.session import get_db_connection
from ..schemas.alert_schema import Alert
from ..services.alert_service import alert_service

router = APIRouter()

@router.get("/", response_model=List[Alert])
async def list_alerts(
    current_user: dict = Depends(require_org_admin),
    limit: int = 50,
    severity: str | None = None,
    resolved: bool | None = None,
    hours: int | None = None,
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        severities = [item.strip().upper() for item in severity.split(",") if item.strip()] if severity else None
        alerts = alert_service.get_alerts(
            conn,
            organization_id=org_id,
            limit=limit,
            severities=severities,
            resolved=resolved,
            hours=hours,
        )
        # Type casting for schema
        for a in alerts:
            if a.get("timestamp") and hasattr(a["timestamp"], "strftime"):
                a["timestamp"] = a["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            a["breakdown"] = a.get("breakdown", {})
        return alerts
    finally:
        conn.close()

@router.get("/ranking")
async def get_risk_ranking(
    current_user: dict = Depends(require_org_admin)
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return alert_service.get_risk_ranking(conn, organization_id=org_id)
    finally:
        conn.close()
