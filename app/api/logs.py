from fastapi import APIRouter, Depends, Query
from typing import Optional
from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..services.flow_service import flow_service

router = APIRouter()

@router.get("/flows")
async def get_flows(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    application: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(require_org_admin)
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return flow_service.get_flow_logs(
            conn,
            organization_id=org_id,
            limit=limit,
            offset=offset,
            src_ip=src_ip,
            dst_ip=dst_ip,
            application=application,
            search=search
        )
    finally:
        conn.close()

@router.get("/stats")
async def get_log_stats(
    current_user: dict = Depends(require_org_admin)
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return flow_service.get_log_stats(conn, organization_id=org_id)
    finally:
        conn.close()
