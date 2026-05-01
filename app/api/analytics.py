from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..services.analytics_service import analytics_service

router = APIRouter()


@router.get("/overview")
async def get_analytics_overview(
    current_user: dict = Depends(require_org_admin),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(8, ge=1, le=25),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return analytics_service.get_overview(conn, organization_id=org_id, hours=hours, limit=limit)
    finally:
        conn.close()


@router.get("/export")
async def export_analytics_report(
    current_user: dict = Depends(require_org_admin),
    kind: str = Query("flows"),
    format: str = Query("csv"),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(5000, ge=1, le=10000),
    src_ip: str | None = Query(None),
    dst_ip: str | None = Query(None),
    application: str | None = Query(None),
    search: str | None = Query(None),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        bundle = analytics_service.export_dataset(
            conn,
            kind=kind,
            organization_id=org_id,
            hours=hours,
            limit=limit,
            src_ip=src_ip,
            dst_ip=dst_ip,
            application=application,
            search=search,
        )
    finally:
        conn.close()

    if format.lower() == "json":
        return {
            "kind": kind,
            "filename": bundle["filename"],
            "rows": bundle["rows"],
        }

    return Response(
        content=bundle["content"],
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{bundle["filename"]}"',
        },
    )
