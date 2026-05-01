from fastapi import APIRouter, Depends

from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..schemas.web_schema import (
    DeviceInspectionStatus,
    DeviceWebActivityResponse,
    DeviceWebEvidenceGroupResponse,
    InspectionPolicyResponse,
    InspectionPolicyUpdate,
    GlobalWebActivityResponse,
    GlobalWebEvidenceGroupResponse,
)
from ..services.web_inspection_service import web_inspection_service
from ..services.audit_service import audit_service

router = APIRouter()


@router.get("/devices/{device_ip}/activity", response_model=DeviceWebActivityResponse)
async def get_device_web_activity(
    device_ip: str,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        activity = web_inspection_service.get_device_activity(
            conn,
            device_ip=device_ip,
            organization_id=org_id,
        )
        return {
            "device_ip": device_ip,
            "activity": activity,
        }
    finally:
        conn.close()


@router.get("/activity", response_model=GlobalWebActivityResponse)
async def get_global_web_activity(
    limit: int = 50,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        activity = web_inspection_service.get_global_activity(
            conn,
            organization_id=org_id,
            limit=limit,
        )
        return {
            "activity": activity,
        }
    finally:
        conn.close()


@router.get("/devices/{device_ip}/activity/groups", response_model=DeviceWebEvidenceGroupResponse)
async def get_device_web_activity_groups(
    device_ip: str,
    limit: int = 50,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        activity = web_inspection_service.get_device_evidence_groups(
            conn,
            device_ip=device_ip,
            organization_id=org_id,
            limit=limit,
        )
        return {
            "device_ip": device_ip,
            "activity": activity,
        }
    finally:
        conn.close()


@router.get("/activity/groups", response_model=GlobalWebEvidenceGroupResponse)
async def get_global_web_activity_groups(
    limit: int = 50,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        activity = web_inspection_service.get_global_evidence_groups(
            conn,
            organization_id=org_id,
            limit=limit,
        )
        return {
            "activity": activity,
        }
    finally:
        conn.close()


@router.get("/devices/{device_ip}/status", response_model=DeviceInspectionStatus)
async def get_device_inspection_status(
    device_ip: str,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return web_inspection_service.get_device_status(
            conn,
            device_ip=device_ip,
            organization_id=org_id,
        )
    finally:
        conn.close()


@router.post("/policies/{agent_id}", response_model=InspectionPolicyResponse)
async def update_inspection_policy(
    agent_id: str,
    payload: InspectionPolicyUpdate,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        result = web_inspection_service.set_policy(
            conn,
            agent_id=agent_id,
            device_ip=payload.device_ip,
            organization_id=org_id,
            inspection_enabled=payload.inspection_enabled,
            allowed_processes=payload.allowed_processes,
            allowed_domains=payload.allowed_domains,
            snippet_max_bytes=payload.snippet_max_bytes,
        )
        
        # Audit log for inspection policy changes
        audit_service.log_inspection_toggle(
            organization_id=str(org_id),
            username=current_user.get("username", "unknown"),
            agent_id=agent_id,
            device_ip=payload.device_ip,
            enabled=payload.inspection_enabled if payload.inspection_enabled is not None else result.get("inspection_enabled", False)
        )
        
        return result
    finally:
        conn.close()
