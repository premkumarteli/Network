from typing import List

from fastapi import APIRouter, Depends, HTTPException

from ..core.dependencies import require_org_admin
from ..db.session import get_db_connection
from ..schemas.agent_schema import AgentDetails, AgentSummary
from ..services.agent_service import agent_service

router = APIRouter()


@router.get("/", response_model=List[AgentSummary])
async def list_agents(current_user: dict = Depends(require_org_admin)):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        return agent_service.get_agents(conn, organization_id=org_id)
    finally:
        conn.close()


@router.get("/{agent_id}", response_model=AgentDetails)
async def get_agent_details(
    agent_id: str,
    current_user: dict = Depends(require_org_admin),
):
    conn = get_db_connection()
    try:
        org_id = current_user.get("organization_id")
        details = agent_service.get_agent_details(conn, agent_id, organization_id=org_id)
        if not details:
            raise HTTPException(status_code=404, detail="Agent not found")
        return details
    finally:
        conn.close()
