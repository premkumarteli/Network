from fastapi import APIRouter, HTTPException, Depends
from core.models import PolicyUpdate, GenericResponse
from core.database import get_db_connection
import json

router = APIRouter(prefix="/api/v1/policy", tags=["Policy Management"])

@router.get("/{org_id}")
async def get_policy(org_id: str):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM security_policies WHERE organization_id = %s", (org_id,))
        row = cursor.fetchone()
        if not row:
            # Return defaults
            return {
                "blocked_domains": [],
                "vpn_restriction": False,
                "alert_threshold": 70
            }
        
        # Parse blocked_domains if stored as CSV or JSON
        row['blocked_domains'] = row['blocked_domains'].split(',') if row['blocked_domains'] else []
        return row
    finally:
        conn.close()

@router.post("/update")
async def update_policy(policy: PolicyUpdate):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor()
        domains_str = ",".join(policy.blocked_domains)
        cursor.execute("""
            INSERT INTO security_policies (organization_id, blocked_domains, vpn_restriction, alert_threshold)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                blocked_domains = VALUES(blocked_domains),
                vpn_restriction = VALUES(vpn_restriction),
                alert_threshold = VALUES(alert_threshold)
        """, (policy.organization_id, domains_str, policy.vpn_restriction, policy.alert_threshold))
        conn.commit()
        return {"status": "success", "message": "Policy updated"}
    finally:
        conn.close()
