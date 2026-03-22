from fastapi import APIRouter, HTTPException
from core.database import get_db_connection
import json

router = APIRouter(prefix="/api/v1/intelligence", tags=["Intelligence Dashboard"])

@router.get("/risk-ranking")
async def get_risk_ranking(organization_id: str):
    """Returns top devices by risk score."""
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT device_id, ip_address, current_score, risk_level, reasons
            FROM device_risks
            WHERE organization_id = %s
            ORDER BY current_score DESC
            LIMIT 10
        """, (organization_id,))
        return cursor.fetchall()
    finally:
        conn.close()

@router.get("/risk-trends")
async def get_risk_trends(organization_id: str):
    """Returns historical risk trends for the last 7 days."""
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT DATE(timestamp) as date, AVG(risk_score) as avg_score, MAX(risk_score) as max_score
            FROM risk_history
            WHERE organization_id = %s AND timestamp > (NOW() - INTERVAL 7 DAY)
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """, (organization_id,))
        return cursor.fetchall()
    finally:
        conn.close()

@router.get("/risk-breakdown/{ip}")
async def get_risk_breakdown(ip: str, organization_id: str):
    """Returns the most recent alert breakdown for a specific device."""
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT severity, risk_score, breakdown_json, timestamp
            FROM alerts
            WHERE device_ip = %s AND organization_id = %s
            ORDER BY timestamp DESC
            LIMIT 1
        """, (ip, organization_id))
        row = cursor.fetchone()
        if row and row['breakdown_json']:
            row['breakdown'] = json.loads(row['breakdown_json'])
            del row['breakdown_json']
        return row or {"message": "No alerts found for this device"}
    finally:
        conn.close()

@router.get("/suspicious-ports")
async def get_suspicious_ports(organization_id: str):
    """Returns top suspicious ports detected in traffic."""
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor(dictionary=True)
        # Port 53 is excluded as it's common DNS
        cursor.execute("""
            SELECT dst_port, COUNT(*) as count, severity
            FROM traffic_logs
            WHERE organization_id = %s AND dst_port != '53' AND severity IN ('HIGH', 'CRITICAL')
            GROUP BY dst_port, severity
            ORDER BY count DESC
            LIMIT 10
        """, (organization_id,))
        return cursor.fetchall()
    finally:
        conn.close()

@router.get("/vpn-events")
async def get_vpn_events(organization_id: str):
    """Returns recent VPN detection events."""
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="DB Error")
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT device_ip, risk_score, breakdown_json, timestamp
            FROM alerts
            WHERE organization_id = %s 
              AND breakdown_json LIKE '%%"vpn_score"%%'
              AND severity IN ('HIGH', 'CRITICAL')
            ORDER BY timestamp DESC
            LIMIT 20
        """, (organization_id,))
        rows = cursor.fetchall()
        for r in rows:
            if r['breakdown_json']:
                r['breakdown'] = json.loads(r['breakdown_json'])
        return rows
    finally:
        conn.close()
