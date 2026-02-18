from core.database import get_db_connection
import csv
import os
import datetime
from collections import Counter

def export_to_csv_task():
    """Helper to dump DB to CSV."""
    if not os.path.exists("data/backups"):
        os.makedirs("data/backups")
    conn = get_db_connection()
    if not conn: return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM traffic_logs")
        rows = cursor.fetchall()
        if not rows: return "empty"
        
        filename = f"data/backups/traffic_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return filename
    except Exception as e:
        print(f"Export error: {e}")
        return None
    finally:
        if conn: conn.close()

def truncate_data():
    """Wipe traffic and activity logs."""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("TRUNCATE TABLE traffic_logs")
            cursor.execute("TRUNCATE TABLE activity_logs")
            conn.commit()
            return True
        except Exception as e:
            print(f"Truncate error: {e}")
        finally:
            conn.close()
    return False

def parse_timestamp(value) -> datetime.datetime:
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value
    return datetime.datetime.now(datetime.timezone.utc)

def fetch_recent_traffic(limit=1000):
    conn = get_db_connection()
    if not conn: return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT %s", (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except: return []

def get_stats():
    rows = fetch_recent_traffic(limit=1200)
    protocol_counts = Counter()
    devices = {row.get("source_ip") for row in rows if row.get("source_ip")}
    recent_count = 0
    now = datetime.datetime.now(datetime.timezone.utc)
    for row in rows:
        protocol_counts[row.get("protocol") or "DNS"] += 1
        if (now - parse_timestamp(row.get("timestamp"))).total_seconds() <= 60:
            recent_count += 1
    total_mb = sum(row.get("packet_size", 0) for row in rows) / (1024*1024)
    if total_mb == 0 and rows: total_mb = len(rows) * 0.05
    return {
        "bandwidth": f"{total_mb:.2f} MB",
        "devices": len(devices),
        "vpn_alerts": len([r for r in rows if r.get("severity") == "HIGH"]),
        "protocols": dict(protocol_counts),
        "upload_speed": recent_count * 2,
        "download_speed": recent_count * 5
    }
