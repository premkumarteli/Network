from core.database import (
    db_fetch_recent_traffic, db_fetch_system_logs, db_fetch_vpn_alerts,
    db_truncate_tables, db_export_to_csv
)
import datetime
import time
from collections import Counter

# --- In-Memory Cache for Dashboard Stats ---
_cache = {
    "stats": None,
    "expiry": 0
}
CACHE_TTL = 5  # 5 seconds TTL for high-traffic dashboard stats

def export_to_csv_task():
    return db_export_to_csv()

def truncate_data():
    return db_truncate_tables()

def parse_timestamp(value) -> datetime.datetime:
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value
    return datetime.datetime.now(datetime.timezone.utc)

def fetch_recent_traffic(limit=1000, severity=None, organization_id=None):
    return db_fetch_recent_traffic(limit, severity, organization_id)

def fetch_system_logs(limit=50, organization_id=None):
    return db_fetch_system_logs(limit, organization_id)

def fetch_vpn_alerts(limit=50, organization_id=None):
    return db_fetch_vpn_alerts(limit, organization_id)

def fetch_device_risks(organization_id=None):
    from core.database import db_fetch_device_risks
    return db_fetch_device_risks(organization_id)

def get_stats(organization_id=None):
    global _cache
    now_ts = time.time()
    
    # Simple multi-tenant cache key
    cache_key = f"stats_{organization_id or 'global'}"
    
    if _cache.get(cache_key) and now_ts < _cache.get(f"{cache_key}_expiry", 0):
        return _cache[cache_key]
        
    rows = db_fetch_recent_traffic(limit=1200, organization_id=organization_id)
    protocol_counts = Counter()
    devices = {row.get("source_ip") for row in rows if row.get("source_ip")}
    recent_count = 0
    now = datetime.datetime.now(datetime.timezone.utc)
    
    for row in rows:
        protocol_counts[row.get("protocol") or "DNS"] += 1
        ts = parse_timestamp(row.get("timestamp"))
        if (now - ts).total_seconds() <= 60:
            recent_count += 1
            
    total_mb = sum(row.get("packet_size", 0) for row in rows) / (1024*1024)
    if total_mb == 0 and rows: 
        total_mb = len(rows) * 0.05
        
    stats = {
        "bandwidth": f"{total_mb:.2f} MB",
        "devices": len(devices),
        "vpn_alerts": len([r for r in rows if r.get("severity") == "HIGH"]),
        "protocols": dict(protocol_counts),
        "upload_speed": recent_count * 2,
        "download_speed": recent_count * 5
    }
    
    # Update Cache
    _cache[cache_key] = stats
    _cache[f"{cache_key}_expiry"] = now_ts + CACHE_TTL
    
    return stats
