from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from ..db.session import get_db_connection, runtime_schema_status, security_schema_status
from ..core.config import settings
from ..services.agent_service import agent_service
from ..services.agent_auth_service import agent_auth_service
from ..services.flow_service import flow_service
from ..services.gateway_auth_service import gateway_auth_service
from ..services.release_service import release_service
from ..services.system_service import system_service
from ..services.metrics_service import metrics_service

router = APIRouter()


@router.get("/status")
async def get_status():
    active_pins = agent_auth_service.transport_pins()
    schema = security_schema_status()
    runtime_schema = runtime_schema_status()
    inspection_observability = {}
    conn = None
    try:
        conn = get_db_connection()
        inspection_observability = agent_service.get_inspection_observability(conn)
    except Exception:
        inspection_observability = {}
    finally:
        if conn:
            conn.close()
    return {
        "status": "healthy" if schema["ready"] and runtime_schema["ready"] else "degraded",
        "service": "NetVisor",
        "security": {
            "schema_ready": schema["ready"],
            "missing_tables": schema["missing_tables"],
            "missing_columns": schema["missing_columns"],
            "runtime_schema_ready": runtime_schema["ready"],
            "runtime_missing_tables": runtime_schema["missing_tables"],
            "runtime_missing_columns": runtime_schema["missing_columns"],
            "runtime_missing_indexes": runtime_schema["missing_indexes"],
            "backend_tls_pins_configured": bool(active_pins),
            "backend_tls_pin_count": len(active_pins),
            "gateway_signed_auth_ready": bool(settings.GATEWAY_MASTER_KEY) and schema["ready"],
            "gateway_bootstrap_only_key_configured": bool(settings.GATEWAY_API_KEY),
        },
        "observability": {
            "flow_ingest": flow_service.metrics_snapshot(),
            "inspection": inspection_observability,
            "backup": system_service.latest_backup_status(),
            "backup_retention": system_service.backup_retention_status(),
            "security_events": metrics_service.snapshot(),
        },
        "release": release_service.snapshot(),
    }


@router.get("/ready")
async def readiness_check():
    """Readiness check that verifies critical system components are ready."""
    checks = {
        "database": False,
        "security_schema": False,
        "runtime_schema": False,
    }
    advisories = {
        "backend_tls_pins_configured": False,
        "gateway_tls_pins_configured": False,
    }
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        checks["database"] = True

        schema = security_schema_status(conn)
        checks["security_schema"] = schema["ready"]
        runtime_schema = runtime_schema_status(conn)
        checks["runtime_schema"] = runtime_schema["ready"]

        advisories["backend_tls_pins_configured"] = bool(agent_auth_service.transport_pins())
        advisories["gateway_tls_pins_configured"] = bool(gateway_auth_service.transport_pins())
    except Exception:
        pass
    finally:
        if conn:
            conn.close()

    all_ready = all(checks.values())
    if not all_ready:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "checks": checks,
                "advisories": advisories,
                "failed_checks": [k for k, v in checks.items() if not v],
            }
        )

    return {
        "status": "ready",
        "checks": checks,
        "advisories": advisories,
        "release": release_service.snapshot(),
    }


@router.get("/metrics")
async def metrics_snapshot():
    conn = None
    inspection_observability = {}
    try:
        conn = get_db_connection()
        inspection_observability = agent_service.get_inspection_observability(conn)
    except Exception:
        inspection_observability = {}
    finally:
        if conn:
            conn.close()

    return {
        "status": "success",
        "flow_ingest": flow_service.metrics_snapshot(),
        "inspection": inspection_observability,
        "backup": system_service.latest_backup_status(),
        "backup_retention": system_service.backup_retention_status(),
        "security_events": metrics_service.snapshot(),
    }


@router.get("/metrics.prom", response_class=PlainTextResponse)
async def prometheus_metrics():
    lines = [metrics_service.prometheus_text().rstrip()]
    flow_metrics = flow_service.metrics_snapshot()
    for key, value in sorted(flow_metrics.items()):
        metric_name = f"netvisor_flow_{key}"
        if isinstance(value, (int, float)):
            lines.append(f"{metric_name} {value}")
    retention_metrics = system_service.backup_retention_status()
    for key, value in sorted(retention_metrics.items()):
        metric_name = f"netvisor_backup_retention_{key}"
        if isinstance(value, (int, float)):
            lines.append(f"{metric_name} {value}")
    return "\n".join(line for line in lines if line) + "\n"
