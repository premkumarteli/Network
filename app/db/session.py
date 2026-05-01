import logging
import threading
import uuid

import mysql.connector
from mysql.connector import pooling

from ..core.config import settings
from ..core.security import get_password_hash

logger = logging.getLogger("netvisor.db")

_pool = None
_pool_lock = threading.Lock()

REQUIRED_SECURITY_TABLES = {
    "agent_credentials": """
        CREATE TABLE IF NOT EXISTS agent_credentials (
            agent_id VARCHAR(100) NOT NULL,
            key_version INT NOT NULL,
            secret_salt VARCHAR(64) NOT NULL,
            secret_hash CHAR(64) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            rotated_at DATETIME NULL,
            last_used_at DATETIME NULL,
            PRIMARY KEY (agent_id, key_version),
            INDEX idx_agent_credentials_status (status)
        )
    """,
    "agent_request_nonces": """
        CREATE TABLE IF NOT EXISTS agent_request_nonces (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            agent_id VARCHAR(100) NOT NULL,
            key_version INT NOT NULL,
            nonce VARCHAR(64) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            UNIQUE KEY uq_agent_nonce (agent_id, key_version, nonce),
            INDEX idx_agent_nonce_expires_at (expires_at)
        )
    """,
    "gateway_credentials": """
        CREATE TABLE IF NOT EXISTS gateway_credentials (
            gateway_id VARCHAR(100) NOT NULL,
            key_version INT NOT NULL,
            secret_salt VARCHAR(64) NOT NULL,
            secret_hash CHAR(64) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            rotated_at DATETIME NULL,
            last_used_at DATETIME NULL,
            PRIMARY KEY (gateway_id, key_version),
            INDEX idx_gateway_credentials_status (status)
        )
    """,
    "gateway_request_nonces": """
        CREATE TABLE IF NOT EXISTS gateway_request_nonces (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            gateway_id VARCHAR(100) NOT NULL,
            key_version INT NOT NULL,
            nonce VARCHAR(64) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            UNIQUE KEY uq_gateway_nonce (gateway_id, key_version, nonce),
            INDEX idx_gateway_nonce_expires_at (expires_at)
        )
    """,
}

REQUIRED_SECURITY_COLUMNS = {
    "users": {
        "status": "ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active' AFTER role",
        "failed_login_count": "ALTER TABLE users ADD COLUMN failed_login_count INT NOT NULL DEFAULT 0 AFTER status",
        "locked_until": "ALTER TABLE users ADD COLUMN locked_until DATETIME NULL AFTER failed_login_count",
        "last_password_change": (
            "ALTER TABLE users ADD COLUMN last_password_change DATETIME DEFAULT CURRENT_TIMESTAMP AFTER locked_until"
        ),
    }
}

REQUIRED_RUNTIME_TABLES = (
    "agents",
    "agent_enrollment_requests",
    "devices",
    "device_ip_history",
    "managed_devices",
    "gateways",
    "flow_ingest_batches",
    "worker_heartbeats",
    "flow_logs",
    "alerts",
    "device_baselines",
    "inspection_policies",
    "web_events",
    "external_endpoints",
    "sessions",
    "system_settings",
    "audit_logs",
)

REQUIRED_RUNTIME_COLUMNS = {
    "agents": {
        "hostname",
        "ip_address",
        "os_family",
        "version",
        "inspection_enabled",
        "inspection_status",
        "inspection_proxy_running",
        "inspection_ca_installed",
        "inspection_browsers_json",
        "inspection_last_error",
        "inspection_metrics_json",
        "cpu_usage",
        "ram_usage",
    },
    "agent_enrollment_requests": {
        "agent_id",
        "organization_id",
        "hostname",
        "device_ip",
        "device_mac",
        "os_family",
        "agent_version",
        "bootstrap_method",
        "source_ip",
        "machine_fingerprint",
        "status",
        "attempt_count",
        "first_seen",
        "last_seen",
        "expires_at",
        "reviewed_by",
        "reviewed_at",
        "review_reason",
        "credential_issued_at",
    },
    "devices": {
        "first_seen",
        "last_seen",
    },
    "managed_devices": {
        "id",
        "organization_id",
    },
    "gateways": {
        "organization_id",
        "created_at",
    },
    "flow_ingest_batches": {
        "batch_id",
        "source_type",
        "batch_json",
        "flow_count",
        "status",
        "attempt_count",
        "available_at",
        "claimed_by",
        "claimed_at",
        "processed_at",
        "last_error",
    },
    "worker_heartbeats": {
        "worker_type",
        "last_seen",
    },
    "flow_logs": {
        "sni",
        "src_mac",
        "dst_mac",
        "network_scope",
        "internal_device_ip",
        "external_endpoint_ip",
        "session_id",
        "application",
    },
    "web_events": {
        "search_query",
        "event_count",
        "risk_level",
        "threat_msg",
        "confidence_score",
    },
}

REQUIRED_RUNTIME_INDEXES = {
    "agents": {
        "idx_agents_org_last_seen",
    },
    "agent_enrollment_requests": {
        "uq_agent_enrollment_agent",
        "idx_agent_enrollment_status_last_seen",
        "idx_agent_enrollment_org_last_seen",
        "idx_agent_enrollment_fingerprint",
        "idx_agent_enrollment_expires_at",
    },
    "devices": {
        "idx_devices_org_last_seen",
        "idx_devices_agent_org_last_seen",
    },
    "device_ip_history": {
        "uq_device_ip_history",
        "idx_device_ip_history_org_last_seen",
    },
    "managed_devices": {
        "uq_managed_agent_ip_org",
        "uq_managed_ip_org",
        "idx_managed_agent_last_seen",
    },
    "flow_ingest_batches": {
        "uniq_flow_ingest_batch_id",
        "idx_flow_ingest_status_available",
        "idx_flow_ingest_created_at",
        "idx_flow_ingest_source",
    },
    "worker_heartbeats": {
        "idx_worker_heartbeats_type_seen",
    },
    "flow_logs": {
        "idx_flow_logs_internal_last_seen",
        "idx_flow_logs_scope_last_seen",
        "idx_flow_logs_session_id",
        "idx_flow_logs_org_app_last_seen",
        "idx_flow_logs_app_src_last_seen",
        "idx_flow_logs_sni_last_seen",
    },
    "external_endpoints": {
        "idx_external_endpoints_org_last_seen",
    },
    "sessions": {
        "idx_sessions_org_last_seen",
        "idx_sessions_device_last_seen",
        "idx_sessions_app_last_seen",
    },
    "inspection_policies": {
        "idx_inspection_policies_device",
        "idx_inspection_policies_org",
    },
    "web_events": {
        "idx_web_events_device_last_seen",
        "idx_web_events_agent_last_seen",
        "idx_web_events_org_last_seen",
        "idx_web_events_base_domain_last_seen",
    },
    "audit_logs": {
        "idx_audit_logs_org",
        "idx_audit_logs_created_at",
    },
}


def _build_db_config() -> dict:
    return {
        "host": settings.DB_HOST,
        "user": settings.DB_USER,
        "password": settings.DB_PASSWORD,
        "database": settings.DB_NAME,
        "connection_timeout": 5,
        "autocommit": False,
    }


def _connect_direct():
    return mysql.connector.connect(**_build_db_config())


def _ensure_connection_ready(conn):
    conn.ping(reconnect=True, attempts=1, delay=0)
    return conn


def _initialize_pool(force: bool = False):
    global _pool

    with _pool_lock:
        if _pool is not None and not force:
            return _pool

        try:
            _pool = pooling.MySQLConnectionPool(
                pool_name=f"netvisor_pool_{uuid.uuid4().hex[:8]}",
                pool_size=10,
                pool_reset_session=True,
                **_build_db_config(),
            )
            logger.info("Managed DB connection pool initialized.")
        except Exception as exc:
            logger.warning("Failed to initialize connection pool, using direct connections: %s", exc)
            _pool = None

        return _pool

def get_db():
    conn = None
    try:
        conn = get_db_connection()
        yield conn
    except Exception as e:
        logger.error(f"DB connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_db_connection():
    """Return a healthy MySQL connection, preferring the pool when available."""
    pool = _initialize_pool()

    if pool is not None:
        try:
            return _ensure_connection_ready(pool.get_connection())
        except Exception as exc:
            logger.warning("Discarding stale pooled connection and retrying direct DB connect: %s", exc)
            _initialize_pool(force=True)

    conn = _connect_direct()
    return _ensure_connection_ready(conn)


def _table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) as count
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name = %s
        """,
        (settings.DB_NAME, table_name),
    )
    result = cursor.fetchone() or {}
    return int(result.get("count") or 0) > 0


def _column_exists(cursor, table_name: str, column_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) as count
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s AND column_name = %s
        """,
        (settings.DB_NAME, table_name, column_name),
    )
    result = cursor.fetchone() or {}
    return int(result.get("count") or 0) > 0


def _index_exists(cursor, table_name: str, index_name: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*) as count
        FROM information_schema.statistics
        WHERE table_schema = %s AND table_name = %s AND index_name = %s
        """,
        (settings.DB_NAME, table_name, index_name),
    )
    result = cursor.fetchone() or {}
    return int(result.get("count") or 0) > 0


def ensure_security_schema(conn=None) -> dict:
    owned_conn = conn is None
    conn = conn or get_db_connection()
    cursor = conn.cursor(dictionary=True)
    created_tables: list[str] = []
    created_columns: list[str] = []
    try:
        for table_name, create_sql in REQUIRED_SECURITY_TABLES.items():
            if not _table_exists(cursor, table_name):
                cursor.execute(create_sql)
                created_tables.append(table_name)

        for table_name, columns in REQUIRED_SECURITY_COLUMNS.items():
            for column_name, alter_sql in columns.items():
                if not _column_exists(cursor, table_name, column_name):
                    cursor.execute(alter_sql)
                    created_columns.append(f"{table_name}.{column_name}")

        conn.commit()
        return {
            "ready": True,
            "created_tables": created_tables,
            "created_columns": created_columns,
        }
    except Exception:
        if owned_conn:
            conn.rollback()
        raise
    finally:
        cursor.close()
        if owned_conn:
            conn.close()


def security_schema_status(conn=None) -> dict:
    owned_conn = conn is None
    conn = conn or get_db_connection()
    cursor = conn.cursor(dictionary=True)
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    try:
        for table_name in REQUIRED_SECURITY_TABLES:
            if not _table_exists(cursor, table_name):
                missing_tables.append(table_name)

        for table_name, columns in REQUIRED_SECURITY_COLUMNS.items():
            for column_name in columns:
                if not _column_exists(cursor, table_name, column_name):
                    missing_columns.append(f"{table_name}.{column_name}")

        return {
            "ready": not missing_tables and not missing_columns,
            "missing_tables": missing_tables,
            "missing_columns": missing_columns,
        }
    finally:
        cursor.close()
        if owned_conn:
            conn.close()


def runtime_schema_status(conn=None) -> dict:
    owned_conn = conn is None
    conn = conn or get_db_connection()
    cursor = conn.cursor(dictionary=True)
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    missing_indexes: list[str] = []
    try:
        for table_name in REQUIRED_RUNTIME_TABLES:
            if not _table_exists(cursor, table_name):
                missing_tables.append(table_name)

        for table_name, columns in REQUIRED_RUNTIME_COLUMNS.items():
            if table_name in missing_tables:
                continue
            for column_name in columns:
                if not _column_exists(cursor, table_name, column_name):
                    missing_columns.append(f"{table_name}.{column_name}")

        for table_name, indexes in REQUIRED_RUNTIME_INDEXES.items():
            if table_name in missing_tables:
                continue
            for index_name in indexes:
                if not _index_exists(cursor, table_name, index_name):
                    missing_indexes.append(f"{table_name}.{index_name}")

        return {
            "ready": not missing_tables and not missing_columns and not missing_indexes,
            "missing_tables": missing_tables,
            "missing_columns": missing_columns,
            "missing_indexes": missing_indexes,
        }
    finally:
        cursor.close()
        if owned_conn:
            conn.close()


def require_runtime_schema(conn=None) -> dict:
    status = runtime_schema_status(conn)
    if status["ready"]:
        return status

    details: list[str] = []
    if status["missing_tables"]:
        details.append(f"tables: {', '.join(status['missing_tables'])}")
    if status["missing_columns"]:
        details.append(f"columns: {', '.join(status['missing_columns'])}")
    if status["missing_indexes"]:
        details.append(f"indexes: {', '.join(status['missing_indexes'])}")

    raise RuntimeError(
        "Runtime schema is incomplete. Apply the current database migrations before starting NetVisor. "
        + "; ".join(details)
    )


def ensure_bootstrap_state():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        ensure_security_schema(conn)

        default_org_id = settings.DEFAULT_ORGANIZATION_ID or "default-org-id"
        cursor.execute(
            "SELECT id FROM organizations WHERE name = %s LIMIT 1",
            ("Default Organization",),
        )
        org = cursor.fetchone()
        if not org:
            cursor.execute(
                "INSERT INTO organizations (id, name, status) VALUES (%s, %s, %s)",
                (default_org_id, "Default Organization", "active"),
            )
        else:
            default_org_id = org["id"]

        admin_password = settings.BOOTSTRAP_ADMIN_PASSWORD
        admin_username = settings.BOOTSTRAP_ADMIN_USERNAME
        if admin_password:
            cursor.execute(
                "SELECT id, role, organization_id FROM users WHERE username = %s LIMIT 1",
                (admin_username,),
            )
            user = cursor.fetchone()
            if not user:
                cursor.execute(
                    """  
                    INSERT INTO users (id, username, password, email, role, organization_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        admin_username,
                        get_password_hash(admin_password),
                        f"{admin_username}@netvisor.local",
                        "org_admin",
                        default_org_id,
                    ),
                )
                logger.info("Bootstrapped org_admin user '%s'.", admin_username)
            elif user.get("role") not in ("org_admin", "super_admin") or not user.get(
                "organization_id"
            ):
                cursor.execute(
                    """  
                    UPDATE users
                    SET role = %s, organization_id = COALESCE(organization_id, %s)
                    WHERE username = %s
                    """,
                    ("org_admin", default_org_id, admin_username),
                )
                logger.info("Normalized bootstrap user '%s' role/org.", admin_username)

        conn.commit()
    finally:
        cursor.close()
        conn.close()
