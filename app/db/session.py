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


def ensure_bootstrap_state():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
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
