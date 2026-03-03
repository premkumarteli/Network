import mysql.connector
from mysql.connector import pooling
from .core.config import settings
import logging

logger = logging.getLogger("netvisor.db")

db_config = {
    "host": settings.DB_HOST,
    "user": settings.DB_USER,
    "password": settings.DB_PASSWORD,
    "database": settings.DB_NAME,
}

try:
    pool = pooling.MySQLConnectionPool(
        pool_name="netvisor_pool",
        pool_size=10,
        **db_config
    )
    logger.info("Managed DB connection pool initialized.")
except Exception as e:
    logger.error(f"Failed to initialize connection pool: {e}")
    pool = None

def get_db():
    conn = None
    try:
        if pool:
            conn = pool.get_connection()
        else:
            conn = mysql.connector.connect(**db_config)
        yield conn
    except Exception as e:
        logger.error(f"DB connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def get_db_connection():
    """Direct connection getter for legacy/manual use"""
    if pool:
        return pool.get_connection()
    return mysql.connector.connect(**db_config)
