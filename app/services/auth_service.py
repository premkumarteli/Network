from typing import Optional
from datetime import datetime, timedelta, timezone
from ..core.security import verify_password, get_password_hash
from ..core.config import settings
import uuid
import logging

logger = logging.getLogger("netvisor.auth")

class AuthService:
    def _parse_timestamp(self, value):
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None

    def _is_locked(self, user: dict) -> bool:
        locked_until = self._parse_timestamp(user.get("locked_until"))
        return bool(locked_until and locked_until > datetime.now(timezone.utc))

    def _record_failed_login(self, db_conn, user_id: str) -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE users
                SET
                    failed_login_count = COALESCE(failed_login_count, 0) + 1,
                    locked_until = CASE
                        WHEN COALESCE(failed_login_count, 0) + 1 >= %s
                            THEN DATE_ADD(UTC_TIMESTAMP(), INTERVAL %s MINUTE)
                        ELSE locked_until
                    END
                WHERE id = %s
                """,
                (
                    max(int(settings.LOGIN_LOCKOUT_THRESHOLD or 5), 1),
                    max(int(settings.LOGIN_LOCKOUT_MINUTES or 15), 1),
                    user_id,
                ),
            )
            db_conn.commit()
        except Exception:
            db_conn.rollback()
        finally:
            cursor.close()

    def _record_successful_login(self, db_conn, user_id: str) -> None:
        cursor = db_conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE users
                SET failed_login_count = 0, locked_until = NULL
                WHERE id = %s
                """,
                (user_id,),
            )
            db_conn.commit()
        except Exception:
            db_conn.rollback()
        finally:
            cursor.close()

    def authenticate(self, db_conn, username, password) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if not user:
                return None
            if str(user.get("status") or "active").lower() == "disabled":
                return None
            if self._is_locked(user):
                return None
            if verify_password(password, user["password"]):
                self._record_successful_login(db_conn, user["id"])
                user["failed_login_count"] = 0
                user["locked_until"] = None
                return user
            if user.get("id"):
                self._record_failed_login(db_conn, user["id"])
            return None
        finally:
            cursor.close()

    def create_user(self, db_conn, user_in) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (user_in.username, user_in.email))
            if cursor.fetchone():
                return None
            
            # Get default organization
            cursor.execute("SELECT id FROM organizations WHERE name = 'Default Organization' LIMIT 1")
            org = cursor.fetchone()
            default_org_id = org["id"] if org else None

            user_id = str(uuid.uuid4())
            hashed_password = get_password_hash(user_in.password)
            
            cursor.execute(
                "INSERT INTO users (id, username, password, email, role, organization_id) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, user_in.username, hashed_password, user_in.email, "viewer", default_org_id)
            )
            db_conn.commit()
            return {
                "id": user_id,
                "username": user_in.username,
                "email": user_in.email,
                "role": "viewer",
                "organization_id": default_org_id,
            }
        finally:
            cursor.close()

    def get_user_by_id(self, db_conn, user_id: str) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,))
            return cursor.fetchone()
        finally:
            cursor.close()

    def count_users(self, db_conn) -> int:
        cursor = db_conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            row = cursor.fetchone()
            return int(row[0] if row else 0)
        finally:
            cursor.close()

auth_service = AuthService()
