from typing import Optional
from ..core.security import verify_password, get_password_hash
import uuid
import logging

logger = logging.getLogger("netvisor.auth")

class AuthService:
    def authenticate(self, db_conn, username, password) -> Optional[dict]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if user and verify_password(password, user["password"]):
                return user
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
                (user_id, user_in.username, hashed_password, user_in.email, user_in.role or "user", default_org_id)
            )
            db_conn.commit()
            return {"id": user_id, "username": user_in.username, "role": user_in.role, "organization_id": default_org_id}
        finally:
            cursor.close()

auth_service = AuthService()
