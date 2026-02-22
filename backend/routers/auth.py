from fastapi import APIRouter, Request, Form, Depends, HTTPException
import time
from fastapi.responses import JSONResponse
from core.database import get_db_connection
from core.security import verify_password, hash_password

from fastapi import APIRouter, Request, Depends, HTTPException, status
import time
from fastapi.responses import JSONResponse
from core.database import get_db_connection
from core.security import verify_password, hash_password
from core.models import UserLogin, UserRegister, GenericResponse
import uuid

router = APIRouter(tags=["Authentication"])

# Simple in-memory rate limiting
login_attempts = {}

@router.post("/login", response_model=GenericResponse)
async def login_handler(request: Request, credentials: UserLogin):
    client_ip = request.client.host
    current_time = time.time()
    
    username = credentials.username
    password = credentials.password

    # Cleanup old attempts
    if client_ip in login_attempts:
        attempts, last_time = login_attempts[client_ip]
        if current_time - last_time > 300: # 5 minutes lockout window
            del login_attempts[client_ip]
    
    if client_ip in login_attempts:
        attempts, last_time = login_attempts[client_ip]
        if attempts >= 5:
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    conn = get_db_connection()
    if not conn: 
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user and verify_password(password, user["password"]):
            # Reset attempts on success
            if client_ip in login_attempts: del login_attempts[client_ip]
            
            request.session["user_id"] = user["id"]
            request.session["username"] = user["username"]
            request.session["role"] = user["role"]
            request.session["organization_id"] = user["organization_id"]
            return {"status": "success", "message": "Login successful"}
    finally:
        if 'cursor' in locals(): cursor.close()
        conn.close()
    
    # Increment failure counter
    attempts, _ = login_attempts.get(client_ip, (0, time.time()))
    login_attempts[client_ip] = (attempts + 1, time.time())
    
    raise HTTPException(status_code=401, detail="Invalid username or password")

@router.post("/register", response_model=GenericResponse)
async def register_handler(data: UserRegister):
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    
    conn = get_db_connection()
    if not conn: 
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (data.username, data.email))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username or Email already exists.")
        
        # Get default organization
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM organizations WHERE name = 'Default Organization' LIMIT 1")
        org = cursor.fetchone()
        default_org_id = org["id"] if org else None

        hashed = hash_password(data.password)
        user_id = str(uuid.uuid4())
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (id, username, password, email, role, organization_id) VALUES (%s, %s, %s, %s, %s, %s)", 
            (user_id, data.username, hashed, data.email, data.role or "user", default_org_id)
        )
        conn.commit()
        return {"status": "success", "message": "Registration successful"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during registration.")
    finally:
        if 'cursor' in locals(): cursor.close()
        conn.close()

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return {"status": "success", "message": "Logged out"}

@router.post("/forgot-password")
async def forgot_password_handler(request: Request):
    # Simple stub
    return {"status": "success", "message": "If that account exists, a reset link has been sent."}

@router.get("/api/me")
async def check_auth(request: Request):
    user_id = request.session.get("user_id")
    if user_id:
        return {
            "authenticated": True, 
            "username": request.session.get("username"), 
            "role": request.session.get("role"),
            "organization_id": request.session.get("organization_id")
        }
    return {"authenticated": False}

