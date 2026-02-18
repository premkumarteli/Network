from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse
from core.database import get_db_connection
from core.security import verify_password, hash_password
from ..templates import templates, fastapi_url_for_compat

router = APIRouter()

@router.get("/login", name="login_page")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "url_for": fastapi_url_for_compat(request)})

@router.post("/login")
async def login_handler(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    if not conn: 
        return templates.TemplateResponse("login.html", {"request": request, "error": "DB Error", "url_for": fastapi_url_for_compat(request)})
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user:
            is_valid = verify_password(password, user["password"])
            if is_valid:
                request.session["user_id"] = user["id"]
                request.session["username"] = user["username"]
                request.session["role"] = user["role"]
                return RedirectResponse(url="/dashboard", status_code=303)
    finally:
        if 'cursor' in locals(): cursor.close()
        conn.close()
    
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid login", "url_for": fastapi_url_for_compat(request)})

@router.get("/register", name="register_page")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "url_for": fastapi_url_for_compat(request)})

@router.post("/register")
async def register_handler(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...), confirm_password: str = Form(...)):
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {"request": request, "error_message": "Passwords do not match.", "url_for": fastapi_url_for_compat(request)})
    
    conn = get_db_connection()
    if not conn: return {"status": "error"}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return templates.TemplateResponse("register.html", {"request": request, "error_message": "Username or Email already exists.", "url_for": fastapi_url_for_compat(request)})
        
        hashed = hash_password(password)
        cursor.execute("INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)", (username, hashed, email, "user"))
        conn.commit()
        return RedirectResponse(url="/login", status_code=303)
    except Exception as e:
        print(f"Register Error: {e}")
        return templates.TemplateResponse("register.html", {"request": request, "error_message": "Registration failed.", "url_for": fastapi_url_for_compat(request)})
    finally:
        if 'cursor' in locals(): cursor.close()
        conn.close()

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
