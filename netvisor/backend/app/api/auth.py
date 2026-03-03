from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from ..core.security import create_access_token
from ..db.session import get_db_connection
from ..schemas.user_schema import UserCreate, User
from ..schemas.token_schema import Token
from ..services.auth_service import auth_service

router = APIRouter()

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    conn = get_db_connection()
    try:
        user = auth_service.authenticate(conn, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=60 * 24 * 8)
        access_token = create_access_token(
            subject=user["id"], expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    finally:
        conn.close()

@router.post("/register", response_model=User)
async def register(
    user_in: UserCreate
):
    if user_in.password != user_in.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    conn = get_db_connection()
    try:
        user = auth_service.create_user(conn, user_in)
        if not user:
            raise HTTPException(status_code=409, detail="Username or Email already exists")
        return user
    finally:
        conn.close()
