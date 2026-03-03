from pydantic import BaseModel, EmailStr
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    role: Optional[str] = "viewer"
    organization_id: Optional[str] = None

class UserCreate(UserBase):
    password: str
    confirm_password: str

class UserLogin(BaseModel):
    username: str
    password: str

class User(UserBase):
    id: str

    class Config:
        from_attributes = True
