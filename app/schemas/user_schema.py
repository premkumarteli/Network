from pydantic import BaseModel, ConfigDict, EmailStr
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    role: Optional[str] = "viewer"
    organization_id: Optional[str] = None

class UserCreate(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    password: str
    confirm_password: str

class UserLogin(BaseModel):
    username: str
    password: str

class User(UserBase):
    id: str

    model_config = ConfigDict(from_attributes=True)

class GenericResponse(BaseModel):
    status: str
    message: str

    model_config = ConfigDict(extra="allow")
