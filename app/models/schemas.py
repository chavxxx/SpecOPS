"""
Pydantic Schemas for WISPnet Security Platform Authentication & User Management
"""
from typing import Optional
from pydantic import BaseModel, Field

class UserRole(str):
    ADMIN = "admin"
    READ_ONLY = "read-only"

class UserResponse(BaseModel):
    id: str
    username: str
    role: str = Field(default="read-only", description="'admin' or 'read-only'")
    full_name: Optional[str] = ""
    enabled: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class User(BaseModel):
    id: str
    username: str
    password_hash: str
    salt: str
    role: str = "read-only"
    full_name: Optional[str] = ""
    enabled: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=50, description="Unique login username")
    password: str = Field(..., min_length=4, max_length=128, description="User password")
    role: str = Field(default="read-only", description="'admin' or 'read-only'")
    full_name: Optional[str] = Field(default="", description="Full name or team role")

class UserUpdate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=4, max_length=128, description="New password if updating")
    role: Optional[str] = Field(default=None, description="'admin' or 'read-only'")
    full_name: Optional[str] = Field(default=None, description="Full name or team role")
    enabled: Optional[bool] = Field(default=None, description="Enable or disable account")

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    user: UserResponse
    message: str
