"""
Authentication & Session Management API Endpoints
"""
import os
import json
import base64
import hmac
import hashlib
import time
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, Response, Header, Cookie
from app.database.db import get_db, DatabaseManager
from app.models.schemas import LoginRequest, LoginResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])

AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "synchavxxx-super-secure-token-secret-key-2026").encode('utf-8')
TOKEN_TTL_SECONDS = 7 * 24 * 3600  # 7 days session

def create_session_token(user: UserResponse) -> str:
    payload = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS
    }
    payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')
    
    signature = hmac.new(AUTH_SECRET_KEY, payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"

def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    try:
        payload_b64, signature = token.split('.', 1)
        expected_sig = hmac.new(AUTH_SECRET_KEY, payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            return None
        
        # Add padding back
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding
            
        payload_json = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
        payload = json.loads(payload_json)
        
        if payload.get("exp", 0) < int(time.time()):
            return None  # Expired
        return payload
    except Exception:
        return None

async def get_current_user_optional(
    request: Request,
    authorization: Optional[str] = Header(None),
    synchavxxx_token: Optional[str] = Cookie(None),
    db: DatabaseManager = Depends(get_db)
) -> Optional[UserResponse]:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    elif synchavxxx_token:
        token = synchavxxx_token

    if not token:
        return None

    payload = verify_session_token(token)
    if not payload:
        return None

    user = db.get_user_by_id(payload.get("id", ""))
    if not user or not user.enabled:
        return None

    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        enabled=user.enabled,
        created_at=user.created_at,
        updated_at=user.updated_at
    )

async def get_current_user(
    current_user: Optional[UserResponse] = Depends(get_current_user_optional)
) -> UserResponse:
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required. Please log in.")
    return current_user

async def require_admin(
    current_user: UserResponse = Depends(get_current_user)
) -> UserResponse:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Action requires Administrator privileges.")
    return current_user

async def require_read_or_admin(
    current_user: UserResponse = Depends(get_current_user)
) -> UserResponse:
    return current_user

@router.post("/login", response_model=LoginResponse)
async def login(
    req: LoginRequest,
    response: Response,
    db: DatabaseManager = Depends(get_db)
):
    user = db.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_session_token(user)
    
    # Set session cookie
    response.set_cookie(
        key="synchavxxx_token",
        value=token,
        max_age=TOKEN_TTL_SECONDS,
        httponly=False,
        samesite="lax",
        secure=False
    )

    return LoginResponse(
        token=token,
        user=user,
        message=f"Welcome back, {user.full_name or user.username} ({user.role})!"
    )

@router.get("/me", response_model=Dict[str, Any])
async def get_me(
    current_user: Optional[UserResponse] = Depends(get_current_user_optional),
    db: DatabaseManager = Depends(get_db)
):
    if not current_user:
        return {
            "authenticated": False,
            "user": None,
            "can_edit": False
        }
    return {
        "authenticated": True,
        "user": current_user.model_dump(),
        "can_edit": current_user.role == "admin"
    }

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("synchavxxx_token")
    return {"status": "success", "message": "Logged out successfully."}
