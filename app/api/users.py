"""
User Management API Endpoints (Admin Protected)
"""
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from app.database.db import get_db, DatabaseManager
from app.models.schemas import UserResponse, UserCreate, UserUpdate
from app.api.auth import require_admin

router = APIRouter(prefix="/users", tags=["User Management"])

@router.get("", response_model=List[UserResponse])
async def list_users(
    admin_user: UserResponse = Depends(require_admin),
    db: DatabaseManager = Depends(get_db)
):
    return db.get_users()

@router.post("", response_model=Dict[str, Any])
async def create_user(
    user_in: UserCreate,
    admin_user: UserResponse = Depends(require_admin),
    db: DatabaseManager = Depends(get_db)
):
    try:
        user_id = db.create_user(user_in)
        return {
            "status": "success",
            "id": user_id,
            "message": f"User '{user_in.username}' created successfully as {user_in.role}."
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create user: {e}")

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    admin_user: UserResponse = Depends(require_admin),
    db: DatabaseManager = Depends(get_db)
):
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        enabled=user.enabled,
        created_at=user.created_at,
        updated_at=user.updated_at
    )

@router.put("/{user_id}", response_model=Dict[str, Any])
async def update_user(
    user_id: str,
    updates: UserUpdate,
    admin_user: UserResponse = Depends(require_admin),
    db: DatabaseManager = Depends(get_db)
):
    try:
        success = db.update_user(user_id, updates)
        if not success:
            raise HTTPException(status_code=404, detail="User not found.")
        return {
            "status": "success",
            "message": "User updated successfully."
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update user: {e}")

@router.delete("/{user_id}", response_model=Dict[str, Any])
async def delete_user(
    user_id: str,
    admin_user: UserResponse = Depends(require_admin),
    db: DatabaseManager = Depends(get_db)
):
    try:
        success = db.delete_user(user_id)
        if not success:
            raise HTTPException(status_code=404, detail="User not found.")
        return {
            "status": "success",
            "message": "User deleted successfully."
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {e}")
