"""
Traffic Analytics API Endpoints (Akvorado Integration)
"""
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query

from app.models.schemas import UserResponse
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user
from app.services.akvorado_adapter import AkvoradoAdapter

router = APIRouter(prefix="/security/traffic", tags=["Traffic Analytics"])

@router.get("/overview", response_model=Dict[str, Any])
async def get_traffic_overview(
    window_minutes: int = Query(60, ge=5, le=1440),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    adapter = AkvoradoAdapter(db=db)
    analytics = adapter.get_traffic_analytics(time_window_minutes=window_minutes)
    return {
        "status": "success",
        "analytics": analytics
    }
