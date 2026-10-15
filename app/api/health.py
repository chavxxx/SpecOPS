"""
Sensor & Integration Health API Endpoints
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends

from app.models.schemas import UserResponse
from app.models.security_schemas import IntegrationHealth, Sensor
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user

router = APIRouter(prefix="/security/health", tags=["System Health"])

@router.get("", response_model=Dict[str, Any])
async def get_system_health(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    integrations = db.get_all_integration_health()
    sensors = db.get_sensors()
    queue_depth = db.get_opensearch_queue_depth()

    overall_status = "healthy"
    for item in integrations:
        if item.connectivity == "degraded" and overall_status != "offline":
            overall_status = "degraded"
        elif item.connectivity == "offline":
            overall_status = "degraded"

    return {
        "overall_status": overall_status,
        "opensearch_queue_depth": queue_depth,
        "integrations": integrations,
        "sensors": sensors
    }
