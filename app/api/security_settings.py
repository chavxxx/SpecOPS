"""
Security & CGNAT Settings Management API Endpoints
"""
import os
import json
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.models.schemas import UserResponse
from app.models.security_schemas import CGNATConfig
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user, require_admin

router = APIRouter(prefix="/security/settings", tags=["Security Settings"])

class SecuritySettings(BaseModel):
    cgnat_config: CGNATConfig = CGNATConfig()
    core_router_host: str = "100.91.0.1"
    core_router_port: int = 8728
    core_router_username: str = "security_ro"
    core_router_password: Optional[str] = None
    ac_router_host: str = "100.91.0.254"
    ac_router_port: int = 8728
    ac_router_username: str = "security_ro"
    ac_router_password: Optional[str] = None
    opensearch_url: str = "http://localhost:9200"
    opensearch_username: str = "admin"
    opensearch_password: Optional[str] = None
    opensearch_mode: str = "auto" # auto, cluster, standalone
    opensearch_verify_ssl: bool = False
    akvorado_url: str = "http://localhost:8080"
    notification_webhook_url: Optional[str] = None
    alert_cooldown_minutes: int = 15
    retention_days_events: int = 90
    retention_days_raw: int = 14

SETTINGS_KEY = "wispnet_security_settings"

@router.get("", response_model=Dict[str, Any])
async def get_security_settings(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    saved = db.get_security_settings(SETTINGS_KEY)
    settings = SecuritySettings(**saved) if saved else SecuritySettings()
    data = settings.model_dump()

    # Mask sensitive credentials
    for field in ["core_router_password", "ac_router_password", "opensearch_password"]:
        if data.get(field):
            data[field] = "********"

    return data

@router.post("", response_model=Dict[str, Any])
async def update_security_settings(
    settings: SecuritySettings,
    db: DatabaseManager = Depends(get_db),
    admin: UserResponse = Depends(require_admin)
):
    # If password fields are '********', preserve previous password
    existing = db.get_security_settings(SETTINGS_KEY) or {}
    new_data = settings.model_dump()

    for field in ["core_router_password", "ac_router_password", "opensearch_password"]:
        if new_data.get(field) == "********":
            new_data[field] = existing.get(field, "")

    db.set_security_settings(SETTINGS_KEY, new_data)

    db.log_security_audit(
        operator_id=admin.username,
        action="update_security_settings",
        target_type="security_settings",
        outcome="success",
        sanitized_details={"cgnat_pool": f"{settings.cgnat_config.public_pool_start}-{settings.cgnat_config.public_pool_end}"}
    )

    return {
        "success": True,
        "message": "Security and CGNAT settings saved successfully"
    }
