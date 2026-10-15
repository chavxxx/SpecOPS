"""
System Information & GitHub Updater API Endpoints
"""
import os
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Header
from pydantic import BaseModel

from app.api.auth import require_admin, require_read_or_admin
from app.models.schemas import UserResponse
from app.database.db import DatabaseManager, get_db
from app.services.updater import SystemUpdater

router = APIRouter(prefix="/system", tags=["System & Updates"])

class UpdateApplyRequest(BaseModel):
    token: Optional[str] = None

@router.get("/info", response_model=Dict[str, Any])
async def get_system_info(
    user: UserResponse = Depends(require_read_or_admin)
):
    """Retrieve platform release, commit hash, and environment status"""
    updater = SystemUpdater()
    commit_info = updater.get_current_commit()
    return {
        "app_name": "SpecOPS — WISPnet Security Operations Platform",
        "version": "v1.2.0",
        "commit": commit_info.get("short_commit", "v1.2.0"),
        "commit_date": commit_info.get("date"),
        "commit_message": commit_info.get("message"),
        "repo": "chavxxx/SpecOPS",
        "status": "operational"
    }

@router.get("/update/check", response_model=Dict[str, Any])
async def check_github_update(
    token: Optional[str] = Query(None, description="Optional GitHub Personal Access Token"),
    user: UserResponse = Depends(require_read_or_admin)
):
    """
    Checks chavxxx/SpecOPS repository for new commits or releases.
    Returns whether an update is available and commit summary.
    """
    updater = SystemUpdater()
    return updater.check_for_updates(token=token)

@router.post("/update/apply", response_model=Dict[str, Any])
async def apply_github_update(
    req: UpdateApplyRequest,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    """
    Applies latest updates from GitHub main branch.
    Pulls code, updates dependencies, and prepares restart.
    """
    updater = SystemUpdater()
    result = updater.apply_update(token=req.token)

    db.log_audit_event(
        operator_id=user.username,
        action="apply_system_update",
        target_type="system",
        outcome=result.get("status", "unknown"),
        details={"result": result}
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message", "Update failed"))

    return result
