"""
Security Audit Logs API Endpoints
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query

from app.models.schemas import UserResponse
from app.models.security_schemas import AuditLogEntry
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user, require_admin

router = APIRouter(prefix="/security/audit", tags=["Audit Logs"])

@router.get("", response_model=Dict[str, Any])
async def list_security_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
    admin: UserResponse = Depends(require_admin)
):
    logs, total = db.get_security_audit_logs(limit=limit, offset=offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "audit_logs": logs
    }
