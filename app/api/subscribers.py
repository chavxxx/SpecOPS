"""
Network-Derived Subscriber Security Profile API Endpoints
Provides pure network security timeline and session history with NO billing integration.
"""
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends

from app.models.schemas import UserResponse
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user

router = APIRouter(prefix="/security/subscribers", tags=["Subscriber Profile"])

@router.get("/{cgnat_ip}", response_model=Dict[str, Any])
async def get_subscriber_security_profile(
    cgnat_ip: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    """
    Returns the network-derived security profile for a CGNAT subscriber address:
    - Active & historical PPPoE sessions
    - Port block allocations
    - Security incidents & attack history
    - Traffic metrics and top detection categories
    Strictly isolated from customer billing/financial databases.
    """
    profile = db.get_subscriber_profile(cgnat_ip)

    # Log audit entry for sensitive subscriber profile lookup
    db.log_security_audit(
        operator_id=user.username,
        action="view_subscriber_security_profile",
        target_type="subscriber_cgnat_ip",
        target_id=cgnat_ip,
        outcome="success",
        sanitized_details={"cgnat_ip": cgnat_ip, "sessions_found": len(profile.get("sessions_history", []))}
    )

    return {
        "status": "success",
        "profile": profile,
        "manual_billing_guidance": {
            "copy_cgnat_ip": cgnat_ip,
            "copy_username": profile.get("current_username"),
            "notice": "Copy the CGNAT IP or PPPoE username above to manually search the independent billing portal."
        }
    }
