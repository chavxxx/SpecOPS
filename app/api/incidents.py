"""
Security Incidents Management API Endpoints
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel

from app.models.schemas import UserResponse
from app.models.security_schemas import (
    Incident,
    IncidentStatus,
    SecuritySeverity,
    SecurityEvent
)
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user

router = APIRouter(prefix="/security/incidents", tags=["Incident Management"])

class IncidentUpdateRequest(BaseModel):
    status: IncidentStatus
    assigned_operator: Optional[str] = None
    resolution_notes: Optional[str] = None

@router.get("", response_model=Dict[str, Any])
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    subscriber_cgnat_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    incidents, total = db.get_incidents(
        status=status,
        severity=severity,
        category=category,
        subscriber_cgnat_ip=subscriber_cgnat_ip,
        limit=limit,
        offset=offset
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "incidents": incidents
    }

@router.get("/{incident_id}", response_model=Dict[str, Any])
async def get_incident_detail(
    incident_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    res = db.get_incident_by_id(incident_id)
    if not res:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, events = res
    return {
        "incident": incident,
        "related_events": events
    }

@router.patch("/{incident_id}", response_model=Dict[str, Any])
async def update_incident(
    incident_id: str,
    update: IncidentUpdateRequest,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    res = db.get_incident_by_id(incident_id)
    if not res:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, _ = res

    # Require resolution notes when resolving or marking benign for high/critical incidents
    if update.status in (IncidentStatus.RESOLVED, IncidentStatus.BENIGN) and incident.severity in (SecuritySeverity.HIGH, SecuritySeverity.CRITICAL):
        if not update.resolution_notes or len(update.resolution_notes.strip()) < 5:
            raise HTTPException(
                status_code=400,
                detail=f"Resolution notes are mandatory when marking {incident.severity.value} severity incidents as {update.status.value}"
            )

    success = db.update_incident_status(
        incident_id=incident_id,
        status=update.status,
        operator=update.assigned_operator or user.username,
        notes=update.resolution_notes
    )

    db.log_security_audit(
        operator_id=user.username,
        action="update_incident_status",
        target_type="incident",
        target_id=incident_id,
        outcome="success",
        sanitized_details={"status": update.status.value, "notes": update.resolution_notes}
    )

    return {
        "success": success,
        "incident_id": incident_id,
        "status": update.status.value
    }

@router.get("/{incident_id}/report", response_model=Dict[str, Any])
async def export_incident_report(
    incident_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    res = db.get_incident_by_id(incident_id)
    if not res:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, events = res

    # Generate executive & forensic report
    report = {
        "report_id": f"REP-{incident.incident_id}",
        "title": f"Security Incident Investigation Report: {incident.title}",
        "organization": "WISP Network & Data Solutions (WISPnet)",
        "incident": incident,
        "forensic_summary": {
            "subscriber_cgnat_ip": incident.affected_subscriber_ip,
            "pppoe_username": incident.pppoe_username or "Unrecorded",
            "affected_public_ip": incident.affected_public_ip,
            "first_observed": incident.first_seen,
            "last_observed": incident.last_seen,
            "total_correlated_events": incident.event_count,
            "total_data_volume_bytes": incident.total_bytes,
            "total_packets": incident.total_packets
        },
        "event_timeline": [
            {
                "timestamp": e.event_timestamp,
                "sensor_id": e.sensor_id,
                "signature": e.signature_name,
                "destination": f"{e.destination_ip}:{e.destination_port}",
                "protocol": e.protocol,
                "attribution_status": e.attribution_status.value
            }
            for e in events[:30]
        ],
        "manual_billing_lookup_guidance": {
            "notice": "This platform maintains strict isolation from the customer billing database.",
            "instructions": (
                f"To identify the subscriber account, copy CGNAT IP '{incident.affected_subscriber_ip}' "
                f"or PPPoE Username '{incident.pppoe_username or ''}' into the external ISP billing console."
            )
        }
    }
    return report
