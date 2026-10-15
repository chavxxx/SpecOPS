"""
Security Events & Suricata Ingestion API Endpoints
"""
import io
import csv
from typing import Optional, List, Dict, Any, Union
from fastapi import APIRouter, HTTPException, Depends, Query, Request, Response
from fastapi.responses import PlainTextResponse

from app.models.schemas import UserResponse
from app.models.security_schemas import (
    SecurityEvent,
    AttributionStatus
)
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user
from app.services.suricata_ingest import SuricataIngestService
from app.services.detection_engine import DetectionEngine
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/security", tags=["Security Events & Ingestion"])

@router.get("/events", response_model=Dict[str, Any])
async def list_security_events(
    cgnat_ip: Optional[str] = Query(None, description="Filter by original subscriber CGNAT IP"),
    public_ip: Optional[str] = Query(None, description="Filter by public source or destination IP"),
    severity: Optional[str] = Query(None, description="Filter by severity: informational, low, medium, high, critical"),
    category: Optional[str] = Query(None, description="Filter by category"),
    attribution_status: Optional[str] = Query(None, description="Filter by attribution status"),
    sensor_id: Optional[str] = Query(None, description="Filter by sensor ID"),
    start_time: Optional[str] = Query(None, description="Start timestamp (ISO)"),
    end_time: Optional[str] = Query(None, description="End timestamp (ISO)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    events, total = db.get_security_events(
        cgnat_ip=cgnat_ip,
        public_ip=public_ip,
        severity=severity,
        category=category,
        attribution_status=attribution_status,
        sensor_id=sensor_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events
    }

@router.get("/events/{event_id}", response_model=Dict[str, Any])
async def get_security_event_detail(
    event_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    result = db.get_security_event_by_id(event_id)
    if not result:
        raise HTTPException(status_code=404, detail="Security event not found")
    event, raw_payload = result
    return {
        "event": event,
        "raw_payload": raw_payload
    }

@router.get("/events/export/csv", response_class=PlainTextResponse)
async def export_security_events_csv(
    cgnat_ip: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    attribution_status: Optional[str] = Query(None),
    limit: int = Query(1000, le=10000),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    events, _ = db.get_security_events(
        cgnat_ip=cgnat_ip,
        severity=severity,
        category=category,
        attribution_status=attribution_status,
        limit=limit
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "event_id", "timestamp_utc", "sensor_id", "observation_point",
        "subscriber_cgnat_ip", "pppoe_username", "public_source_ip", "public_source_port",
        "destination_ip", "destination_port", "protocol", "category", "severity",
        "signature_name", "attribution_status", "packets", "bytes"
    ])

    for e in events:
        writer.writerow([
            e.event_id, e.event_timestamp, e.sensor_id, e.observation_point,
            e.subscriber_cgnat_ip or "", e.pppoe_username or "", e.source_ip, e.source_port or "",
            e.destination_ip, e.destination_port or "", e.protocol, e.category.value, e.severity.value,
            e.signature_name or "", e.attribution_status.value, e.packets or 0, e.bytes or 0
        ])

    db.log_security_audit(
        operator_id=user.username,
        action="export_security_events_csv",
        target_type="security_events",
        outcome="success",
        sanitized_details={"count": len(events)}
    )

    return PlainTextResponse(output.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=security_events.csv"
    })

@router.post("/suricata/ingest", response_model=Dict[str, Any])
async def ingest_suricata_eve(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
    sensor_id: str = Query("sensor-post-cgnat-01"),
    observation_point: str = Query("post_cgnat"),
    db: DatabaseManager = Depends(get_db)
):
    """
    Ingests Suricata EVE JSON event(s):
    - Normalizes & deduplicates
    - Performs immediate CGNAT subscriber attribution
    - Evaluates detection rules
    - Correlates incidents & triggers notifications
    - Enqueues to OpenSearch
    """
    ingest_svc = SuricataIngestService(db)
    detection_engine = DetectionEngine(db)
    notification_svc = NotificationService(db)

    events_list = [payload] if isinstance(payload, dict) else payload
    ingested_events: List[SecurityEvent] = []
    incidents_triggered: List[str] = []

    for raw in events_list:
        event = ingest_svc.ingest_event(raw, sensor_id=sensor_id, observation_point=observation_point)
        if event:
            ingested_events.append(event)
            # Evaluate detection rules & incident correlation
            incident = detection_engine.evaluate_event(event)
            if incident:
                incidents_triggered.append(incident.incident_id)
                # Dispatch notification if alert threshold reached
                await notification_svc.send_incident_alert(incident)

    return {
        "status": "success",
        "received_count": len(events_list),
        "ingested_count": len(ingested_events),
        "incidents_correlated": len(incidents_triggered),
        "sample_event_id": ingested_events[0].event_id if ingested_events else None
    }
