"""
Detection Rules Configuration API Endpoints
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel

from app.models.schemas import UserResponse
from app.models.security_schemas import DetectionRule
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user, require_admin

router = APIRouter(prefix="/security/rules", tags=["Detection Rules"])

class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    threshold_configuration: Optional[Dict[str, Any]] = None
    time_window_seconds: Optional[int] = None
    severity: Optional[str] = None
    exclusions: Optional[List[str]] = None

@router.get("", response_model=List[DetectionRule])
async def list_detection_rules(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    return db.get_detection_rules()

@router.put("/{rule_id}", response_model=Dict[str, Any])
async def update_detection_rule(
    rule_id: str,
    update: RuleUpdateRequest,
    db: DatabaseManager = Depends(get_db),
    admin: UserResponse = Depends(require_admin)
):
    success = db.update_detection_rule(
        rule_id=rule_id,
        enabled=update.enabled,
        threshold_config=update.threshold_configuration,
        time_window_seconds=update.time_window_seconds,
        severity=update.severity,
        exclusions=update.exclusions,
        operator=admin.username
    )

    if not success:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    db.log_security_audit(
        operator_id=admin.username,
        action="update_detection_rule",
        target_type="detection_rule",
        target_id=rule_id,
        outcome="success",
        sanitized_details={"enabled": update.enabled, "severity": update.severity}
    )

    return {
        "success": True,
        "rule_id": rule_id,
        "message": "Detection rule updated successfully"
    }

@router.post("/{rule_id}/test", response_model=Dict[str, Any])
async def test_rule_against_history(
    rule_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    rules = [r for r in db.get_detection_rules() if r.rule_id == rule_id]
    if not rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule = rules[0]

    # Evaluate against the last 100 security events
    events, total = db.get_security_events(limit=100)
    matched_events = []
    from app.services.detection_engine import DetectionEngine
    engine = DetectionEngine(db)

    for ev in events:
        sub_ip = ev.subscriber_cgnat_ip or ev.source_ip
        if sub_ip in rule.exclusions:
            continue
        if engine._check_rule_thresholds(rule, ev):
            matched_events.append({
                "event_id": ev.event_id,
                "timestamp": ev.event_timestamp,
                "subscriber": sub_ip,
                "signature": ev.signature_name
            })

    return {
        "rule_id": rule_id,
        "rule_name": rule.name,
        "events_tested": len(events),
        "matched_count": len(matched_events),
        "matches_sample": matched_events[:10]
    }
