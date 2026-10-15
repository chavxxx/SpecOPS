"""
CGNAT Mapping & Attribution Search API Endpoints
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, Response, UploadFile, File
from fastapi.responses import PlainTextResponse

from app.models.schemas import UserResponse
from app.models.security_schemas import (
    CGNATConfig,
    CGNATMapping,
    CGNATValidationReport,
    AttributionLookupRequest,
    AttributionResult
)
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user, require_admin
from app.services.cgnat_engine import CGNATEngine
from app.services.attribution_engine import CGNATAttributionEngine

router = APIRouter(prefix="/cgnat", tags=["CGNAT Mapping & Attribution"])

@router.get("/mappings", response_model=Dict[str, Any])
async def list_cgnat_mappings(
    public_ip: Optional[str] = Query(None, description="Filter by public IP"),
    subscriber_cgnat_ip: Optional[str] = Query(None, description="Filter by subscriber CGNAT IP"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    mappings, total = db.get_cgnat_mappings(
        public_ip=public_ip,
        subscriber_cgnat_ip=subscriber_cgnat_ip,
        limit=limit,
        offset=offset
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "mappings": mappings
    }

@router.post("/mappings/generate", response_model=Dict[str, Any])
async def generate_cgnat_mappings(
    config: CGNATConfig,
    num_subscribers: Optional[int] = Query(None, description="Max subscribers to allocate"),
    save_to_database: bool = Query(True, description="Immediately persist to active mappings table"),
    db: DatabaseManager = Depends(get_db),
    admin: UserResponse = Depends(require_admin)
):
    try:
        mappings = CGNATEngine.generate_deterministic_mappings(config, num_subscribers=num_subscribers)
        validation = CGNATEngine.validate_mappings(mappings, config.first_eligible_port, config.last_eligible_port, config.port_block_size)

        if not validation.valid:
            return {
                "success": False,
                "message": "Generated mappings failed validation checks",
                "validation": validation,
                "mappings_count": 0
            }

        if save_to_database:
            db.clear_cgnat_mappings()
            inserted = db.insert_cgnat_mappings_batch(mappings)
            db.log_security_audit(
                operator_id=admin.username,
                action="generate_cgnat_mappings",
                target_type="cgnat_mappings",
                outcome="success",
                sanitized_details={"count": len(mappings), "public_pool": f"{config.public_pool_start}-{config.public_pool_end}"}
            )

        return {
            "success": True,
            "message": f"Successfully generated {len(mappings)} deterministic CGNAT port-block mappings",
            "mappings_count": len(mappings),
            "validation": validation,
            "sample": mappings[:5]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate mappings: {str(e)}")

@router.post("/mappings/validate", response_model=CGNATValidationReport)
async def validate_active_mappings(
    first_eligible_port: int = Query(2048),
    last_eligible_port: int = Query(65535),
    expected_block_size: int = Query(2048),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    mappings, _ = db.get_cgnat_mappings(limit=10000)
    report = CGNATEngine.validate_mappings(
        mappings,
        first_eligible_port=first_eligible_port,
        last_eligible_port=last_eligible_port,
        expected_block_size=expected_block_size
    )
    return report

@router.get("/mappings/export/routeros", response_class=PlainTextResponse)
async def export_routeros_v7_rules(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    mappings, _ = db.get_cgnat_mappings(limit=10000)
    if not mappings:
        raise HTTPException(status_code=404, detail="No CGNAT mappings configured to export")
    script = CGNATEngine.export_routeros_v7_script(mappings)
    return PlainTextResponse(script, media_type="text/plain", headers={
        "Content-Disposition": "attachment; filename=cgnat_routeros_v7_rules.rsc"
    })

@router.get("/mappings/export/csv", response_class=PlainTextResponse)
async def export_cgnat_csv(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    mappings, _ = db.get_cgnat_mappings(limit=10000)
    if not mappings:
        raise HTTPException(status_code=404, detail="No CGNAT mappings configured to export")
    csv_text = CGNATEngine.export_csv(mappings)
    return PlainTextResponse(csv_text, media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=cgnat_mappings.csv"
    })

@router.post("/mappings/import", response_model=Dict[str, Any])
async def import_cgnat_csv(
    csv_data: str,
    db: DatabaseManager = Depends(get_db),
    admin: UserResponse = Depends(require_admin)
):
    try:
        mappings = CGNATEngine.import_csv(csv_data)
        validation = CGNATEngine.validate_mappings(mappings)
        if not validation.valid:
            raise HTTPException(status_code=400, detail=f"Imported CSV failed validation: {validation.issues}")

        inserted = db.insert_cgnat_mappings_batch(mappings)
        db.log_security_audit(
            operator_id=admin.username,
            action="import_cgnat_csv",
            target_type="cgnat_mappings",
            outcome="success",
            sanitized_details={"count": inserted}
        )
        return {
            "success": True,
            "imported_count": inserted,
            "validation": validation
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV import failed: {str(e)}")

@router.post("/lookup", response_model=AttributionResult)
async def attribute_subscriber(
    request: AttributionLookupRequest,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(get_current_user)
):
    """
    Core CGNAT Subscriber Attribution Endpoint:
    Accepts public IP, source port, protocol, timestamp, and returns the resolved
    subscriber CGNAT IP, active PPPoE username, and confidence state.
    """
    engine = CGNATAttributionEngine(db)
    result = engine.attribute(request)

    # Audit lookup for forensic traceability
    db.log_security_audit(
        operator_id=user.username,
        action="cgnat_attribution_lookup",
        target_type="cgnat_lookup",
        target_id=f"{request.public_ip}:{request.public_port}",
        outcome=result.attribution_status.value,
        sanitized_details={
            "public_ip": request.public_ip,
            "public_port": request.public_port,
            "resolved_cgnat_ip": result.subscriber_cgnat_ip,
            "resolved_username": result.pppoe_username
        }
    )
    return result
