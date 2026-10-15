"""
IP Reputation & Blacklist Intelligence REST API Endpoints
WISP Network & Data Solutions (WISPnet)
"""
import io
import csv
import json
import ipaddress
from typing import List, Optional, Dict, Any, Tuple
from fastapi import APIRouter, HTTPException, Depends, Query, Response, UploadFile, File
from fastapi.responses import StreamingResponse

from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user, require_admin, require_read_or_admin
from app.models.schemas import UserResponse
from app.models.ip_intel_schemas import (
    SingleLookupRequest,
    SingleLookupResponse,
    BulkScanCreateRequest,
    BulkScanResponse,
    PublicIPInventoryItem,
    PublicIPInventoryCreate,
    PublicIPInventoryUpdate,
    ProviderConfigItem,
    ProviderConfigUpdate,
    IPIntelOverviewStats,
    IPInvestigationCreate,
    IPInvestigationItem,
    ReputationStatus
)
from app.services.ip_intel.base import is_valid_ip, get_ip_version, is_private_or_special_ip
from app.services.ip_intel.scanner import get_ip_intel_scanner
from app.services.ip_intel.cgnat_correlation import CGNATReputationCorrelator

router = APIRouter(prefix="/ip-intelligence", tags=["IP Intelligence & Reputation"])

# ---------------------------------------------------------------------------
# 1. OVERVIEW & KPIS
# ---------------------------------------------------------------------------
@router.get("/overview", response_model=IPIntelOverviewStats)
async def get_overview_stats(
    time_window: str = Query("24h", description="Time window: 1h, 24h, 7d, 30d"),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    hours_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
    hours = hours_map.get(time_window, 24)
    stats = db.get_ip_intel_overview_stats(time_window_hours=hours)
    return IPIntelOverviewStats(**stats)

# ---------------------------------------------------------------------------
# 2. SINGLE IP LOOKUP
# ---------------------------------------------------------------------------
@router.post("/check", response_model=SingleLookupResponse)
async def check_single_ip(
    req: SingleLookupRequest,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    ip = req.ip_address.strip()
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail=f"Invalid IP address format: '{ip}'")

    scanner = get_ip_intel_scanner()
    res = await scanner.check_ip(req)
    
    # Audit lookup
    db.log_ip_intel_audit(
        username=user.username,
        action="single_ip_lookup",
        target_type="ip",
        target_id=ip,
        details={"status": res.overall_status.value, "score": res.overall_score}
    )
    return res

# ---------------------------------------------------------------------------
# 3. BULK SCANNER
# ---------------------------------------------------------------------------
@router.post("/scans", response_model=BulkScanResponse)
async def create_bulk_scan(
    req: BulkScanCreateRequest,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    scanner = get_ip_intel_scanner()
    target_ips: List[str] = []

    if req.scan_type == "bulk_cidr":
        if not req.cidr_range:
            raise HTTPException(status_code=400, detail="CIDR range is required for bulk_cidr scans.")
        try:
            limit = 1024 if req.confirm_large_cidr else 256
            target_ips = scanner.expand_cidr(req.cidr_range, max_limit=limit)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    elif req.scan_type == "inventory":
        # Scan all active inventory items
        inv_items = db.get_ip_inventory(monitoring_status="active", limit=1000)
        target_ips = [item["ip_address"] for item in inv_items]
        if not target_ips:
            raise HTTPException(status_code=400, detail="No active IP addresses found in inventory.")
    else:
        # bulk_manual
        if not req.ip_list:
            raise HTTPException(status_code=400, detail="IP list cannot be empty.")
        # Deduplicate and validate
        seen = set()
        for raw in req.ip_list:
            clean = raw.strip()
            if clean and is_valid_ip(clean) and clean not in seen:
                seen.add(clean)
                target_ips.append(clean)
        if not target_ips:
            raise HTTPException(status_code=400, detail="No valid IP addresses provided.")

    scan_id = db.create_bulk_scan(
        scan_type=req.scan_type,
        target_ips=target_ips,
        scan_depth=req.scan_depth,
        selected_providers=req.selected_providers,
        concurrency_limit=req.concurrency_limit,
        created_by=user.username
    )

    # Start background job
    scanner.start_bulk_scan_job(scan_id)

    db.log_ip_intel_audit(
        username=user.username,
        action="create_bulk_scan",
        target_type="scan",
        target_id=scan_id,
        details={"targets": len(target_ips), "type": req.scan_type}
    )

    scan_record = db.get_scan(scan_id)
    return BulkScanResponse(**scan_record)

@router.get("/scans/{scan_id}", response_model=BulkScanResponse)
async def get_scan_status(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return BulkScanResponse(**scan)

@router.post("/scans/{scan_id}/pause")
async def pause_scan(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    db.set_scan_status(scan_id, "paused")
    return {"status": "paused", "scan_id": scan_id}

@router.post("/scans/{scan_id}/resume")
async def resume_scan(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    db.set_scan_status(scan_id, "running")
    scanner = get_ip_intel_scanner()
    scanner.start_bulk_scan_job(scan_id)
    return {"status": "resumed", "scan_id": scan_id}

@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    db.set_scan_status(scan_id, "cancelled")
    return {"status": "cancelled", "scan_id": scan_id}

# ---------------------------------------------------------------------------
# 4. PUBLIC IP INVENTORY
# ---------------------------------------------------------------------------
@router.get("/inventory", response_model=List[PublicIPInventoryItem])
async def list_ip_inventory(
    response: Response,
    monitoring_status: Optional[str] = None,
    reputation_status: Optional[str] = None,
    purpose_role: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = Query("recent"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    total = db.get_ip_inventory_count(
        monitoring_status=monitoring_status,
        reputation_status=reputation_status,
        purpose_role=purpose_role,
        search=search
    )
    response.headers["X-Total-Count"] = str(total)
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
    items = db.get_ip_inventory(
        monitoring_status=monitoring_status,
        reputation_status=reputation_status,
        purpose_role=purpose_role,
        search=search,
        sort_by=sort_by,
        limit=limit,
        offset=offset
    )
    return [PublicIPInventoryItem(**it) for it in items]

def parse_target_ips(target: str) -> Tuple[List[str], Optional[str]]:
    """Parses single IP, CIDR subnet, or hyphenated IP range into individual IPv4 host strings"""
    target = target.strip()
    # 1. Single IP
    try:
        ipaddress.IPv4Address(target)
        return [target], None
    except Exception:
        pass

    # 2. CIDR Prefix (e.g. 157.119.69.128/28)
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            return (hosts or [str(net.network_address)])[:512], target
        except Exception:
            pass

    # 3. Hyphenated Range: e.g. 157.119.69.130 - 157.119.69.140
    if "-" in target:
        parts = [p.strip() for p in target.split("-", 1)]
        try:
            start = ipaddress.IPv4Address(parts[0])
            end = ipaddress.IPv4Address(parts[1])
            if int(start) <= int(end):
                count = min(512, int(end) - int(start) + 1)
                ips = [str(ipaddress.IPv4Address(int(start) + i)) for i in range(count)]
                return ips, f"{parts[0]}-{parts[1]}"
        except Exception:
            pass

    return [], None

@router.post("/inventory", response_model=Dict[str, Any])
async def add_inventory_ip(
    req: PublicIPInventoryCreate,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    raw_target = req.ip_address.strip()
    ips, inferred_cidr = parse_target_ips(raw_target)
    if not ips:
        raise HTTPException(status_code=400, detail="Invalid IP address, CIDR subnet, or IP range format.")

    cidr_val = req.cidr_allocation or inferred_cidr
    added_ids = []
    for ip in ips:
        item_id = db.upsert_ip_inventory_item(
            ip_address=ip,
            cidr_allocation=cidr_val,
            inventory_identifier=req.inventory_identifier,
            routing_context=req.routing_context,
            purpose_role=req.purpose_role,
            monitoring_status=req.monitoring_status.value,
            notes=req.notes
        )
        added_ids.append(item_id)

    db.log_ip_intel_audit(
        username=user.username,
        action="add_inventory_ip",
        target_type="ip" if len(ips) == 1 else "range",
        target_id=raw_target,
        details={"role": req.purpose_role, "count": len(ips)}
    )

    msg = f"Added {ips[0]} to inventory" if len(ips) == 1 else f"Successfully added {len(ips)} IP addresses from range to inventory"
    return {
        "success": True,
        "count": len(ips),
        "id": added_ids[0] if added_ids else None,
        "ip_address": ips[0] if len(ips) == 1 else raw_target,
        "message": msg
    }

@router.put("/inventory/{ip_address}")
async def update_inventory_ip(
    ip_address: str,
    req: PublicIPInventoryUpdate,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    item = db.get_ip_inventory_item(ip_address)
    if not item:
        raise HTTPException(status_code=404, detail="IP address not found in inventory.")

    db.upsert_ip_inventory_item(
        ip_address=ip_address,
        cidr_allocation=req.cidr_allocation if req.cidr_allocation is not None else item.get("cidr_allocation"),
        inventory_identifier=req.inventory_identifier if req.inventory_identifier is not None else item.get("inventory_identifier"),
        routing_context=req.routing_context if req.routing_context is not None else item.get("routing_context"),
        purpose_role=req.purpose_role or item.get("purpose_role", "CGNAT Pool"),
        monitoring_status=req.monitoring_status.value if req.monitoring_status else item.get("monitoring_status", "active"),
        notes=req.notes if req.notes is not None else item.get("notes")
    )
    return {"success": True, "ip_address": ip_address}

@router.delete("/inventory/{ip_address}", response_model=Dict[str, Any])
async def delete_inventory_ip(
    ip_address: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    item = db.get_ip_inventory_item(ip_address)
    if not item:
        raise HTTPException(status_code=404, detail="IP address not found in inventory.")
    db.delete_ip_inventory_item(ip_address)
    db.log_ip_intel_audit(
        username=user.username,
        action="delete_inventory_ip",
        target_type="ip",
        target_id=ip_address,
        details={"ip": ip_address}
    )
    return {"success": True, "message": f"Successfully removed {ip_address} from inventory."}

# ---------------------------------------------------------------------------
# 5. IP DETAILS, HISTORY & CORRELATIONS
# ---------------------------------------------------------------------------
@router.get("/ip/{ip_address}/history")
async def get_ip_history(
    ip_address: str,
    limit: int = Query(50, ge=1, le=200),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    history = db.get_ip_reputation_history(ip_address, limit=limit)
    return history

@router.get("/ip/{ip_address}/events")
async def get_ip_suricata_events(
    ip_address: str,
    limit: int = Query(20, ge=1, le=100),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    total, alerts = CGNATReputationCorrelator.get_related_suricata_alerts(ip_address, limit=limit, db=db)
    return {"ip_address": ip_address, "total_events": total, "events": alerts}

@router.get("/ip/{ip_address}/attribution")
async def get_ip_cgnat_attribution(
    ip_address: str,
    event_port: Optional[int] = None,
    event_timestamp: Optional[str] = None,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    brief = CGNATReputationCorrelator.correlate_cgnat(
        ip_str=ip_address,
        event_port=event_port,
        event_timestamp=event_timestamp,
        db=db
    )
    return brief

# ---------------------------------------------------------------------------
# 6. PROVIDER MANAGEMENT
# ---------------------------------------------------------------------------
@router.get("/providers", response_model=List[ProviderConfigItem])
async def list_providers(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    provs = db.get_providers_config()
    return [ProviderConfigItem(**p) for p in provs]

@router.put("/providers/{provider_id}")
async def update_provider(
    provider_id: str,
    req: ProviderConfigUpdate,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    prov = db.get_provider_raw(provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found.")

    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    db.update_provider_config(provider_id, updates)
    
    db.log_ip_intel_audit(
        username=user.username,
        action="update_provider_config",
        target_type="provider",
        target_id=provider_id,
        details={"updated_fields": list(updates.keys())}
    )
    return {"success": True, "provider_id": provider_id}

@router.post("/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    prov = db.get_provider_raw(provider_id)
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found.")

    scanner = get_ip_intel_scanner()
    adapter = scanner.get_provider_instance(prov)
    health = await adapter.health_check()
    return health

# ---------------------------------------------------------------------------
# 7. INVESTIGATIONS
# ---------------------------------------------------------------------------
@router.get("/investigations", response_model=List[IPInvestigationItem])
async def list_investigations(
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    invs = db.get_investigations(status=status, limit=limit)
    return [IPInvestigationItem(**inv) for inv in invs]

@router.post("/investigations", response_model=Dict[str, Any])
async def create_investigation(
    req: IPInvestigationCreate,
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    inv_id = db.create_investigation(
        ip_address=req.ip_address,
        title=req.title,
        severity=req.severity,
        operator_notes=req.operator_notes,
        assigned_operator=user.username
    )
    return {"success": True, "investigation_id": inv_id}

# ---------------------------------------------------------------------------
# 8. EXPORT TO CSV AND JSON
# ---------------------------------------------------------------------------
@router.get("/export/csv")
async def export_inventory_csv(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    items = db.get_ip_inventory(limit=5000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP Address", "Version", "CIDR Allocation", "Identifier", "Routing Context",
        "Purpose / Role", "Monitoring Status", "Reputation Status", "Risk Score",
        "Active Listings", "Historical Listings", "Latest Abuse", "Last Checked"
    ])
    for it in items:
        writer.writerow([
            it.get("ip_address"), it.get("ip_version"), it.get("cidr_allocation"),
            it.get("inventory_identifier"), it.get("routing_context"), it.get("purpose_role"),
            it.get("monitoring_status"), it.get("current_reputation_status"), it.get("risk_score"),
            it.get("active_listing_count"), it.get("historical_listing_count"),
            it.get("latest_abuse_report"), it.get("last_checked_at")
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=wisp_ip_reputation_inventory.csv"}
    )
