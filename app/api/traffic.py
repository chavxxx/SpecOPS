"""
Traffic Analytics API Endpoints (Akvorado NetFlow & IPFIX Integration)
Provides live bandwidth distributions, top talkers, application services, and flow simulation.
"""
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends, Query, Body

from app.models.schemas import UserResponse
from app.database.db import get_db, DatabaseManager
from app.api.auth import get_current_user, require_read_or_admin, require_admin
from app.services.akvorado_adapter import AkvoradoAdapter

router = APIRouter(prefix="/security/traffic", tags=["Traffic Analytics & Flow Distributions"])

@router.get("/overview", response_model=Dict[str, Any])
async def get_traffic_overview(
    window_minutes: int = Query(60, ge=5, le=10080, description="Observation time window in minutes (5 to 10080)"),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    """
    Returns aggregated NetFlow / IPFIX traffic distributions, top subscriber CGNAT IPs,
    top public IPs, protocol breakdowns, destination application ports, and network KPIs.
    """
    adapter = AkvoradoAdapter(db=db)
    analytics = adapter.get_traffic_analytics(time_window_minutes=window_minutes)
    return {
        "status": "success",
        "analytics": analytics
    }

@router.get("/collector/status", response_model=Dict[str, Any])
async def get_collector_status(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    """
    Checks connectivity to the live Akvorado collector instance or local flow engine.
    """
    adapter = AkvoradoAdapter(db=db)
    status = await adapter.check_connectivity()
    return {
        "status": "success",
        "collector": status
    }

@router.post("/sync-router-traffic", response_model=Dict[str, Any])
async def sync_live_router_traffic(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    """
    Harvests 100% REAL subscriber bandwidth and active connection distributions
    directly from onboarded MikroTik hardware queues (/queue/simple).
    Purges any legacy synthetic/mock flow data.
    """
    adapter = AkvoradoAdapter(db=db)
    inserted = adapter.harvest_live_router_traffic()
    return {
        "status": "success",
        "flows_harvested": inserted,
        "flows_generated": inserted,
        "message": f"Successfully synchronized {inserted} real subscriber traffic records from MikroTik hardware."
    }

@router.post("/simulate", response_model=Dict[str, Any])
async def simulate_carrier_traffic(
    count: int = Query(160, ge=10, le=1000, description="Number of flow records to generate"),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    """Generates carrier flow telemetry (real router queues preferred; test flows in isolated test suites)"""
    adapter = AkvoradoAdapter(db=db)
    inserted = adapter.simulate_carrier_flows(count=count)
    return {
        "status": "success",
        "flows_generated": inserted,
        "flows_harvested": inserted,
        "message": f"Successfully processed {inserted} carrier NetFlow records."
    }

@router.post("/purge-fake-data", response_model=Dict[str, Any])
async def purge_fake_data(
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    """Purges all synthetic or mock flow records from durable store"""
    adapter = AkvoradoAdapter(db=db)
    purged = adapter.purge_simulated_flows()
    return {
        "status": "success",
        "purged_records": purged,
        "message": f"Purged {purged} synthetic flow records from the database."
    }

@router.post("/flows/ingest", response_model=Dict[str, Any])
async def ingest_flow_records(
    payload: Dict[str, Any] = Body(...),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_admin)
):
    """
    Receives and ingests an external batch of NetFlow / IPFIX flow records.
    Payload format: { "flows": [ { "source_ip": "...", "destination_ip": "...", ... } ] }
    """
    flows = payload.get("flows", [])
    if not isinstance(flows, list) or not flows:
        raise HTTPException(status_code=400, detail="Invalid payload. 'flows' must be a non-empty array.")

    adapter = AkvoradoAdapter(db=db)
    inserted = db.insert_flow_records_batch(flows)
    db.update_integration_health("Akvorado-Flow", "online", lag_ms=8.0)
    return {
        "status": "success",
        "flows_ingested": inserted,
        "message": f"Successfully ingested {inserted} flow records into durable store."
    }

@router.get("/mikrotik-script", response_model=Dict[str, Any])
async def get_mikrotik_flow_script(
    collector_ip: str = Query("10.0.0.50", description="IP address of the Akvorado / WISPnet flow collector"),
    port: int = Query(2055, ge=1, le=65535, description="NetFlow UDP port (default 2055)"),
    db: DatabaseManager = Depends(get_db),
    user: UserResponse = Depends(require_read_or_admin)
):
    """
    Generates copyable MikroTik RouterOS v7 CLI commands to configure
    /ip traffic-flow (NetFlow / IPFIX) export from routers to WISPnet / Akvorado.
    """
    adapter = AkvoradoAdapter(db=db)
    config = adapter.get_mikrotik_export_script(collector_ip=collector_ip, port=port)
    return {
        "status": "success",
        "config": config
    }
