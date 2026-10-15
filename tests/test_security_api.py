"""
Automated tests for WISPnet Security API Endpoints & RBAC Protection
"""
import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.database.db import get_db

@pytest.mark.asyncio
async def test_unauthorized_access_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/cgnat/mappings")
        assert res.status_code == 401

@pytest.mark.asyncio
async def test_analyst_can_query_cgnat_lookup(analyst_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        lookup_payload = {
            "public_ip": "157.119.69.129",
            "public_port": 2500,
            "protocol": "tcp",
            "timestamp": "2026-10-15T12:00:00Z"
        }
        res = await ac.post("/api/cgnat/lookup", json=lookup_payload, headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert "attribution_status" in data
        assert "public_ip" in data

@pytest.mark.asyncio
async def test_analyst_cannot_generate_cgnat_mappings(analyst_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        gen_payload = {
            "public_pool_start": "157.119.69.129",
            "public_pool_end": "157.119.69.130",
            "subscriber_pool_start": "100.91.0.2",
            "port_block_size": 2048
        }
        res = await ac.post("/api/cgnat/mappings/generate", json=gen_payload, headers=analyst_headers)
        assert res.status_code == 403 # Forbidden for Analyst role!

@pytest.mark.asyncio
async def test_admin_can_generate_cgnat_mappings(admin_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        gen_payload = {
            "public_pool_start": "157.119.69.129",
            "public_pool_end": "157.119.69.130",
            "subscriber_pool_start": "100.91.0.2",
            "port_block_size": 2048,
            "first_eligible_port": 2048,
            "last_eligible_port": 65535
        }
        res = await ac.post("/api/cgnat/mappings/generate?num_subscribers=10", json=gen_payload, headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["mappings_count"] == 10

@pytest.mark.asyncio
async def test_security_events_list_and_csv_export(analyst_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # List events
        res = await ac.get("/api/security/events?limit=10", headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert "events" in data
        assert "total" in data

        # CSV Export
        res_csv = await ac.get("/api/security/events/export/csv", headers=analyst_headers)
        assert res_csv.status_code == 200
        assert "event_id,timestamp_utc" in res_csv.text

@pytest.mark.asyncio
async def test_subscriber_profile_without_billing_leakage(analyst_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/security/subscribers/100.91.0.2", headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        profile = data["profile"]
        assert profile["subscriber_cgnat_ip"] == "100.91.0.2"
        # Verify strict isolation: no billing balances or card numbers
        assert "billing_balance" not in profile
        assert "payment_history" not in profile
        assert "credit_card" not in profile
        assert "manual_billing_guidance" in data

@pytest.mark.asyncio
async def test_security_settings_masks_credentials(admin_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/security/settings", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data.get("core_router_password") in (None, "********")
        assert data.get("ac_router_password") in (None, "********")

@pytest.mark.asyncio
async def test_security_health_endpoint(analyst_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/security/health", headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert "overall_status" in data
        assert "integrations" in data
        assert "sensors" in data
        assert "opensearch_queue_depth" in data
