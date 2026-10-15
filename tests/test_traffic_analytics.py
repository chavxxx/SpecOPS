"""
Automated Integration Tests for Akvorado Flow Analytics & Traffic Distributions
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.db import get_db

@pytest.fixture
def test_db():
    return get_db()

@pytest.mark.asyncio
async def test_traffic_overview_anonymous_rejected(test_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/security/traffic/overview")
        assert res.status_code == 401

@pytest.mark.asyncio
async def test_traffic_analytics_lifecycle(test_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login as admin
        login_res = await client.post("/api/auth/login", json={
            "username": "synchavxxx",
            "password": "passworD1369"
        })
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Get collector status
        status_res = await client.get("/api/security/traffic/collector/status", headers=headers)
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert status_data["status"] == "success"
        assert "collector" in status_data
        assert "url" in status_data["collector"]

        # 3. Get initial overview
        overview_res = await client.get("/api/security/traffic/overview?window_minutes=60", headers=headers)
        assert overview_res.status_code == 200
        overview = overview_res.json()
        assert overview["status"] == "success"
        analytics = overview["analytics"]
        assert "kpis" in analytics
        assert "top_subscribers" in analytics
        assert "top_public_ips" in analytics
        assert "protocols" in analytics
        assert "top_destination_ports" in analytics

        # 4. Simulate carrier flow telemetry
        sim_res = await client.post("/api/security/traffic/simulate?count=50", headers=headers)
        assert sim_res.status_code == 200
        sim_data = sim_res.json()
        assert sim_data["status"] == "success"
        assert sim_data["flows_generated"] >= 50

        # 5. Verify overview after simulation reflects flow data
        after_res = await client.get("/api/security/traffic/overview?window_minutes=60", headers=headers)
        assert after_res.status_code == 200
        after_analytics = after_res.json()["analytics"]
        assert after_analytics["kpis"]["total_flows"] >= 50
        assert after_analytics["kpis"]["total_bytes"] > 0
        assert len(after_analytics["top_subscribers"]) > 0
        assert len(after_analytics["protocols"]) > 0
        assert len(after_analytics["top_destination_ports"]) > 0

        # 6. Test MikroTik flow export script generator
        script_res = await client.get("/api/security/traffic/mikrotik-script?collector_ip=10.0.0.50&port=2055", headers=headers)
        assert script_res.status_code == 200
        script_data = script_res.json()
        assert script_data["status"] == "success"
        assert "/ip traffic-flow" in script_data["config"]["script"]

        # 7. Ingest external flow batch
        batch_payload = {
            "flows": [
                {
                    "flow_id": "test-flow-001",
                    "source_ip": "100.64.12.99",
                    "destination_ip": "1.1.1.1",
                    "destination_port": 53,
                    "protocol": "udp",
                    "bytes": 512,
                    "packets": 2,
                    "subscriber_cgnat_ip": "100.64.12.99",
                    "pppoe_username": "test.user.99"
                }
            ]
        }
        ingest_res = await client.post("/api/security/traffic/flows/ingest", json=batch_payload, headers=headers)
        assert ingest_res.status_code == 200
        assert ingest_res.json()["flows_ingested"] == 1
