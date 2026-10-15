"""
Tests for Sensor Observation Points & Pipeline Health Subsystem
Verifies live diagnostic probing, carrier pipeline flow state, and sensor lifecycle CRUD.
"""
import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_get_system_health(admin_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/security/health", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "overall_status" in data
        assert "integrations" in data
        assert "sensors" in data
        assert "opensearch_queue_depth" in data
        assert "pipeline_nodes" in data
        assert "active_sensors_count" in data
        assert "total_sensors_count" in data

        # Check default pipeline nodes
        nodes = data["pipeline_nodes"]
        assert "pre_cgnat" in nodes
        assert "core_gateway" in nodes
        assert "post_cgnat" in nodes
        assert "correlation_engine" in nodes
        assert "opensearch_queue" in nodes

@pytest.mark.asyncio
async def test_run_all_health_probes(admin_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/api/security/health/check-all", headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert "probe_results" in data
        results = data["probe_results"]
        assert len(results) >= 5
        names = [r["integration_name"] for r in results]
        assert "Akvorado-Flow" in names
        assert "OpenSearch-Cluster" in names
        assert "RouterOS-Core" in names
        assert "RouterOS-PPPoE-AC" in names
        assert "Suricata-IDS" in names

@pytest.mark.asyncio
async def test_probe_single_integration(admin_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Probe Akvorado
        res_akv = await ac.post("/api/security/health/probe/Akvorado-Flow", headers=admin_headers)
        assert res_akv.status_code == 200
        akv_data = res_akv.json()
        assert akv_data["status"] == "success"
        assert akv_data["probe"]["integration_name"] == "Akvorado-Flow"

        # Probe Suricata
        res_sur = await ac.post("/api/security/health/probe/Suricata-IDS", headers=admin_headers)
        assert res_sur.status_code == 200
        sur_data = res_sur.json()
        assert sur_data["status"] == "success"
        assert sur_data["probe"]["integration_name"] == "Suricata-IDS"

@pytest.mark.asyncio
async def test_sensor_lifecycle_crud(admin_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create Sensor
        new_sensor = {
            "sensor_id": "sensor-test-border-tap-99",
            "sensor_name": "Test Border Optical TAP 99",
            "sensor_type": "tap",
            "observation_point": "post_cgnat",
            "host": "157.119.69.254",
            "interface": "sfp-sfpplus4-transit",
            "version": "TAP-10G-HW",
            "enabled": True,
            "health_status": "healthy"
        }
        create_res = await ac.post("/api/security/health/sensors", json=new_sensor, headers=admin_headers)
        assert create_res.status_code == 200
        sensor = create_res.json()
        assert sensor["sensor_id"] == "sensor-test-border-tap-99"
        assert sensor["sensor_name"] == "Test Border Optical TAP 99"
        assert sensor["observation_point"] == "post_cgnat"

        # 2. Ping Sensor Heartbeat
        ping_res = await ac.post(
            f"/api/security/health/sensors/{sensor['sensor_id']}/heartbeat",
            json={"health_status": "healthy"},
            headers=admin_headers
        )
        assert ping_res.status_code == 200
        ping_data = ping_res.json()
        assert ping_data["health_status"] == "healthy"
        assert ping_data["last_seen"] is not None

        # 3. Verify in Health listing
        list_res = await ac.get("/api/security/health", headers=admin_headers)
        assert list_res.status_code == 200
        sensors = list_res.json()["sensors"]
        sensor_ids = [s["sensor_id"] for s in sensors]
        assert "sensor-test-border-tap-99" in sensor_ids

        # 4. Delete Sensor
        del_res = await ac.delete(f"/api/security/health/sensors/{sensor['sensor_id']}", headers=admin_headers)
        assert del_res.status_code == 200
        del_data = del_res.json()
        assert del_data["status"] == "success"

        # 5. Verify 404 on deleting non-existent sensor
        del_res2 = await ac.delete("/api/security/health/sensors/non-existent-sensor-xyz", headers=admin_headers)
        assert del_res2.status_code == 404
