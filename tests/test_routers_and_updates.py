"""
Unit & Integration Tests for Router Onboarding & GitHub Updater
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.db import get_db

@pytest.fixture
def test_db():
    return get_db()

@pytest.mark.asyncio
async def test_list_routers_anonymous_rejected(test_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/routers")
        assert res.status_code == 401

@pytest.mark.asyncio
async def test_router_onboarding_crud_and_roles(test_db):
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

        # 2. List initial routers (should include seeded core & ac routers)
        list_res = await client.get("/api/routers", headers=headers)
        assert list_res.status_code == 200
        initial_routers = list_res.json()
        assert len(initial_routers) >= 2
        roles = [r["role"] for r in initial_routers]
        assert "core" in roles
        assert "ac" in roles

        # 3. Filter by role
        core_res = await client.get("/api/routers?role=core", headers=headers)
        assert core_res.status_code == 200
        for r in core_res.json():
            assert r["role"] == "core"

        # 4. Onboard new Border Router
        new_router = {
            "name": "Border BGP Gateway Edge-01",
            "role": "border",
            "host": "157.119.69.1",
            "port": 8728,
            "username": "security_ro",
            "password": "SecurePassword123!",
            "use_ssl": False,
            "use_rest": True,
            "notes": "Upstream Cogent/Telstra Transit Edge"
        }
        create_res = await client.post("/api/routers", json=new_router, headers=headers)
        assert create_res.status_code == 201
        data = create_res.json()
        assert data["status"] == "success"
        router_id = data["router_id"]

        # 5. Get single router
        get_res = await client.get(f"/api/routers/{router_id}", headers=headers)
        assert get_res.status_code == 200
        r_info = get_res.json()
        assert r_info["name"] == "Border BGP Gateway Edge-01"
        assert r_info["role"] == "border"
        assert "password" not in r_info  # Password must NEVER be exposed

        # 6. Test connectivity
        test_res = await client.post(f"/api/routers/{router_id}/test", headers=headers)
        assert test_res.status_code == 200
        test_data = test_res.json()
        assert "online" in test_data
        assert test_data["role"] == "border"

        # 7. Update router
        update_res = await client.put(f"/api/routers/{router_id}", json={
            "name": "Border BGP Gateway Edge-01 (Renamed)",
            "notes": "Updated rack position"
        }, headers=headers)
        assert update_res.status_code == 200

        # Verify update
        get_after = await client.get(f"/api/routers/{router_id}", headers=headers)
        assert get_after.json()["name"] == "Border BGP Gateway Edge-01 (Renamed)"

        # 8. Delete router
        del_res = await client.delete(f"/api/routers/{router_id}", headers=headers)
        assert del_res.status_code == 200

        # Verify deleted
        get_del = await client.get(f"/api/routers/{router_id}", headers=headers)
        assert get_del.status_code == 404

@pytest.mark.asyncio
async def test_system_info_and_update_check(test_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login_res = await client.post("/api/auth/login", json={
            "username": "synchavxxx",
            "password": "passworD1369"
        })
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. System Info
        info_res = await client.get("/api/system/info", headers=headers)
        assert info_res.status_code == 200
        info = info_res.json()
        assert "version" in info
        assert "commit" in info
        assert info["repo"] == "chavxxx/SpecOPS"

        # 2. Update Check
        check_res = await client.get("/api/system/update/check", headers=headers)
        assert check_res.status_code == 200
        check_data = check_res.json()
        assert "has_update" in check_data
        assert "current_commit" in check_data
        assert check_data["repo"] == "chavxxx/SpecOPS"
