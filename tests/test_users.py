"""
Unit & Integration Tests for User Management & Role-Based Access Control (RBAC)
"""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.db import DatabaseManager
from app.models.schemas import UserCreate, UserUpdate

@pytest.fixture
def test_db(tmp_path):
    db_file = str(tmp_path / "test_users.db")
    db = DatabaseManager(db_file)
    return db

def test_database_user_seeding_and_auth(test_db):
    # Default admin user synchavxxx should be seeded
    users = test_db.get_users()
    assert len(users) >= 1
    admin_users = [u for u in users if u.username == "synchavxxx"]
    assert len(admin_users) == 1
    assert admin_users[0].role == "admin"

    # Authenticate with default password passworD1369
    auth_user = test_db.authenticate_user("synchavxxx", "passworD1369")
    assert auth_user is not None
    assert auth_user.username == "synchavxxx"
    assert auth_user.role == "admin"

    # Wrong password should fail
    assert test_db.authenticate_user("synchavxxx", "wrong_password") is None

def test_create_and_update_users(test_db):
    # Create read-only user
    ro_id = test_db.create_user(UserCreate(
        username="viewer1",
        password="password123",
        role="read-only",
        full_name="NOC Observer"
    ))
    assert ro_id is not None

    ro_user = test_db.get_user_by_username("viewer1")
    assert ro_user is not None
    assert ro_user.role == "read-only"
    assert ro_user.full_name == "NOC Observer"

    # Verify authentication
    auth_ro = test_db.authenticate_user("viewer1", "password123")
    assert auth_ro is not None
    assert auth_ro.role == "read-only"

    # Update role to admin and change password
    test_db.update_user(ro_id, UserUpdate(
        password="newpassword456",
        role="admin",
        full_name="Promoted Admin"
    ))

    # Old password fails, new succeeds
    assert test_db.authenticate_user("viewer1", "password123") is None
    auth_promoted = test_db.authenticate_user("viewer1", "newpassword456")
    assert auth_promoted is not None
    assert auth_promoted.role == "admin"
    assert auth_promoted.full_name == "Promoted Admin"

def test_prevent_deleting_last_admin(test_db):
    admin = test_db.get_user_by_username("synchavxxx")
    assert admin is not None

    # Deleting only admin must raise ValueError
    with pytest.raises(ValueError, match="Cannot delete the last remaining active Admin user"):
        test_db.delete_user(admin.id)

    # Disabling only admin must raise ValueError
    with pytest.raises(ValueError, match="Cannot disable or demote the last remaining active Admin user"):
        test_db.update_user(admin.id, UserUpdate(enabled=False))

    # Create second admin
    admin2_id = test_db.create_user(UserCreate(
        username="admin2",
        password="password456",
        role="admin"
    ))

    # Now deleting first admin succeeds
    assert test_db.delete_user(admin.id) is True
    assert test_db.get_user_by_username("synchavxxx") is None

@pytest.mark.asyncio
async def test_auth_api_workflow(monkeypatch, tmp_path):
    test_db_file = str(tmp_path / "test_api_users.db")
    db = DatabaseManager(test_db_file)
    from app.database import db as db_module
    monkeypatch.setattr(db_module, "get_db", lambda: db)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 0. Unauthenticated access to admin endpoint returns 401
        unauth_res = await client.post("/api/users", json={"username": "unauth", "password": "123"})
        assert unauth_res.status_code == 401

        # 1. Login as default admin (synchavxxx / passworD1369)
        res = await client.post("/api/auth/login", json={"username": "synchavxxx", "password": "passworD1369"})
        assert res.status_code == 200
        data = res.json()
        assert "token" in data
        assert data["user"]["role"] == "admin"
        assert data["user"]["username"] == "synchavxxx"
        admin_token = data["token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # 2. Check /api/auth/me
        me_res = await client.get("/api/auth/me", headers=admin_headers)
        assert me_res.status_code == 200
        assert me_res.json()["user"]["username"] == "synchavxxx"
        assert me_res.json()["can_edit"] is True

        # 3. Create a read-only user
        import uuid
        test_uname = f"noc_op_{uuid.uuid4().hex[:6]}"
        create_res = await client.post("/api/users", json={
            "username": test_uname,
            "password": "operatorpass",
            "role": "read-only",
            "full_name": "Shift Operator"
        }, headers=admin_headers)
        assert create_res.status_code == 200
        user_id = create_res.json()["id"]

        # 4. Login as read-only user
        ro_login = await client.post("/api/auth/login", json={"username": test_uname, "password": "operatorpass"})
        assert ro_login.status_code == 200
        ro_token = ro_login.json()["token"]
        ro_headers = {"Authorization": f"Bearer {ro_token}"}

        # 5. Read-only user can access CGNAT mappings (read allowed)
        mappings_res = await client.get("/api/cgnat/mappings", headers=ro_headers)
        assert mappings_res.status_code == 200

        # 6. Read-only user CANNOT generate CGNAT mappings (403 Forbidden)
        forbidden_gen = await client.post("/api/cgnat/mappings/generate", json={
            "public_pool_start": "157.119.69.129",
            "public_pool_end": "157.119.69.130",
            "subscriber_pool_start": "100.91.0.2",
            "port_block_size": 2048
        }, headers=ro_headers)
        assert forbidden_gen.status_code == 403

        # 7. Read-only user CANNOT update security settings (403 Forbidden)
        forbidden_settings = await client.post("/api/security/settings", json={
            "core_router_host": "1.2.3.4"
        }, headers=ro_headers)
        assert forbidden_settings.status_code == 403

        # 8. Read-only user CANNOT manage users (403 Forbidden)
        forbidden_users = await client.get("/api/users", headers=ro_headers)
        assert forbidden_users.status_code == 403

        # 9. Admin can update and delete user
        update_res = await client.put(f"/api/users/{user_id}", json={
            "full_name": "Senior Operator"
        }, headers=admin_headers)
        assert update_res.status_code == 200

        del_res = await client.delete(f"/api/users/{user_id}", headers=admin_headers)
        assert del_res.status_code == 200
