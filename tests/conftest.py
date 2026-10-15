"""
Pytest configuration and PYTHONPATH setup
"""
import sys
import os
import pytest

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database.db import get_db
from app.api.auth import create_session_token
from app.models.schemas import UserResponse, UserCreate, UserRole

@pytest.fixture
def admin_headers():
    db = get_db()
    user = db.get_user_by_username("synchavxxx")
    if not user:
        db.create_user(UserCreate(
            username="synchavxxx",
            password="passworD1369",
            role=UserRole.ADMIN,
            full_name="WISPnet Security Administrator"
        ))
        user = db.get_user_by_username("synchavxxx")
    token = create_session_token(UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        enabled=user.enabled
    ))
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def analyst_headers():
    db = get_db()
    user = db.get_user_by_username("analyst_test")
    if not user:
        db.create_user(UserCreate(
            username="analyst_test",
            password="TestPassword123!",
            role=UserRole.READ_ONLY,
            full_name="Security Analyst"
        ))
        user = db.get_user_by_username("analyst_test")
    token = create_session_token(UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        enabled=user.enabled
    ))
    return {"Authorization": f"Bearer {token}"}
