"""
SQLite Database Layer for WISPnet Security Monitoring & IP Reputation Intelligence Platform
"""
import sqlite3
import json
import uuid
import os
import hashlib
import secrets
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from app.models.schemas import (
    User,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserRole
)
from app.database.security_db import SecurityDatabaseMixin
from app.database.ip_intel_db import IPIntelDatabaseMixin

DB_FILE = os.getenv("WISP_SECURITY_DB", "wisp_security.db")

class DatabaseManager(SecurityDatabaseMixin, IPIntelDatabaseMixin):
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    @property
    def db_file(self) -> str:
        return self.db_path

    def get_connection(self) -> sqlite3.Connection:
        return self._get_connection()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'read-only',
                    full_name TEXT DEFAULT '',
                    enabled INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 1.1 App Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. Initialize Security & Attribution Tables
            self._init_security_db(conn)

            # 3. Initialize IP Intelligence & Reputation Tables
            self._init_ip_intel_db(conn)

            # 4. Seed Default Admin & Analyst Users if users table is empty
            cursor.execute("SELECT COUNT(*) FROM users;")
            user_count = cursor.fetchone()[0]
            if user_count == 0:
                pwd_hash, salt = self._hash_password("passworD1369")
                cursor.execute("""
                    INSERT INTO users (id, username, password_hash, salt, role, full_name, enabled)
                    VALUES (?, ?, ?, ?, 'admin', 'WISPnet Security Administrator', 1);
                """, ("895d2761", "synchavxxx", pwd_hash, salt))

                a_hash, a_salt = self._hash_password("analyst123")
                cursor.execute("""
                    INSERT INTO users (id, username, password_hash, salt, role, full_name, enabled)
                    VALUES (?, ?, ?, ?, 'read-only', 'Security Analyst', 1);
                """, ("9149fa44", "analyst_test", a_hash, a_salt))

            conn.commit()

    # ------------------------------------------------------------------------
    # User Management & Authentication Methods
    # ------------------------------------------------------------------------
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        if not salt:
            salt = secrets.token_hex(16)
        salted = f"{salt}:{password}".encode('utf-8')
        pwd_hash = hashlib.sha256(salted).hexdigest()
        return pwd_hash, salt

    def _verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        check_hash, _ = self._hash_password(password, salt)
        return hmac_compare(check_hash, stored_hash)

    def get_users(self) -> List[UserResponse]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users ORDER BY username ASC")
            rows = cursor.fetchall()
            return [
                UserResponse(
                    id=row["id"],
                    username=row["username"],
                    role=row["role"] or "read-only",
                    full_name=row["full_name"] or "",
                    enabled=bool(row["enabled"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"]
                )
                for row in rows
            ]

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return User(
                id=row["id"],
                username=row["username"],
                password_hash=row["password_hash"],
                salt=row["salt"],
                role=row["role"] or "read-only",
                full_name=row["full_name"] or "",
                enabled=bool(row["enabled"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"]
            )

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return User(
                id=row["id"],
                username=row["username"],
                password_hash=row["password_hash"],
                salt=row["salt"],
                role=row["role"] or "read-only",
                full_name=row["full_name"] or "",
                enabled=bool(row["enabled"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"]
            )

    def create_user(self, user_in: UserCreate) -> str:
        clean_user = user_in.username.strip()
        existing = self.get_user_by_username(clean_user)
        if existing:
            raise ValueError(f"User '{clean_user}' already exists.")

        pwd_hash, salt = self._hash_password(user_in.password)
        user_id = str(uuid.uuid4())[:8]
        role = "admin" if user_in.role.lower() == "admin" else "read-only"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (id, username, password_hash, salt, role, full_name, enabled)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (user_id, clean_user, pwd_hash, salt, role, user_in.full_name or ""))
            conn.commit()
        return user_id

    def update_user(self, user_id: str, updates: UserUpdate) -> bool:
        user = self.get_user_by_id(user_id)
        if not user:
            return False

        if (updates.enabled is False or (updates.role and updates.role != "admin")) and user.role == "admin":
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE role = 'admin' AND enabled = 1 AND id != ?", (user_id,))
                row = cursor.fetchone()
                if row and row["admin_count"] == 0:
                    raise ValueError("Cannot disable or demote the last remaining active Admin user.")

        query_parts = []
        params = []

        if updates.full_name is not None:
            query_parts.append("full_name = ?")
            params.append(updates.full_name)

        if updates.role is not None:
            role = "admin" if updates.role.lower() == "admin" else "read-only"
            query_parts.append("role = ?")
            params.append(role)

        if updates.enabled is not None:
            query_parts.append("enabled = ?")
            params.append(1 if updates.enabled else 0)

        if updates.password:
            pwd_hash, salt = self._hash_password(updates.password)
            query_parts.append("password_hash = ?")
            query_parts.append("salt = ?")
            params.extend([pwd_hash, salt])

        if not query_parts:
            return True

        query_parts.append("updated_at = CURRENT_TIMESTAMP")
        params.append(user_id)

        sql = f"UPDATE users SET {', '.join(query_parts)} WHERE id = ?"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor.rowcount > 0

    def delete_user(self, user_id: str) -> bool:
        user = self.get_user_by_id(user_id)
        if not user:
            return False

        if user.role == "admin":
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE role = 'admin' AND enabled = 1 AND id != ?", (user_id,))
                row = cursor.fetchone()
                if row and row["admin_count"] == 0:
                    raise ValueError("Cannot delete the last remaining active Admin user.")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    def authenticate_user(self, username: str, password: str) -> Optional[UserResponse]:
        user = self.get_user_by_username(username)
        if not user or not user.enabled:
            return None

        if self._verify_password(password, user.password_hash, user.salt):
            return UserResponse(
                id=user.id,
                username=user.username,
                role=user.role,
                full_name=user.full_name,
                enabled=user.enabled,
                created_at=user.created_at,
                updated_at=user.updated_at
            )
        return None

def hmac_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)

_db_instance: Optional[DatabaseManager] = None

def get_db() -> DatabaseManager:
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager()
    return _db_instance
