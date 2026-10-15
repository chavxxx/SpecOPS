"""
Application Configuration
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "app" / "static"
DB_FILE = os.getenv("SYNCHAVXXX_DB", str(BASE_DIR / "synchavxxx.db"))

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
