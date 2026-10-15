"""
WISPnet Security Monitoring, Threat Detection & IP Reputation Intelligence Platform
FastAPI Application Entry Point
"""
import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.services.security_worker import get_security_worker
from app.database.db import get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("wispnet-security")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and Start Security Background Worker
    logger.info("Initializing WISPnet Security Platform Database...")
    db = get_db()
    
    logger.info("Starting Security Background Telemetry & Scan Worker...")
    worker = get_security_worker()
    await worker.start(interval_seconds=10)
    
    yield
    
    # Shutdown
    logger.info("Stopping Security Background Worker...")
    await worker.stop()
    logger.info("WISPnet Security Platform shut down cleanly.")

app = FastAPI(
    title="WISPnet Security Monitoring, Threat Detection & IP Reputation Intelligence Platform",
    description="Carrier-grade security operations, deterministic CGNAT attribution, intrusion telemetry, and IP reputation intelligence for WISP Network & Data Solutions.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core API Routes
app.include_router(api_router)

# System Health Endpoint
@app.get("/healthz")
async def health_check():
    return {
        "status": "ok",
        "app": "WISPnet Security & IP Reputation Intelligence Platform",
        "version": "1.0.0"
    }

# Static Web Console Mount
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(
            os.path.join(static_dir, "index.html"),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
