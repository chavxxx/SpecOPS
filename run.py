#!/usr/bin/env python3
"""
WISPnet Security Monitoring & IP Reputation Intelligence Platform
Service Launcher & CLI Runner
"""
import sys
import os
import argparse
import logging
import uvicorn

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database.db import get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("wispnet-security")

def run_server(host="0.0.0.0", port=8000, reload=False):
    """Starts the FastAPI Web Dashboard & Background Security Telemetry Engine"""
    logger.info(f"Starting WISPnet Security Platform at http://{host}:{port}")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
        access_log=True,
        loop="auto",
        http="auto"
    )

def main():
    parser = argparse.ArgumentParser(
        description="WISPnet Security Monitoring, Threat Detection & IP Reputation Platform"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Web console host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Web console port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable hot reload for development")
    parser.add_argument("--seed-demo", action="store_true", help="Seed demo security telemetry and sample events")

    args = parser.parse_args()

    # Pre-flight check database initialization
    get_db()

    if args.seed_demo:
        from scripts.seed_security_data import main as seed_data
        logger.info("Seeding realistic demo security telemetry and test events...")
        seed_data()

    run_server(args.host, args.port, reload=args.reload)

if __name__ == "__main__":
    main()
