"""
WISPnet Background Security Worker
Periodically flushes OpenSearch durable queue buffer and maintains integration health.
"""
import asyncio
import logging
from typing import Optional

from app.database.db import get_db, DatabaseManager
from app.services.opensearch_adapter import OpenSearchAdapter

logger = logging.getLogger(__name__)

class SecurityBackgroundWorker:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()
        self.opensearch = OpenSearchAdapter(db=self.db)
        self.running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self, interval_seconds: int = 10):
        if self.running:
            return
        self.running = True
        self._task = asyncio.create_task(self._run_loop(interval_seconds))
        logger.info("Security background worker started")

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Security background worker stopped")

    async def _run_loop(self, interval_seconds: int):
        while self.running:
            try:
                # 1. Flush OpenSearch durable queue
                flushed = await self.opensearch.flush_buffer(batch_size=50)
                if flushed > 0:
                    logger.debug(f"Flushed {flushed} security documents to OpenSearch")

                # 2. Check OpenSearch connectivity
                await self.opensearch.check_connectivity()

                # 3. Resume any interrupted or pending IP intelligence scans
                from app.services.ip_intel.scanner import get_ip_intel_scanner
                scanner = get_ip_intel_scanner()
                with self.db._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT scan_id FROM ip_intel_scans WHERE status = 'running' LIMIT 1;")
                    active_scan = cursor.fetchone()
                    if active_scan:
                        scanner.start_bulk_scan_job(active_scan[0])

            except Exception as e:
                logger.error(f"Error in security background worker: {e}")

            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                break

_worker_instance: Optional[SecurityBackgroundWorker] = None

def get_security_worker() -> SecurityBackgroundWorker:
    global _worker_instance
    if _worker_instance is None:
        _worker_instance = SecurityBackgroundWorker()
    return _worker_instance
