"""
WISPnet Alerting & Notification Service
Handles webhooks, email alerts, deduplication, alert cooldowns, and audit logging.
"""
import os
import json
import httpx
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta

from app.models.security_schemas import (
    Incident,
    SecuritySeverity
)
from app.database.db import DatabaseManager, get_db

logger = logging.getLogger(__name__)

class NotificationService:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()
        self.webhook_url = os.getenv("SECURITY_WEBHOOK_URL")
        self.cooldown_minutes = int(os.getenv("ALERT_COOLDOWN_MINUTES", "15"))
        # In-memory cooldown tracking: (target_key, rule_or_category) -> last_dispatched_datetime
        self._cooldown_cache: Dict[str, datetime] = {}

    def should_alert(self, incident: Incident) -> bool:
        """Determines if an incident qualifies for an alert based on severity and cooldown"""
        # Only alert on high or critical
        if incident.severity not in (SecuritySeverity.HIGH, SecuritySeverity.CRITICAL):
            return False

        key = f"{incident.affected_subscriber_ip}_{incident.category.value}"
        last_sent = self._cooldown_cache.get(key)
        now = datetime.now(timezone.utc)

        if last_sent and (now - last_sent) < timedelta(minutes=self.cooldown_minutes):
            logger.debug(f"Notification suppressed by cooldown for {key}")
            return False

        self._cooldown_cache[key] = now
        return True

    async def send_incident_alert(
        self,
        incident: Incident,
        app_base_url: str = "http://localhost:8000"
    ) -> Dict[str, Any]:
        """
        Dispatches structured notification payload containing forensic evidence,
        CGNAT IP, PPPoE username, and incident link.
        """
        if not self.should_alert(incident):
            return {"status": "cooldown_suppressed"}

        payload = {
            "alert_type": "WISPnet Security Incident",
            "incident_id": incident.incident_id,
            "title": incident.title,
            "category": incident.category.value,
            "severity": incident.severity.value.upper(),
            "status": incident.status.value,
            "subscriber_cgnat_ip": incident.affected_subscriber_ip,
            "pppoe_username": incident.pppoe_username or "Unresolved at event time",
            "affected_public_ip": incident.affected_public_ip,
            "first_seen": incident.first_seen,
            "last_seen": incident.last_seen,
            "event_count": incident.event_count,
            "total_bytes": incident.total_bytes,
            "total_packets": incident.total_packets,
            "evidence": incident.evidence_summary,
            "incident_url": f"{app_base_url}/#incidents?id={incident.incident_id}",
            "dispatched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }

        # Log notification attempt to database
        self._log_notification(incident.incident_id, "webhook", "configured_webhook", incident.title, payload)

        if not self.webhook_url:
            logger.info(f"[WISPnet Notification] {incident.severity.value.upper()}: {incident.title} (Subscriber: {incident.affected_subscriber_ip}, User: {incident.pppoe_username})")
            return {"status": "logged_locally", "payload": payload}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(self.webhook_url, json=payload)
                return {"status": "delivered", "http_code": res.status_code}
        except Exception as e:
            logger.warning(f"Failed to deliver security webhook: {e}")
            return {"status": "delivery_failed", "error": str(e)}

    def _log_notification(
        self,
        incident_id: str,
        channel: str,
        recipient: str,
        subject: str,
        payload: Dict[str, Any]
    ):
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO notification_logs (
                    incident_id, channel, recipient, subject, payload_json, status
                ) VALUES (?, ?, ?, ?, ?, 'dispatched')
            """, (incident_id, channel, recipient, subject, json.dumps(payload)))
            conn.commit()

_notification_service_instance: Optional[NotificationService] = None

def get_notification_service() -> NotificationService:
    """Singleton getter for NotificationService"""
    global _notification_service_instance
    if _notification_service_instance is None:
        _notification_service_instance = NotificationService()
    return _notification_service_instance
