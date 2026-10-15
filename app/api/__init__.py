"""
API Router Aggregator for WISPnet Security & IP Intelligence Platform
"""
from fastapi import APIRouter

from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.cgnat import router as cgnat_router
from app.api.security_events import router as security_events_router
from app.api.detection_rules import router as detection_rules_router
from app.api.incidents import router as incidents_router
from app.api.subscribers import router as subscribers_router
from app.api.health import router as health_router
from app.api.traffic import router as traffic_router
from app.api.security_settings import router as security_settings_router
from app.api.audit import router as audit_router
from app.api.ip_intel import router as ip_intel_router
from app.api.routers import router as routers_router
from app.api.system import router as system_router

api_router = APIRouter(prefix="/api")

# Authentication & Access Control
api_router.include_router(auth_router)
api_router.include_router(users_router)

# CGNAT Attribution & Port Mapping
api_router.include_router(cgnat_router)

# Security Events & Intrusion Telemetry
api_router.include_router(security_events_router)

# Detection Rules
api_router.include_router(detection_rules_router)

# Security Incidents & Investigations
api_router.include_router(incidents_router)

# Subscriber Investigation Profiles
api_router.include_router(subscribers_router)

# Sensors & Health Diagnostics
api_router.include_router(health_router)

# Traffic Analytics (Akvorado flow linkage)
api_router.include_router(traffic_router)

# Security & Router Settings
api_router.include_router(security_settings_router)

# Router Onboarding & Hardware Management
api_router.include_router(routers_router)

# Security Audit Logs
api_router.include_router(audit_router)

# IP Reputation & Blacklist Intelligence
api_router.include_router(ip_intel_router)

# System & GitHub Updates
api_router.include_router(system_router)

__all__ = ["api_router"]
