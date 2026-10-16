"""
Pydantic Schemas and Enums for IP Reputation & Blacklist Intelligence Module
WISP Network & Data Solutions (WISPnet)
"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ReputationStatus(str, Enum):
    CLEAN = "CLEAN"
    LISTED = "LISTED"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    UNKNOWN = "UNKNOWN"
    INCOMPLETE = "INCOMPLETE"

class ListingCategory(str, Enum):
    NONE = "none"
    SPAM = "spam"
    ABUSE_REPORTS = "abuse_reports"
    MALICIOUS_SCAN = "malicious_scan"
    BOTNET_C2 = "botnet_c2"
    DELIVERABILITY = "deliverability"
    THREAT_ACTOR = "threat_actor"
    OTHER = "other"

class ProviderType(str, Enum):
    DNSBL = "dnsbl"
    ABUSE_API = "abuse_api"
    THREAT_INTEL = "threat_intel"
    EMAIL_REPUTATION = "email_reputation"
    GAMING_INTEL = "gaming_intel"

class MonitoringStatus(str, Enum):
    ACTIVE = "active"
    RESERVED = "reserved"
    RETIRED = "retired"
    EXCLUDED = "excluded"
    DISABLED = "disabled"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

class ProviderResult(BaseModel):
    provider_id: str
    provider_name: str
    provider_type: ProviderType
    queried_ip: str
    check_timestamp: str
    lookup_status: str  # completed, failed, timeout, rate_limited, blocked, unsupported
    duration_ms: float = 0.0
    is_cached: bool = False
    is_listed: bool = False
    listing_category: ListingCategory = ListingCategory.NONE
    source_classification: Optional[str] = None
    source_score: Optional[float] = None
    risk_status: ReputationStatus = ReputationStatus.UNKNOWN
    evidence_summary: str = ""
    raw_reference: Optional[Dict[str, Any]] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    documentation_url: Optional[str] = None

class ScoreFactor(BaseModel):
    factor: str
    weight: float
    evidence: str

class SingleLookupRequest(BaseModel):
    ip_address: str
    depth: str = "standard"  # standard, comprehensive
    providers: Optional[List[str]] = None
    include_historical_cgnat: bool = True
    include_suricata: bool = True
    include_akvorado: bool = True
    event_timestamp: Optional[str] = None
    event_port: Optional[int] = None

class CGNATCorrelationBrief(BaseModel):
    is_cgnat_public_pool: bool
    public_ip: str
    subscriber_candidates_count: int
    exact_match: bool
    subscriber_cgnat_ip: Optional[str] = None
    pppoe_username: Optional[str] = None
    allocated_port_block: Optional[str] = None
    attribution_status: str  # verified, high_confidence, partial, unattributed
    explanation: str

class SingleLookupResponse(BaseModel):
    ip_address: str
    ip_version: int
    overall_status: ReputationStatus
    overall_score: float  # 0.0 to 100.0
    score_factors: List[ScoreFactor] = []
    total_providers_checked: int
    positive_findings_count: int
    failed_checks_count: int
    check_timestamp: str
    explanation: str
    provider_results: List[ProviderResult] = []
    cgnat_correlation: Optional[CGNATCorrelationBrief] = None
    suricata_alerts_count: int = 0
    recent_suricata_alerts: List[Dict[str, Any]] = []
    flow_summary: Optional[Dict[str, Any]] = None

class BulkScanCreateRequest(BaseModel):
    scan_type: str = "bulk_manual"  # bulk_manual, bulk_cidr, inventory
    ip_list: Optional[List[str]] = None
    cidr_range: Optional[str] = None
    scan_depth: str = "standard"
    selected_providers: Optional[List[str]] = None
    concurrency_limit: int = 5
    confirm_large_cidr: bool = False

class BulkScanResponse(BaseModel):
    scan_id: str
    scan_type: str
    target_count: int
    completed_count: int = 0
    failed_count: int = 0
    listed_count: int = 0
    status: ScanStatus = ScanStatus.PENDING
    scan_depth: str = "standard"
    progress_percent: float = 0.0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str

class PublicIPInventoryItem(BaseModel):
    id: str
    ip_address: str
    ip_version: int
    cidr_allocation: Optional[str] = None
    inventory_identifier: Optional[str] = None
    routing_context: Optional[str] = None
    purpose_role: str = "CGNAT Pool"
    monitoring_status: MonitoringStatus = MonitoringStatus.ACTIVE
    current_reputation_status: ReputationStatus = ReputationStatus.UNKNOWN
    active_listing_count: int = 0
    historical_listing_count: int = 0
    risk_score: float = 0.0
    latest_abuse_report: Optional[str] = None
    last_security_alert: Optional[str] = None
    last_checked_at: Optional[str] = None
    last_successful_lookup_at: Optional[str] = None
    notes: Optional[str] = None
    created_at: str
    updated_at: str

class PublicIPInventoryCreate(BaseModel):
    ip_address: str
    cidr_allocation: Optional[str] = None
    inventory_identifier: Optional[str] = None
    routing_context: Optional[str] = None
    purpose_role: str = "CGNAT Pool"
    monitoring_status: MonitoringStatus = MonitoringStatus.ACTIVE
    notes: Optional[str] = None

class PublicIPInventoryUpdate(BaseModel):
    cidr_allocation: Optional[str] = None
    inventory_identifier: Optional[str] = None
    routing_context: Optional[str] = None
    purpose_role: Optional[str] = None
    monitoring_status: Optional[MonitoringStatus] = None
    notes: Optional[str] = None

class ProviderConfigItem(BaseModel):
    provider_id: str
    provider_name: str
    provider_type: ProviderType
    enabled: bool
    api_endpoint: Optional[str] = None
    api_key_masked: Optional[str] = None
    has_api_key: bool = False
    auth_method: str = "none"
    dns_zone: Optional[str] = None
    timeout_seconds: float = 5.0
    rate_limit_rpm: int = 60
    max_concurrent: int = 5
    cache_duration_positive_sec: int = 1800
    cache_duration_negative_sec: int = 7200
    supported_indicators: List[str] = ["ipv4"]
    quota_limit: Optional[int] = None
    quota_remaining: Optional[int] = None
    quota_reset_at: Optional[str] = None
    last_successful_request_at: Optional[str] = None
    last_error: Optional[str] = None
    documentation_url: Optional[str] = None
    terms_notice: Optional[str] = None

class ProviderConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None  # Cleartext received from admin, hashed/masked on write
    auth_method: Optional[str] = None
    dns_zone: Optional[str] = None
    timeout_seconds: Optional[float] = None
    rate_limit_rpm: Optional[int] = None
    max_concurrent: Optional[int] = None
    cache_duration_positive_sec: Optional[int] = None
    cache_duration_negative_sec: Optional[int] = None

class IPBlockSummary(BaseModel):
    cidr_allocation: str
    total_ips: int
    active_ips: int
    disabled_ips: int
    status: str  # active, disabled, mixed
    purpose_role: Optional[str] = "CGNAT Pool"
    clean_count: int = 0
    listed_count: int = 0
    last_checked_at: Optional[str] = None

class IPBlockToggleRequest(BaseModel):
    cidr_allocation: str
    monitoring_status: MonitoringStatus = MonitoringStatus.DISABLED

class IPStatusToggleRequest(BaseModel):
    monitoring_status: MonitoringStatus = MonitoringStatus.DISABLED

class IPBlockDeleteRequest(BaseModel):
    cidr_allocation: str

class IPIntelOverviewStats(BaseModel):
    total_monitored_ips: int
    total_listed_ips: int
    total_recent_abuse_ips: int
    total_deteriorating_ips: int
    new_listings_24h: int
    resolved_listings_24h: int
    failed_provider_checks: int
    ips_requiring_review: int
    open_investigations_count: int
    last_successful_scan_at: Optional[str] = None
    provider_summary: List[Dict[str, Any]] = []
    total_disabled_ips: int = 0

class IPInvestigationCreate(BaseModel):
    ip_address: str
    title: str
    severity: str = "medium"
    operator_notes: Optional[str] = None

class IPInvestigationItem(BaseModel):
    investigation_id: str
    ip_address: str
    title: str
    status: str
    severity: str
    attributed_subscriber_ip: Optional[str] = None
    attributed_pppoe_user: Optional[str] = None
    port_block: Optional[str] = None
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    evidence_summary: Optional[str] = None
    operator_notes: Optional[str] = None
    assigned_operator: Optional[str] = None
    created_at: str
    updated_at: str

# ---------------------------------------------------------------------------
# Online Gaming & Anti-Cheat Compatibility Schemas
# ---------------------------------------------------------------------------
class GameCompatibilityStatus(str, Enum):
    EXCELLENT = "EXCELLENT"      # Green: Low latency (<50ms), clean IP, ISP-classified
    COMPATIBLE = "COMPATIBLE"    # Green: Clean IP, acceptable latency (<120ms)
    RESTRICTED = "RESTRICTED"    # Amber: High latency, possible NAT/PTR issue
    BLOCKED = "BLOCKED"          # Red: Flagged on anti-cheat blacklist or unreachable

class GameServiceItem(BaseModel):
    game_id: str
    game_name: str
    category: str
    endpoint: str
    status: GameCompatibilityStatus
    latency_ms: float
    port_requirements: str
    anti_cheat_engine: str
    notes: str

class GamingCompatibilitySummary(BaseModel):
    ip_address: str
    overall_grade: str           # "A+", "A", "B", "C", "F"
    overall_status: GameCompatibilityStatus
    anti_cheat_risk: str         # "LOW", "MODERATE", "HIGH", "CRITICAL"
    nat_suitability: str         # "NAT Type 2 (Moderate / Open Recommended)", etc.
    isp_classification: str      # "Residential / Wireless ISP", "CGNAT Subscriber Pool", etc.
    games: List[GameServiceItem] = []
    recommendations: List[str] = []

# ---------------------------------------------------------------------------
# Autonomous IP Remediation & Delisting Agent Schemas
# ---------------------------------------------------------------------------
class RemediationJobStatus(str, Enum):
    EVALUATING = "evaluating"
    SANITIZING = "sanitizing"
    DELISTING = "delisting"
    MONITORING = "monitoring"
    COMPLETED = "completed"
    FAILED = "failed"

class RemediationActionItem(BaseModel):
    id: str
    provider_id: str
    provider_name: str
    organization: Optional[str] = None
    category: Optional[str] = None
    action_type: str = "web_portal"            # web_portal, email_appeal, geofeed_update, dns_ptr
    action_title: str
    description: str
    impact: Optional[str] = None
    external_url: Optional[str] = None
    email_contact: Optional[str] = None
    removal_sla: Optional[str] = None
    requirements: List[str] = []
    appeal_letter: Optional[str] = None
    is_blocking: bool = False
    status: str = "ready"     # flagged, ready, submitted, verified
    prefilled_payload: Optional[Dict[str, Any]] = None

class RemediationJobCreate(BaseModel):
    ip_address: str
    auto_apply_mitigation: bool = False
    operator_notes: Optional[str] = None

class RemediationJobResponse(BaseModel):
    job_id: str
    ip_address: str
    status: RemediationJobStatus
    progress_percent: float = 0.0
    blocking_authorities_count: int = 0
    blocking_authorities: List[str] = []
    root_cause_analysis: Dict[str, Any] = {}
    attributed_subscriber: Optional[Dict[str, Any]] = None
    sanitization_commands: List[str] = []
    delisting_actions: List[RemediationActionItem] = []
    geofeed_entry: Optional[str] = None
    rdns_recommendation: Optional[str] = None
    verification_schedule: str = "Every 1 hour (24h window)"
    logs: List[Dict[str, Any]] = []
    created_at: str
    updated_at: str
    completed_at: Optional[str] = None
