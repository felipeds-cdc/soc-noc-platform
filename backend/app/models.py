"""
Modelos Pydantic para request/response
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


class SeverityEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatusEnum(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertStatusEnum(str, Enum):
    TRIGGERED = "triggered"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class UserRoleEnum(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# === Auth Models ===

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: Optional[str] = None
    role: UserRoleEnum = UserRoleEnum.ANALYST


class UserResponse(BaseModel):
    id: str
    username: str
    email: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)


# === Event Models ===

class EventBase(BaseModel):
    event_type: str
    source: str
    severity: SeverityEnum
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    command: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None


class EventCreate(EventBase):
    raw_log: Optional[str] = None
    payload: Optional[dict] = None


class EventResponse(EventBase):
    id: str
    timestamp: datetime
    status: EventStatusEnum
    analyst_id: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class EventUpdate(BaseModel):
    status: Optional[EventStatusEnum] = None
    analyst_id: Optional[str] = None
    resolution_notes: Optional[str] = None


class EventQuery(BaseModel):
    event_type: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    source_ip: Optional[str] = None
    status: Optional[EventStatusEnum] = None
    mitre_technique_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = 1
    page_size: int = 50


class EventListResponse(BaseModel):
    events: List[EventResponse]
    total: int
    page: int
    page_size: int
    has_next: bool


# === Alert Models ===

class AlertResponse(BaseModel):
    id: str
    event_id: str
    rule_id: str
    rule_name: str
    severity: SeverityEnum
    status: AlertStatusEnum
    description: Optional[str] = None
    notified_channels: List[str]
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatusEnum] = None


class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int
    page: int
    page_size: int
    has_next: bool


# === Honeypot Models ===

class HoneypotSessionResponse(BaseModel):
    id: str
    session_id: str
    source_ip: str
    source_port: Optional[int] = None
    username: str
    password: str
    login_success: bool
    commands_executed: List[dict] = []
    session_duration: Optional[int] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_latitude: Optional[float] = None
    geo_longitude: Optional[float] = None
    asn: Optional[int] = None
    started_at: datetime
    ended_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HoneypotQuery(BaseModel):
    source_ip: Optional[str] = None
    username: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = 1
    page_size: int = 50


# === Threat Hunting Models ===

class ThreatHuntQuery(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    filters: Optional[dict] = None
    time_range: Optional[str] = "24h"
    index: Optional[str] = "soc_events"


class ThreatHuntResult(BaseModel):
    query: str
    total_hits: int
    results: List[dict]
    execution_time_ms: float


class IPAnalysisResponse(BaseModel):
    ip: str
    total_events: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    event_types: dict = {}
    severity_distribution: dict = {}
    geo_info: Optional[dict] = None
    reputation: Optional[dict] = None
    associated_sessions: int = 0
    commands_executed: List[str] = []


# === Dashboard Models ===

class DashboardKPIs(BaseModel):
    total_events_24h: int
    total_alerts_24h: int
    critical_alerts: int
    high_alerts: int
    unique_source_ips: int
    honeypot_sessions_24h: int
    brute_force_attempts: int
    port_scan_attempts: int


class TimeSeriesData(BaseModel):
    timestamp: datetime
    count: int


class DashboardTimeSeries(BaseModel):
    events: List[TimeSeriesData]
    alerts: List[TimeSeriesData]


class TopItem(BaseModel):
    key: str
    count: int


class DashboardTopItems(BaseModel):
    top_source_ips: List[TopItem]
    top_event_types: List[TopItem]
    top_usernames: List[TopItem]
    top_countries: List[TopItem]


# === Report Models ===

class ReportRequest(BaseModel):
    report_type: str = Field(..., description="executive, incidents, honeypot, ioc")
    format: str = Field(default="markdown", description="markdown, html, pdf")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    include_iocs: bool = True
    include_recommendations: bool = True


class ReportResponse(BaseModel):
    report_id: str
    report_type: str
    format: str
    generated_at: datetime
    content: str
    download_url: Optional[str] = None


# === IOC Models ===

class IOCCreate(BaseModel):
    type: str = Field(..., description="ip, hash, domain, url, email")
    value: str
    severity: SeverityEnum
    confidence: int = Field(..., ge=0, le=100)
    source: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []


class IOCResponse(BaseModel):
    id: str
    type: str
    value: str
    severity: SeverityEnum
    confidence: int
    source: Optional[str] = None
    description: Optional[str] = None
    tags: List[str]
    first_seen: datetime
    last_seen: datetime
    is_active: bool

    class Config:
        from_attributes = True


class IOCListResponse(BaseModel):
    iocs: List[IOCResponse]
    total: int


# === Playbook Models ===

class PlaybookResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    trigger_event_type: Optional[str] = None
    trigger_severity: Optional[str] = None
    actions: list
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaybookExecutionResponse(BaseModel):
    id: str
    playbook_id: str
    event_id: str
    status: str
    execution_log: Optional[dict] = None
    started_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# === MITRE ATT&CK Models ===

class MITRETechniqueResponse(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str
    detected_count: int
    severity: str
    example_events: List[dict]


class MITREMatrixResponse(BaseModel):
    tactics: List[dict]
    techniques: List[MITRETechniqueResponse]


# === System Models ===

class SystemHealthResponse(BaseModel):
    redis_connected: bool
    elasticsearch_connected: bool
    postgres_connected: bool
    events_last_hour: int
    processor_lag_seconds: Optional[float] = None


class SystemConfigUpdate(BaseModel):
    key: str
    value: dict
