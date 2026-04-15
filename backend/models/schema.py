from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text, Boolean
from ..db.config import Base
import datetime

def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

class AgentIdentity(Base):
    __tablename__ = "agent_identities"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    role = Column(String)  # e.g., 'researcher', 'admin'
    api_key_hash = Column(String)  # SHA-256 hashed token
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    event_type = Column(String, index=True) # FIREWALL_BLOCK, HONEYPOT_TRIGGER, DLP_FINDING, etc.
    risk_score = Column(Float, index=True)
    details = Column(JSON)
    timestamp = Column(DateTime(timezone=True), index=True, default=_utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    agent_id = Column(String)
    action = Column(String)
    status = Column(String, index=True) # ALLOWED, BLOCKED, MODIFIED
    input_text = Column(Text)
    output_text = Column(Text)
    timestamp = Column(DateTime(timezone=True), index=True, default=_utcnow)


class DashboardUser(Base):
    __tablename__ = "dashboard_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="viewer")  # viewer, analyst, admin
    team = Column(String, default="default")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class UserSessionToken(Base):
    __tablename__ = "user_session_tokens"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    token_hash = Column(String, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(Integer, index=True)
    policy = Column(JSON)
    changed_by = Column(String, index=True)
    change_note = Column(String, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class PolicyChangeAudit(Base):
    __tablename__ = "policy_change_audit"

    id = Column(Integer, primary_key=True, index=True)
    policy_version = Column(Integer, index=True)
    changed_by = Column(String, index=True)
    summary = Column(String, default="")
    details = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class ThreatIntelPattern(Base):
    __tablename__ = "threat_intel_patterns"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, index=True)
    pattern = Column(String)
    reason = Column(String)
    weight = Column(Float, default=0.65)
    source = Column(String, default="manual")
    enabled = Column(Boolean, default=True)
    created_by = Column(String, default="system")
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class ToolRiskProfile(Base):
    __tablename__ = "tool_risk_profiles"

    id = Column(Integer, primary_key=True, index=True)
    tool_name = Column(String, unique=True, index=True)
    max_risk_score = Column(Float, default=0.80)
    require_approval_above = Column(Float, default=0.60)
    updated_by = Column(String, default="system")
    updated_at = Column(DateTime(timezone=True), default=_utcnow)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    agent_id = Column(String, index=True)
    role = Column(String)
    tool_name = Column(String)
    risk_score = Column(Float)
    prompt = Column(Text)
    status = Column(String, index=True, default="pending")  # pending, approved, rejected
    payload = Column(JSON)
    created_by = Column(String, index=True)
    approved_by = Column(String, default=None)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class RotatingApiKey(Base):
    __tablename__ = "rotating_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, index=True)
    label = Column(String, default="active")
    active = Column(Boolean, default=True)
    created_by = Column(String, default="system")
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class RiskCalibrationFeedback(Base):
    __tablename__ = "risk_calibration_feedback"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    expected_decision = Column(String, index=True)  # safe | blocked
    actual_decision = Column(String, index=True)  # safe | blocked
    risk_score = Column(Float, default=0.0)
    notes = Column(Text, default="")
    recorded_by = Column(String, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
