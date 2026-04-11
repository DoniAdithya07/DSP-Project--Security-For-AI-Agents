from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text
from ..db.config import Base
import datetime

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    event_type = Column(String) # FIREWALL_BLOCK, HONEYPOT_TRIGGER, DLP_FINDING, etc.
    risk_score = Column(Float)
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    agent_id = Column(String)
    action = Column(String)
    status = Column(String, index=True) # ALLOWED, BLOCKED, MODIFIED
    input_text = Column(Text)
    output_text = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
