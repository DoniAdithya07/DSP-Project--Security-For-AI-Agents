import logging
import os
import uuid
import json
import asyncio
import hashlib
import hmac
import secrets
import time
import datetime
import shutil
import smtplib
from pathlib import Path
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from copy import deepcopy
from typing import Any, Dict, Optional, List
from email.message import EmailMessage

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .db.config import engine, get_db, Base
from .models.api import ExecuteRequest
from .models.schema import (
    AuditLog,
    SecurityEvent,
    AgentIdentity,
    DashboardUser,
    UserSessionToken,
    PolicyVersion,
    PolicyChangeAudit,
    ThreatIntelPattern,
    ToolRiskProfile,
    ApprovalRequest,
    RotatingApiKey,
    RiskCalibrationFeedback,
)
from .core.firewall import firewall
from .core.gateway import secure_gateway
from .core.healing import self_healing_engine
from .core.crypto import crypto_manager
from .core.rate_limit import rate_limiter
from .core.agent_reasoner import agent_reasoner
from .core.policy import policy_engine

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


AUTH_TOKEN_TTL_HOURS = int(os.getenv("DASHBOARD_TOKEN_TTL_HOURS", "12"))
MAX_CONCURRENT_EXECUTIONS = int(os.getenv("MAX_CONCURRENT_EXECUTIONS", "8"))
MAX_PENDING_EXECUTIONS = int(os.getenv("MAX_PENDING_EXECUTIONS", "32"))
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip()
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "").strip()
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "aegismind@localhost").strip()
ALERT_EMAIL_SUBJECT_PREFIX = os.getenv("ALERT_EMAIL_SUBJECT_PREFIX", "[AegisMind Alert]").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes"}
SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")
ARCHIVE_DIR = Path(os.getenv("ARCHIVE_DIR", "backend/archives"))
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", str(ARCHIVE_DIR / "backups")))
LOGS_REQUIRE_DASHBOARD_AUTH = os.getenv("LOGS_REQUIRE_DASHBOARD_AUTH", "false").strip().lower() in {"1", "true", "yes"}
AUTO_ARCHIVE_LOGS_DAYS = int(os.getenv("AUTO_ARCHIVE_LOGS_DAYS", "0"))
AUTO_ROTATE_API_KEYS_DAYS = int(os.getenv("AUTO_ROTATE_API_KEYS_DAYS", "0"))
AUTO_ROTATE_DEACTIVATE_OLD = os.getenv("AUTO_ROTATE_DEACTIVATE_OLD", "true").strip().lower() in {"1", "true", "yes"}
AUTO_ROTATE_LABEL = os.getenv("AUTO_ROTATE_LABEL", "auto-rotated")
AUTO_ROTATE_EXPORT_PATH = os.getenv("AUTO_ROTATE_EXPORT_PATH", "").strip()
MAINTENANCE_INTERVAL_SECONDS = max(30, int(os.getenv("MAINTENANCE_INTERVAL_SECONDS", "300")))
THREAT_FEED_URL = os.getenv("THREAT_FEED_URL", "").strip()
THREAT_FEED_API_KEY = os.getenv("THREAT_FEED_API_KEY", "").strip()
THREAT_FEED_POLL_MINUTES = max(1, int(os.getenv("THREAT_FEED_POLL_MINUTES", "60")))
ENABLE_OPENTELEMETRY = os.getenv("ENABLE_OPENTELEMETRY", "false").strip().lower() in {"1", "true", "yes"}
SLO_TARGET_AVAILABILITY = float(os.getenv("SLO_TARGET_AVAILABILITY", "99.9"))
SLO_TARGET_P95_MS = float(os.getenv("SLO_TARGET_P95_MS", "800"))
PASSWORD_HASH_ALGO = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = int(os.getenv("DASHBOARD_PASSWORD_HASH_ITERATIONS", "390000"))
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

execution_semaphore = asyncio.Semaphore(MAX_CONCURRENT_EXECUTIONS)
pending_executions = 0
pending_lock = asyncio.Lock()
risk_calibration_bias = 0.0
last_threat_feed_sync_at: Optional[datetime.datetime] = None
last_threat_feed_sync_error: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class ThreatIntelImportRequest(BaseModel):
    source: str = "manual"
    items: List[Dict[str, Any]]


class ToolRiskProfileRequest(BaseModel):
    tool_name: str
    max_risk_score: float = Field(default=0.80, ge=0.0, le=1.0)
    require_approval_above: float = Field(default=0.60, ge=0.0, le=1.0)


class PolicyPublishRequest(BaseModel):
    policy: Dict[str, Any]
    change_note: str = ""


class ApprovalDecisionRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")


class RotateApiKeyRequest(BaseModel):
    label: str = "rotated-key"
    deactivate_old_keys: bool = True


class DashboardUserUpsertRequest(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="analyst")
    team: str = Field(default="default")
    is_active: bool = True


class CalibrationFeedbackRequest(BaseModel):
    session_id: str = ""
    expected_decision: str = Field(pattern="^(safe|blocked)$")
    actual_decision: str = Field(pattern="^(safe|blocked)$")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    notes: str = Field(default="", max_length=2000)


class ThreatFeedSyncRequest(BaseModel):
    url: Optional[str] = None
    source: str = "remote"


class RestoreBackupRequest(BaseModel):
    backup_file: str
    dry_run: bool = True


class SecurityStreamManager:
    def __init__(self):
        self.connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.connections = [conn for conn in self.connections if conn is not websocket]

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        async with self._lock:
            live_connections = list(self.connections)
        stale: List[WebSocket] = []
        for conn in live_connections:
            try:
                await conn.send_json(payload)
            except Exception:
                stale.append(conn)
        if stale:
            async with self._lock:
                self.connections = [conn for conn in self.connections if conn not in stale]


stream_manager = SecurityStreamManager()


class MetricsStore:
    def __init__(self):
        self._counts = Counter()
        self._latencies: Dict[str, List[float]] = defaultdict(list)

    def increment(self, key: str, value: int = 1) -> None:
        self._counts[key] += value

    def observe_latency(self, path: str, duration: float) -> None:
        bucket = self._latencies[path]
        bucket.append(duration)
        if len(bucket) > 2000:
            del bucket[:1000]

    def render_prometheus(self) -> str:
        lines: List[str] = []
        for key, value in sorted(self._counts.items()):
            safe_key = key.replace(".", "_").replace("-", "_")
            lines.append(f"aegismind_{safe_key} {value}")
        for path, values in self._latencies.items():
            if not values:
                continue
            safe_path = path.replace("/", "_").replace("-", "_").strip("_") or "root"
            avg = sum(values) / len(values)
            p95_index = max(0, int(len(values) * 0.95) - 1)
            p95 = sorted(values)[p95_index]
            lines.append(f"aegismind_latency_avg_seconds{{path=\"{safe_path}\"}} {avg:.6f}")
            lines.append(f"aegismind_latency_p95_seconds{{path=\"{safe_path}\"}} {p95:.6f}")
        return "\n".join(lines) + "\n"


metrics_store = MetricsStore()


def _legacy_password_hash(password: str) -> str:
    salt = os.getenv("DASHBOARD_AUTH_SALT", "aegis-dashboard-salt")
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return f"{PASSWORD_HASH_ALGO}${PASSWORD_HASH_ITERATIONS}${salt.hex()}${derived.hex()}"


def _verify_password(password: str, stored_hash: str) -> tuple[bool, bool]:
    if not stored_hash:
        return False, False

    if stored_hash.startswith(f"{PASSWORD_HASH_ALGO}$"):
        try:
            _, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
            derived = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iterations),
            )
            return hmac.compare_digest(derived.hex(), digest_hex), False
        except Exception:
            return False, False

    legacy_ok = hmac.compare_digest(stored_hash, _legacy_password_hash(password))
    return legacy_ok, legacy_ok


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_optional_timestamp(value: Optional[str], label: str) -> Optional[datetime.datetime]:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {label} timestamp. Use ISO-8601 format.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _read_secret(name: str) -> Optional[str]:
    secret_path = Path(SECRETS_DIR) / name
    if secret_path.exists():
        try:
            return secret_path.read_text(encoding="utf-8").strip()
        except Exception:
            return None
    env_value = os.getenv(name)
    return env_value.strip() if isinstance(env_value, str) and env_value.strip() else None


async def _notify_alert(payload: Dict[str, Any]) -> None:
    targets = []
    if ALERT_WEBHOOK_URL:
        targets.append(("webhook", ALERT_WEBHOOK_URL))
    if SLACK_WEBHOOK_URL:
        targets.append(("slack", SLACK_WEBHOOK_URL))

    for target_name, url in targets:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(url, json=payload)
            metrics_store.increment(f"alerts_{target_name}_sent_total")
        except Exception:
            metrics_store.increment(f"alerts_{target_name}_failed_total")

    if ALERT_EMAIL_TO and SMTP_HOST:
        try:
            await asyncio.to_thread(_send_email_alert_sync, payload)
            metrics_store.increment("alerts_email_sent_total")
        except Exception:
            metrics_store.increment("alerts_email_failed_total")


def _send_email_alert_sync(payload: Dict[str, Any]) -> None:
    message = EmailMessage()
    message["From"] = ALERT_EMAIL_FROM
    message["To"] = ALERT_EMAIL_TO
    message["Subject"] = f"{ALERT_EMAIL_SUBJECT_PREFIX} {payload.get('event', 'security_event')}"
    message.set_content(json.dumps(payload, indent=2))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)


def _sqlite_db_path() -> Optional[Path]:
    db_url = os.getenv("DATABASE_URL", "sqlite:///./aegismind.db")
    if not db_url.startswith("sqlite:///"):
        return None
    raw_path = db_url.replace("sqlite:///", "", 1)
    path = Path(raw_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def _rotate_api_key_internal(
    session: Session,
    *,
    label: str,
    created_by: str,
    deactivate_old_keys: bool,
    export_raw: bool = False,
) -> str:
    raw_key = secrets.token_urlsafe(24)
    hashed = crypto_manager.hash_api_key(raw_key)
    if deactivate_old_keys:
        session.query(RotatingApiKey).update({"active": False})
    session.add(
        RotatingApiKey(
            key_hash=hashed,
            label=label,
            active=True,
            created_by=created_by,
        )
    )
    if export_raw and AUTO_ROTATE_EXPORT_PATH:
        export_path = Path(AUTO_ROTATE_EXPORT_PATH)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(raw_key, encoding="utf-8")
    return raw_key


def _archive_old_logs_internal(
    session: Session,
    *,
    days: int,
    archived_by: str,
) -> Dict[str, Any]:
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    old_audit = session.query(AuditLog).filter(AuditLog.timestamp < cutoff).all()
    old_events = session.query(SecurityEvent).filter(SecurityEvent.timestamp < cutoff).all()

    export_payload = {
        "archived_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cutoff": cutoff.isoformat(),
        "archived_by": archived_by,
        "audit_logs": [
            {
                "id": row.id,
                "session_id": row.session_id,
                "agent_id": row.agent_id,
                "action": row.action,
                "status": row.status,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            } for row in old_audit
        ],
        "security_events": [
            {
                "id": row.id,
                "session_id": row.session_id,
                "event_type": row.event_type,
                "risk_score": row.risk_score,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            } for row in old_events
        ],
    }

    archive_file = ARCHIVE_DIR / f"archive-{int(time.time())}.json"
    archive_file.write_text(json.dumps(export_payload, indent=2), encoding="utf-8")

    for row in old_audit:
        session.delete(row)
    for row in old_events:
        session.delete(row)

    return {
        "archived_audit_logs": len(old_audit),
        "archived_security_events": len(old_events),
        "archive_file": str(archive_file),
    }


def _compute_calibration_bias(session: Session) -> float:
    # Feedback-driven bias:
    # false-negative (expected blocked, actual safe) -> increase risk
    # false-positive (expected safe, actual blocked) -> decrease risk
    rows = (
        session.query(RiskCalibrationFeedback)
        .order_by(RiskCalibrationFeedback.created_at.desc())
        .limit(500)
        .all()
    )
    if not rows:
        return 0.0

    false_negative = 0
    false_positive = 0
    for row in rows:
        if row.expected_decision == "blocked" and row.actual_decision == "safe":
            false_negative += 1
        if row.expected_decision == "safe" and row.actual_decision == "blocked":
            false_positive += 1

    total = len(rows)
    drift = (false_negative - false_positive) / total
    return round(max(-0.15, min(0.15, drift * 0.25)), 4)


async def _sync_threat_feed(
    session: Session,
    *,
    url_override: Optional[str] = None,
    source: str = "remote",
) -> Dict[str, Any]:
    global last_threat_feed_sync_at, last_threat_feed_sync_error

    target_url = (url_override or THREAT_FEED_URL).strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="Threat feed URL is not configured.")

    headers = {"Accept": "application/json"}
    if THREAT_FEED_API_KEY:
        headers["Authorization"] = f"Bearer {THREAT_FEED_API_KEY}"

    async with httpx.AsyncClient(timeout=8.0) as client:
        response = await client.get(target_url, headers=headers)
        response.raise_for_status()
        payload = response.json()

    items = payload.get("items") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise HTTPException(status_code=422, detail="Threat feed payload must be an array or {items: []}.")

    imported = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id") or f"feed_{uuid.uuid4().hex[:8]}")
        pattern = str(item.get("pattern") or "").strip()
        reason = str(item.get("reason") or "Threat intel pattern")
        weight = float(item.get("weight") or 0.65)
        if not pattern:
            continue
        existing = session.query(ThreatIntelPattern).filter(ThreatIntelPattern.rule_id == rule_id).first()
        if existing:
            existing.pattern = pattern
            existing.reason = reason
            existing.weight = max(0.0, min(weight, 1.0))
            existing.source = source
            existing.enabled = True
        else:
            session.add(
                ThreatIntelPattern(
                    rule_id=rule_id,
                    pattern=pattern,
                    reason=reason,
                    weight=max(0.0, min(weight, 1.0)),
                    source=source,
                    enabled=True,
                    created_by="system-feed",
                )
            )
        imported += 1

    _load_threat_feed_from_db(session)
    last_threat_feed_sync_at = datetime.datetime.now(datetime.timezone.utc)
    last_threat_feed_sync_error = None
    metrics_store.increment("threat_feed_sync_total")
    return {"imported": imported, "source": source, "url": target_url}


def _ensure_dashboard_admin(session: Session) -> None:
    username = os.getenv("DASHBOARD_ADMIN_USER", "admin")
    password = os.getenv("DASHBOARD_ADMIN_PASSWORD", "admin123")
    sync_password = os.getenv("DASHBOARD_ADMIN_SYNC_PASSWORD", "true").strip().lower() in {"1", "true", "yes"}
    existing = session.query(DashboardUser).filter(DashboardUser.username == username).first()
    if existing:
        if sync_password:
            existing.password_hash = _password_hash(password)
            existing.role = "admin"
            existing.team = existing.team or "security"
            existing.is_active = True
        return
    session.add(
        DashboardUser(
            username=username,
            password_hash=_password_hash(password),
            role="admin",
            team="security",
            is_active=True,
        )
    )
    logger.info("Initialized default dashboard admin user: %s", username)


def _ensure_bootstrap_api_key(session: Session) -> None:
    required_key = _read_secret("SECURITY_API_KEY")
    if not required_key:
        return
    hashed = crypto_manager.hash_api_key(required_key)
    existing = session.query(RotatingApiKey).filter(RotatingApiKey.key_hash == hashed, RotatingApiKey.active == True).first()
    if existing:
        return
    session.add(
        RotatingApiKey(
            key_hash=hashed,
            label="bootstrap-secret",
            active=True,
            created_by="system",
        )
    )


def _ensure_initial_policy_version(session: Session) -> None:
    existing = session.query(PolicyVersion).count()
    if existing:
        return
    policy_payload = policy_engine.export_policy()
    session.add(
        PolicyVersion(
            version=1,
            policy=policy_payload,
            changed_by="system",
            change_note="bootstrap policy",
        )
    )
    session.add(
        PolicyChangeAudit(
            policy_version=1,
            changed_by="system",
            summary="Initialized baseline policy",
            details=policy_payload,
        )
    )


def _load_threat_feed_from_db(session: Session) -> None:
    feed_rules = session.query(ThreatIntelPattern).filter(ThreatIntelPattern.enabled == True).all()
    firewall.update_threat_feed([
        {
            "rule_id": rule.rule_id,
            "pattern": rule.pattern,
            "reason": rule.reason,
            "weight": rule.weight,
        }
        for rule in feed_rules
    ])


def _auth_user_from_bearer(authorization: Optional[str], db: Session) -> Optional[DashboardUser]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    raw_token = authorization.split(" ", 1)[1].strip()
    if not raw_token:
        return None
    token_hash = _token_hash(raw_token)
    now = datetime.datetime.now(datetime.timezone.utc)
    token_record = db.query(UserSessionToken).filter(
        UserSessionToken.token_hash == token_hash,
        UserSessionToken.expires_at >= now
    ).first()
    if not token_record:
        return None
    user = db.query(DashboardUser).filter(
        DashboardUser.username == token_record.username,
        DashboardUser.is_active == True
    ).first()
    return user


def _init_opentelemetry() -> None:
    if not ENABLE_OPENTELEMETRY:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        provider = TracerProvider(resource=Resource.create({"service.name": "aegismind-backend"}))
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        HTTPXClientInstrumentor().instrument()
        logger.info("OpenTelemetry instrumentation enabled.")
    except Exception as exc:
        logger.warning("OpenTelemetry initialization skipped: %s", exc)


async def _maintenance_loop() -> None:
    last_threat_poll = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
    while True:
        try:
            with Session(engine) as session:
                global risk_calibration_bias
                risk_calibration_bias = _compute_calibration_bias(session)

                if AUTO_ARCHIVE_LOGS_DAYS > 0:
                    archived = _archive_old_logs_internal(
                        session,
                        days=AUTO_ARCHIVE_LOGS_DAYS,
                        archived_by="auto-maintenance",
                    )
                    if archived["archived_audit_logs"] or archived["archived_security_events"]:
                        metrics_store.increment("auto_archive_runs_total")

                if AUTO_ROTATE_API_KEYS_DAYS > 0:
                    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=AUTO_ROTATE_API_KEYS_DAYS)
                    active_key = (
                        session.query(RotatingApiKey)
                        .filter(RotatingApiKey.active == True)
                        .order_by(RotatingApiKey.created_at.desc())
                        .first()
                    )
                    if not active_key or (active_key.created_at and active_key.created_at <= cutoff):
                        _rotate_api_key_internal(
                            session,
                            label=AUTO_ROTATE_LABEL,
                            created_by="auto-maintenance",
                            deactivate_old_keys=AUTO_ROTATE_DEACTIVATE_OLD,
                            export_raw=bool(AUTO_ROTATE_EXPORT_PATH),
                        )
                        metrics_store.increment("auto_key_rotations_total")

                now = datetime.datetime.now(datetime.timezone.utc)
                should_poll_feed = (
                    bool(THREAT_FEED_URL)
                    and (now - last_threat_poll) >= datetime.timedelta(minutes=THREAT_FEED_POLL_MINUTES)
                )
                if should_poll_feed:
                    try:
                        await _sync_threat_feed(session, source="scheduled-feed")
                        last_threat_poll = now
                    except Exception as exc:
                        global last_threat_feed_sync_error
                        last_threat_feed_sync_error = str(exc)
                        metrics_store.increment("threat_feed_sync_failed_total")

                session.commit()
        except Exception:
            metrics_store.increment("maintenance_loop_errors_total")

        await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    
    with Session(engine) as session:
        if session.query(AgentIdentity).count() == 0:
            import secrets
            raw_key = secrets.token_hex(16)
            hashed = crypto_manager.hash_api_key(raw_key)
            agent = AgentIdentity(agent_id="admin-agent", role="admin", api_key_hash=hashed)
            session.add(agent)
            session.commit()
            logger.info("="*60)
            logger.info(f"INITIALIZED FIRST AGENT. ID: admin-agent | SECRET: {raw_key}")
            logger.info("="*60)
        _ensure_dashboard_admin(session)
        _ensure_bootstrap_api_key(session)
        _ensure_initial_policy_version(session)
        _load_threat_feed_from_db(session)
        global risk_calibration_bias
        risk_calibration_bias = _compute_calibration_bias(session)
        session.commit()
            
    logger.info("Database initialized")
    maintenance_task = asyncio.create_task(_maintenance_loop())
    try:
        yield
    finally:
        maintenance_task.cancel()
        try:
            await maintenance_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="AegisMind Security Framework", lifespan=lifespan)
_init_opentelemetry()
cors_origins = [origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    started = time.perf_counter()
    try:
        response = await call_next(request)
        metrics_store.increment(f"http_status_{response.status_code}")
        return response
    finally:
        elapsed = time.perf_counter() - started
        metrics_store.observe_latency(request.url.path, elapsed)


def _create_audit_log(
    db: Session,
    *,
    session_id: str,
    action: str,
    status: str,
    input_text: str,
    output_text: str,
    agent_id: str
) -> AuditLog:
    entry = AuditLog(
        session_id=session_id,
        agent_id=agent_id,
        action=action,
        status=status,
        # Data-at-Rest Protection
        input_text=crypto_manager.encrypt_text(input_text),
        output_text=crypto_manager.encrypt_text(output_text),
    )
    db.add(entry)
    return entry


def _create_security_event(
    db: Session,
    *,
    session_id: str,
    event_type: str,
    risk_score: float,
    details: Dict[str, Any],
) -> SecurityEvent:
    # Encrypt prompt if present in details
    if "prompt" in details:
        details["prompt"] = crypto_manager.encrypt_text(details["prompt"])

    event = SecurityEvent(
        session_id=session_id,
        event_type=event_type,
        risk_score=risk_score,
        details=details,
    )
    db.add(event)
    return event


SENSITIVE_DETAIL_TOKENS = ("prompt", "secret", "token", "password", "credential", "key", "output", "result", "response")
SAFE_ZONE_MAX = 0.60


def _is_privileged_agent(agent: AgentIdentity) -> bool:
    # Legacy root access is treated as privileged for compatibility with
    # existing SECURITY_API_KEY-only deployments.
    return bool(agent.role == "admin" or agent.agent_id == "legacy-agent-001")


def _is_dashboard_identity(agent: AgentIdentity) -> bool:
    return str(agent.agent_id or "").startswith("user:")


def _mask_text(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 10:
        return "*" * len(text)
    return f"{text[:4]}***{text[-3:]}"


def _mask_structure(value: Any) -> Any:
    if isinstance(value, dict):
        masked: Dict[str, Any] = {}
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(token in lowered for token in SENSITIVE_DETAIL_TOKENS):
                masked[key] = _mask_text(nested)
            else:
                masked[key] = _mask_structure(nested)
        return masked
    if isinstance(value, list):
        return [_mask_structure(item) for item in value]
    if isinstance(value, str):
        return value if len(value) <= 120 else f"{value[:117]}..."
    return value


def _build_explainability(firewall_result: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = float(firewall_result.get("risk_score") or 0.0)
    zone = "block" if risk_score >= SAFE_ZONE_MAX else "safe"
    return {
        "risk_score": round(risk_score, 4),
        "risk_percent": round(risk_score * 100, 1),
        "zone": zone,
        "safe_zone_max_percent": int(SAFE_ZONE_MAX * 100),
        "block_zone_min_percent": int(SAFE_ZONE_MAX * 100),
        "matched_rules": list(firewall_result.get("matched_rules") or []),
        "threats": list(firewall_result.get("threats") or []),
        "multi_model_guard": firewall_result.get("multi_model_guard") or {},
        "calibration": firewall_result.get("calibration") or {"bias": round(float(risk_calibration_bias), 4)},
    }



# Removed _infer_tool: Now using AgentReasoner for LLM-driven inference.


def verify_agent(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_agent_id: Optional[str] = Header(default=None, alias="X-Agent-Id"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db)
) -> AgentIdentity:
    dashboard_user = _auth_user_from_bearer(authorization, db)
    if dashboard_user:
        return AgentIdentity(
            agent_id=f"user:{dashboard_user.username}",
            role=str(dashboard_user.role or "researcher"),
            api_key_hash=""
        )

    # 1. Strong Authentication: Validate explicit agent ID mapping
    if x_api_key and x_agent_id:
        agent = db.query(AgentIdentity).filter(AgentIdentity.agent_id == x_agent_id, AgentIdentity.is_active == True).first()
        if agent and crypto_manager.hash_api_key(x_api_key) == agent.api_key_hash:
            return agent

    # 2. Rotating API keys table (preferred)
    if x_api_key:
        key_hash = crypto_manager.hash_api_key(x_api_key)
        rotation_match = db.query(RotatingApiKey).filter(
            RotatingApiKey.key_hash == key_hash,
            RotatingApiKey.active == True
        ).first()
        if rotation_match:
            return AgentIdentity(agent_id="legacy-agent-001", role="researcher")

    # 3. Legacy fallback from secrets manager/env
    required_key = _read_secret("SECURITY_API_KEY")
    if required_key and x_api_key == required_key:
        return AgentIdentity(agent_id="legacy-agent-001", role="researcher")

    raise HTTPException(status_code=401, detail="Invalid Agent credentials or unauthorized identity.")


def verify_dashboard_user(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db)
) -> DashboardUser:
    user = _auth_user_from_bearer(authorization, db)
    if not user:
        raise HTTPException(status_code=401, detail="Dashboard authentication required.")
    return user


def require_admin(user: DashboardUser = Depends(verify_dashboard_user)) -> DashboardUser:
    if str(user.role).lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin role required.")
    return user

@app.get("/")
async def root():
    return {"message": "AegisMind API is online"}


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "time": datetime.datetime.now(datetime.timezone.utc).isoformat()}

@app.post("/agent/execute")
async def execute_task(
    request: Request,
    payload: Optional[ExecuteRequest] = Body(default=None),
    prompt: Optional[str] = Query(default=None, max_length=4000),
    session_id: Optional[str] = Query(default=None, max_length=128),
    dry_run: Optional[bool] = Query(default=None),
    approval_id: Optional[int] = Query(default=None, ge=1),
    db: Session = Depends(get_db),
    agent: AgentIdentity = Depends(verify_agent),
):
    # Capture client IP for profiling
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Enforce Denial-of-Wallet & DoS protection at the Edge
    rate_limiter.check_rate_limit(agent.agent_id)
    
    request_payload = payload
    if request_payload is None:
        if prompt is None:
            raise HTTPException(status_code=422, detail="Provide request body or query prompt.")
        try:
            request_payload = ExecuteRequest(
                prompt=prompt,
                role=agent.role,
                session_id=session_id,
                dry_run=bool(dry_run) if dry_run is not None else False,
                approval_id=approval_id
            )
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif dry_run is not None:
        request_payload.dry_run = bool(dry_run)
    if approval_id is not None:
        request_payload.approval_id = approval_id

    session_id = request_payload.session_id or str(uuid.uuid4())
    global pending_executions
    async with pending_lock:
        if pending_executions >= MAX_PENDING_EXECUTIONS:
            metrics_store.increment("backpressure_rejections_total")
            raise HTTPException(status_code=503, detail="Execution queue is full. Try again shortly.")
        pending_executions += 1

    semaphore_acquired = False

    try:
        try:
            await asyncio.wait_for(execution_semaphore.acquire(), timeout=0.2)
            semaphore_acquired = True
        except TimeoutError as exc:
            metrics_store.increment("concurrency_rejections_total")
            raise HTTPException(status_code=503, detail="Execution concurrency limit reached.") from exc

        # 1. Prompt Firewall Scan
        firewall_result = firewall.scan(request_payload.prompt)
        raw_risk_score = float(firewall_result.get("risk_score") or 0.0)
        calibrated_risk = max(0.0, min(1.0, raw_risk_score + float(risk_calibration_bias)))
        if abs(calibrated_risk - raw_risk_score) >= 0.0001:
            firewall_result["risk_score"] = round(calibrated_risk, 4)
            firewall_result["is_blocked"] = calibrated_risk >= SAFE_ZONE_MAX
            firewall_result["status"] = "blocked" if firewall_result["is_blocked"] else "safe"
            firewall_result["decision"] = "block" if firewall_result["is_blocked"] else "allow"
            firewall_result["calibration"] = {
                "base_risk_score": round(raw_risk_score, 4),
                "bias": round(float(risk_calibration_bias), 4),
            }
        explainability = _build_explainability(firewall_result)

        if request_payload.dry_run:
            simulated_allowed = not firewall_result["is_blocked"]
            simulated_status = "safe" if simulated_allowed else "blocked"
            simulated_reason = (
                "Simulation shows prompt can pass firewall checks."
                if simulated_allowed
                else "Simulation shows this prompt would be blocked by firewall."
            )

            if firewall_result["is_blocked"]:
                _create_security_event(
                    db,
                    session_id=session_id,
                    event_type="FIREWALL_SIMULATION_BLOCK",
                    risk_score=float(firewall_result["risk_score"]),
                    details={
                        "prompt": request_payload.prompt,
                        "threats": firewall_result["threats"],
                        "matched_rules": firewall_result.get("matched_rules", []),
                    },
                )

            _create_audit_log(
                db,
                session_id=session_id,
                action="simulate",
                status=simulated_status,
                input_text=request_payload.prompt,
                output_text=simulated_reason,
                agent_id=agent.agent_id
            )
            db.commit()
            metrics_store.increment("simulation_requests_total")
            await stream_manager.broadcast({
                "type": "simulation",
                "session_id": session_id,
                "status": simulated_status,
                "risk_score": float(firewall_result["risk_score"]),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            return {
                "session_id": session_id,
                "firewall": firewall_result,
                "explainability": explainability,
                "gateway": {
                    "allowed": simulated_allowed,
                    "status": "simulated",
                    "simulation": True,
                    "reason": simulated_reason,
                    "agent_thought": "Dry run mode active. No real tool execution performed.",
                    "agent_response": "Simulation complete. Review explainability details before live execution.",
                },
            }

        if firewall_result["is_blocked"]:
            remediation = self_healing_engine.register_firewall_block(
                session_id,
                {
                    "prompt": request_payload.prompt,
                    "threats": firewall_result["threats"],
                    "risk_score": firewall_result["risk_score"],
                },
            )
            _create_security_event(
                db,
                session_id=session_id,
                event_type="FIREWALL_BLOCK",
                risk_score=float(firewall_result["risk_score"]),
                details={
                    "prompt": request_payload.prompt,
                    "threats": firewall_result["threats"],
                    "matched_rules": firewall_result.get("matched_rules", []),
                    "remediation": remediation,
                },
            )
            _create_audit_log(
                db,
                session_id=session_id,
                action="firewall_precheck",
                status="blocked",
                input_text=request_payload.prompt,
                output_text=f"Blocked: {', '.join(firewall_result['threats'])}",
                agent_id=agent.agent_id
            )
            db.commit()
            metrics_store.increment("blocked_firewall_total")
            await stream_manager.broadcast({
                "type": "firewall_block",
                "session_id": session_id,
                "risk_score": float(firewall_result["risk_score"]),
                "threats": list(firewall_result.get("threats", [])),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            if float(firewall_result.get("risk_score") or 0.0) >= SAFE_ZONE_MAX:
                asyncio.create_task(_notify_alert({
                    "event": "firewall_block",
                    "session_id": session_id,
                    "agent_id": agent.agent_id,
                    "risk_score": float(firewall_result.get("risk_score") or 0.0),
                    "threats": list(firewall_result.get("threats", [])),
                }))
            return {
                "session_id": session_id,
                "firewall": firewall_result,
                "gateway": {
                    "allowed": False,
                    "status": "blocked",
                    "simulation": False,
                    "reason": "Security violation detected in prompt.",
                    "remediation": remediation,
                },
                "explainability": explainability,
            }

        # 2. Tool selection and secure gateway evaluation
        reasoning = {"tool_name": request_payload.requested_tool, "args": request_payload.tool_args, "thought": "Manually requested."}
        
        if not request_payload.requested_tool:
            reasoning = agent_reasoner.infer_tool(request_payload.prompt, agent.role)
            
        selected_tool = reasoning["tool_name"]
        tool_args = reasoning["args"] or {"query": request_payload.prompt}
        current_risk = float(firewall_result.get("risk_score") or 0.0)
        tool_profile = None
        role_policy = policy_engine.role_policies.get(request_payload.role)
        policy_allows_tool = True
        if selected_tool and selected_tool != "none":
            tool_profile = db.query(ToolRiskProfile).filter(ToolRiskProfile.tool_name == selected_tool).first()
            if role_policy:
                blocked_tools = set(role_policy.get("blocked_tools", []))
                allowed_tools = set(role_policy.get("allowed_tools", []))
                policy_allows_tool = (
                    selected_tool not in policy_engine.global_blocked_tools
                    and selected_tool not in blocked_tools
                    and ("*" in allowed_tools or selected_tool in allowed_tools)
                )

        if tool_profile and current_risk > float(tool_profile.max_risk_score):
            _create_audit_log(
                db,
                session_id=session_id,
                action=selected_tool,
                status="blocked",
                input_text=request_payload.prompt,
                output_text=f"Blocked by tool risk profile. Risk {current_risk:.2f} > max {tool_profile.max_risk_score:.2f}.",
                agent_id=agent.agent_id
            )
            _create_security_event(
                db,
                session_id=session_id,
                event_type="TOOL_PROFILE_BLOCK",
                risk_score=current_risk,
                details={"tool": selected_tool, "risk_score": current_risk, "max_allowed": float(tool_profile.max_risk_score)},
            )
            db.commit()
            metrics_store.increment("blocked_tool_profile_total")
            await stream_manager.broadcast({
                "type": "tool_profile_block",
                "session_id": session_id,
                "tool": selected_tool,
                "risk_score": current_risk,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            return {
                "session_id": session_id,
                "firewall": firewall_result,
                "explainability": explainability,
                "gateway": {
                    "allowed": False,
                    "status": "blocked",
                    "simulation": False,
                    "reason": f"Tool risk profile blocked '{selected_tool}'.",
                },
            }

        approval_threshold = float(tool_profile.require_approval_above) if tool_profile else float(policy_engine.human_approval_risk_threshold)
        requires_approval = (
            selected_tool != "none"
            and policy_allows_tool
            and current_risk >= approval_threshold
            and agent.role != "admin"
        )
        if requires_approval:
            if not request_payload.approval_id:
                approval_entry = ApprovalRequest(
                    session_id=session_id,
                    agent_id=agent.agent_id,
                    role=request_payload.role,
                    tool_name=selected_tool,
                    risk_score=current_risk,
                    prompt=request_payload.prompt,
                    status="pending",
                    payload={"tool_args": tool_args, "reasoning": reasoning},
                    created_by=agent.agent_id,
                )
                db.add(approval_entry)
                _create_audit_log(
                    db,
                    session_id=session_id,
                    action=selected_tool,
                    status="pending",
                    input_text=request_payload.prompt,
                    output_text=f"Approval required for risk {current_risk:.2f}.",
                    agent_id=agent.agent_id
                )
                db.commit()
                metrics_store.increment("approval_requests_total")
                await stream_manager.broadcast({
                    "type": "approval_required",
                    "session_id": session_id,
                    "tool": selected_tool,
                    "risk_score": current_risk,
                    "approval_status": "pending",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                })
                return {
                    "session_id": session_id,
                    "firewall": firewall_result,
                    "explainability": explainability,
                    "gateway": {
                        "allowed": False,
                        "status": "approval_required",
                        "simulation": False,
                        "approval_id": approval_entry.id,
                        "reason": f"Human approval required for tool '{selected_tool}' at risk {current_risk:.2f}.",
                    },
                }

            approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_payload.approval_id).first()
            if not approval or approval.status != "approved":
                raise HTTPException(status_code=403, detail="Approval token invalid or not approved yet.")

        gateway_result = {"status": "executed", "result": "Direct conversation requested."}
        
        if selected_tool != "none":
            gateway_result = secure_gateway.request_tool_execution(
                session_id=session_id,
                role=request_payload.role,
                tool_name=selected_tool,
                args=tool_args,
                ip_address=client_ip,
            )
        
        # 3. Conversational Synthesis (The "Agent Heart")
        agent_answer = "Execution completed."
        if gateway_result["status"] in ["executed", "modified"]:
            # If no tool was used, provide a direct answer. 
            # If a tool was used, synthesize the answer based on the result.
            context_data = gateway_result.get("result", "Done") if selected_tool != "none" else "Direct conversation."
            agent_answer = agent_reasoner.synthesize_response(
                request_payload.prompt, 
                context_data, 
                reasoning.get("thought", "N/A")
            )
        
        # Attach details for the UI
        gateway_result["agent_thought"] = reasoning.get("thought", "Static analysis")
        gateway_result["agent_response"] = agent_answer

        # 4. Audit logs for all outcomes
        _create_audit_log(
            db,
            session_id=session_id,
            action=selected_tool,
            status=gateway_result["status"],
            input_text=request_payload.prompt,
            output_text=agent_answer, # Log the final synthesized answer
            agent_id=agent.agent_id
        )

        if gateway_result["status"] == "blocked":
            _create_security_event(
                db,
                session_id=session_id,
                event_type="GATEWAY_BLOCK",
                risk_score=1.0,
                details={"tool": selected_tool, "reason": gateway_result.get("reason", "Blocked by gateway")},
            )
            if gateway_result.get("remediation"):
                _create_security_event(
                    db,
                    session_id=session_id,
                    event_type="SELF_HEALING_ACTION",
                    risk_score=1.0,
                    details=gateway_result["remediation"],
                )
        elif gateway_result["status"] == "modified":
            _create_security_event(
                db,
                session_id=session_id,
                event_type="DLP_REDACTION",
                risk_score=0.7,
                details={"tool": selected_tool, "findings": gateway_result.get("dlp_findings", [])},
            )

        gateway_result["simulation"] = False
        db.commit()
        metrics_store.increment(f"gateway_status_{gateway_result['status']}_total")
        await stream_manager.broadcast({
            "type": "execution_result",
            "session_id": session_id,
            "tool": selected_tool,
            "status": gateway_result["status"],
            "risk_score": float(firewall_result.get("risk_score") or 0.0),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })
        if gateway_result["status"] == "blocked":
            asyncio.create_task(_notify_alert({
                "event": "gateway_block",
                "session_id": session_id,
                "agent_id": agent.agent_id,
                "tool": selected_tool,
                "reason": gateway_result.get("reason", "blocked"),
                "risk_score": float(firewall_result.get("risk_score") or 0.0),
            }))
        return {
            "session_id": session_id,
            "firewall": firewall_result,
            "explainability": explainability,
            "gateway": gateway_result
        }
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Database error during execution")
        raise HTTPException(status_code=500, detail="Database failure while processing request.") from exc
    finally:
        if semaphore_acquired:
            execution_semaphore.release()
        async with pending_lock:
            pending_executions = max(0, pending_executions - 1)

@app.get("/logs/security")
async def get_security_logs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_id: Optional[str] = Query(default=None, max_length=128),
    event_type: Optional[str] = Query(default=None, max_length=64),
    min_risk_score: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    max_risk_score: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    from_ts: Optional[str] = Query(default=None, description="ISO-8601 timestamp"),
    to_ts: Optional[str] = Query(default=None, description="ISO-8601 timestamp"),
    db: Session = Depends(get_db),
    agent: AgentIdentity = Depends(verify_agent),
):
    if LOGS_REQUIRE_DASHBOARD_AUTH and not _is_dashboard_identity(agent):
        raise HTTPException(status_code=403, detail="Dashboard authentication is required for log access.")

    if min_risk_score is not None and max_risk_score is not None and min_risk_score > max_risk_score:
        raise HTTPException(status_code=422, detail="min_risk_score must be <= max_risk_score.")

    parsed_from = _parse_optional_timestamp(from_ts, "from_ts")
    parsed_to = _parse_optional_timestamp(to_ts, "to_ts")
    if parsed_from and parsed_to and parsed_from > parsed_to:
        raise HTTPException(status_code=422, detail="from_ts must be <= to_ts.")

    query = db.query(SecurityEvent)
    if session_id:
        query = query.filter(SecurityEvent.session_id == session_id.strip())
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.strip())
    if min_risk_score is not None:
        query = query.filter(SecurityEvent.risk_score >= min_risk_score)
    if max_risk_score is not None:
        query = query.filter(SecurityEvent.risk_score <= max_risk_score)
    if parsed_from is not None:
        query = query.filter(SecurityEvent.timestamp >= parsed_from)
    if parsed_to is not None:
        query = query.filter(SecurityEvent.timestamp <= parsed_to)

    events = (
        query
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    privileged = _is_privileged_agent(agent)
    # Security events might contain prompt snippets in details
    for event in events:
        if isinstance(event.details, dict) and "prompt" in event.details:
            try:
                event.details["prompt"] = crypto_manager.decrypt_text(event.details["prompt"])
            except Exception:
                pass
        if not privileged:
            event.details = _mask_structure(deepcopy(event.details))
    return events

@app.get("/logs/audit")
async def get_audit_logs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_id: Optional[str] = Query(default=None, max_length=128),
    status: Optional[str] = Query(default=None, max_length=32),
    action: Optional[str] = Query(default=None, max_length=64),
    from_ts: Optional[str] = Query(default=None, description="ISO-8601 timestamp"),
    to_ts: Optional[str] = Query(default=None, description="ISO-8601 timestamp"),
    db: Session = Depends(get_db),
    agent: AgentIdentity = Depends(verify_agent),
):
    if LOGS_REQUIRE_DASHBOARD_AUTH and not _is_dashboard_identity(agent):
        raise HTTPException(status_code=403, detail="Dashboard authentication is required for log access.")

    parsed_from = _parse_optional_timestamp(from_ts, "from_ts")
    parsed_to = _parse_optional_timestamp(to_ts, "to_ts")
    if parsed_from and parsed_to and parsed_from > parsed_to:
        raise HTTPException(status_code=422, detail="from_ts must be <= to_ts.")

    query = db.query(AuditLog)
    if session_id:
        query = query.filter(AuditLog.session_id == session_id.strip())
    if status:
        query = query.filter(AuditLog.status == status.strip().lower())
    if action:
        query = query.filter(AuditLog.action == action.strip())
    if parsed_from is not None:
        query = query.filter(AuditLog.timestamp >= parsed_from)
    if parsed_to is not None:
        query = query.filter(AuditLog.timestamp <= parsed_to)

    logs = (
        query
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    privileged = _is_privileged_agent(agent)
    for log in logs:
        try:
            log.input_text = crypto_manager.decrypt_text(log.input_text)
            log.output_text = crypto_manager.decrypt_text(log.output_text)
        except Exception:
            # Fallback for old unencrypted or malformed logs
            pass
        if not privileged:
            log.input_text = _mask_text(log.input_text)
            log.output_text = _mask_text(log.output_text)
    return logs


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    return metrics_store.render_prometheus()


@app.post("/auth/login")
async def auth_login(payload: LoginRequest, db: Session = Depends(get_db)):
    username = payload.username.strip()
    user = db.query(DashboardUser).filter(
        DashboardUser.username == username,
        DashboardUser.is_active == True
    ).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    password_ok, needs_upgrade = _verify_password(payload.password, str(user.password_hash or ""))
    if not password_ok:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if needs_upgrade:
        user.password_hash = _password_hash(payload.password)

    raw_token = secrets.token_urlsafe(32)
    token_record = UserSessionToken(
        username=user.username,
        token_hash=_token_hash(raw_token),
        expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=AUTH_TOKEN_TTL_HOURS),
    )
    db.add(token_record)
    db.commit()
    metrics_store.increment("auth_login_success_total")
    return {
        "access_token": raw_token,
        "token_type": "bearer",
        "expires_hours": AUTH_TOKEN_TTL_HOURS,
        "user": {"username": user.username, "role": user.role, "team": user.team},
    }


@app.post("/auth/logout")
async def auth_logout(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    raw_token = authorization.split(" ", 1)[1].strip()
    token_hash = _token_hash(raw_token)
    token_record = db.query(UserSessionToken).filter(UserSessionToken.token_hash == token_hash).first()
    if token_record:
        db.delete(token_record)
        db.commit()
    return {"status": "logged_out"}


@app.get("/auth/me")
async def auth_me(user: DashboardUser = Depends(verify_dashboard_user)):
    return {"username": user.username, "role": user.role, "team": user.team}


@app.get("/auth/users")
async def list_dashboard_users(
    _: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    users = db.query(DashboardUser).order_by(DashboardUser.username.asc()).all()
    return [
        {
            "username": user.username,
            "role": user.role,
            "team": user.team,
            "is_active": user.is_active,
            "created_at": user.created_at,
        }
        for user in users
    ]


@app.post("/auth/users")
async def upsert_dashboard_user(
    payload: DashboardUserUpsertRequest,
    admin: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    username = payload.username.strip()
    existing = db.query(DashboardUser).filter(DashboardUser.username == username).first()
    if existing:
        existing.password_hash = _password_hash(payload.password)
        existing.role = payload.role
        existing.team = payload.team
        existing.is_active = payload.is_active
    else:
        db.add(
            DashboardUser(
                username=username,
                password_hash=_password_hash(payload.password),
                role=payload.role,
                team=payload.team,
                is_active=payload.is_active,
            )
        )
    db.commit()
    metrics_store.increment("dashboard_user_upsert_total")
    return {"status": "ok", "updated_by": admin.username, "username": username}


@app.get("/policy/current")
async def get_current_policy(user: DashboardUser = Depends(verify_dashboard_user)):
    return {"policy": policy_engine.export_policy(), "requested_by": user.username}


@app.get("/policy/versions")
async def get_policy_versions(
    limit: int = Query(default=20, ge=1, le=100),
    _: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    versions = db.query(PolicyVersion).order_by(PolicyVersion.version.desc()).limit(limit).all()
    return versions


@app.post("/policy/publish")
async def publish_policy(
    payload: PolicyPublishRequest,
    user: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        applied_policy = policy_engine.apply_policy(payload.policy)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    latest = db.query(func.max(PolicyVersion.version)).scalar() or 0
    next_version = int(latest) + 1
    db.add(
        PolicyVersion(
            version=next_version,
            policy=applied_policy,
            changed_by=user.username,
            change_note=payload.change_note,
        )
    )
    db.add(
        PolicyChangeAudit(
            policy_version=next_version,
            changed_by=user.username,
            summary=payload.change_note or "Policy published",
            details=applied_policy,
        )
    )
    db.commit()
    metrics_store.increment("policy_publish_total")
    await stream_manager.broadcast({
        "type": "policy_publish",
        "version": next_version,
        "changed_by": user.username,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    return {"version": next_version, "policy": applied_policy}


@app.post("/threat-intel/import")
async def import_threat_intel(
    payload: ThreatIntelImportRequest,
    user: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    created = 0
    for item in payload.items:
        rule_id = str(item.get("rule_id") or f"feed_{uuid.uuid4().hex[:8]}")
        pattern = str(item.get("pattern") or "").strip()
        reason = str(item.get("reason") or "Threat intel pattern")
        weight = float(item.get("weight") or 0.65)
        if not pattern:
            continue
        db.add(
            ThreatIntelPattern(
                rule_id=rule_id,
                pattern=pattern,
                reason=reason,
                weight=max(0.0, min(weight, 1.0)),
                source=payload.source,
                enabled=True,
                created_by=user.username,
            )
        )
        created += 1
    db.commit()
    _load_threat_feed_from_db(db)
    metrics_store.increment("threat_intel_import_total")
    return {"imported": created}


@app.post("/threat-intel/sync")
async def sync_threat_intel(
    payload: ThreatFeedSyncRequest,
    _: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    result = await _sync_threat_feed(db, url_override=payload.url, source=payload.source)
    db.commit()
    return result


@app.get("/threat-intel/status")
async def threat_intel_status(_: DashboardUser = Depends(verify_dashboard_user)):
    return {
        "configured_url": THREAT_FEED_URL or None,
        "poll_minutes": THREAT_FEED_POLL_MINUTES,
        "last_sync_at": last_threat_feed_sync_at,
        "last_error": last_threat_feed_sync_error,
        "loaded_patterns": len(firewall.external_patterns),
    }


@app.get("/threat-intel/list")
async def list_threat_intel(
    _: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ThreatIntelPattern).order_by(ThreatIntelPattern.created_at.desc()).all()
    return rows


@app.get("/tool-profiles")
async def list_tool_profiles(
    _: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ToolRiskProfile).order_by(ToolRiskProfile.tool_name.asc()).all()
    return rows


@app.post("/tool-profiles")
async def upsert_tool_profile(
    payload: ToolRiskProfileRequest,
    user: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    existing = db.query(ToolRiskProfile).filter(ToolRiskProfile.tool_name == payload.tool_name).first()
    if existing:
        existing.max_risk_score = payload.max_risk_score
        existing.require_approval_above = payload.require_approval_above
        existing.updated_by = user.username
        existing.updated_at = datetime.datetime.now(datetime.timezone.utc)
    else:
        db.add(
            ToolRiskProfile(
                tool_name=payload.tool_name,
                max_risk_score=payload.max_risk_score,
                require_approval_above=payload.require_approval_above,
                updated_by=user.username,
            )
        )
    db.commit()
    return {"status": "ok"}


@app.get("/approvals/pending")
async def list_pending_approvals(
    _: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ApprovalRequest).filter(ApprovalRequest.status == "pending").order_by(ApprovalRequest.created_at.desc()).limit(100).all()
    return rows


@app.post("/approvals/{approval_id}/decision")
async def decide_approval(
    approval_id: int,
    payload: ApprovalDecisionRequest,
    user: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    approval = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    approval.status = "approved" if payload.decision == "approve" else "rejected"
    approval.approved_by = user.username
    approval.approved_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    await stream_manager.broadcast({
        "type": "approval_decision",
        "approval_id": approval_id,
        "status": approval.status,
        "approved_by": user.username,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    return {"approval_id": approval_id, "status": approval.status}


@app.get("/sessions/{session_id}/replay")
async def get_session_replay(
    session_id: str,
    agent: AgentIdentity = Depends(verify_agent),
    db: Session = Depends(get_db),
):
    audit_rows = db.query(AuditLog).filter(AuditLog.session_id == session_id).order_by(AuditLog.timestamp.asc()).all()
    event_rows = db.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).order_by(SecurityEvent.timestamp.asc()).all()
    privileged = _is_privileged_agent(agent)

    for row in audit_rows:
        try:
            row.input_text = crypto_manager.decrypt_text(row.input_text)
            row.output_text = crypto_manager.decrypt_text(row.output_text)
        except Exception:
            pass
        if not privileged:
            row.input_text = _mask_text(row.input_text)
            row.output_text = _mask_text(row.output_text)

    for event in event_rows:
        if isinstance(event.details, dict) and "prompt" in event.details:
            try:
                event.details["prompt"] = crypto_manager.decrypt_text(event.details["prompt"])
            except Exception:
                pass
        if not privileged:
            event.details = _mask_structure(deepcopy(event.details))

    return {
        "session_id": session_id,
        "timeline": {
            "audit_logs": audit_rows,
            "security_events": event_rows,
        }
    }


@app.get("/analytics/scorecard")
async def get_security_scorecard(
    window_days: int = Query(default=7, ge=1, le=90),
    _: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=window_days)
    audit_rows = db.query(AuditLog).filter(AuditLog.timestamp >= cutoff).all()
    event_rows = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff).all()

    safe_statuses = {"executed", "modified", "safe"}
    blocked_statuses = {"blocked", "denied"}
    safe_count = 0
    blocked_count = 0
    daily_totals: Dict[str, Dict[str, int]] = defaultdict(lambda: {"safe": 0, "blocked": 0})
    for row in audit_rows:
        status = str(row.status or "").lower()
        date_key = row.timestamp.date().isoformat() if row.timestamp else "unknown"
        if status in safe_statuses:
            safe_count += 1
            daily_totals[date_key]["safe"] += 1
        if status in blocked_statuses:
            blocked_count += 1
            daily_totals[date_key]["blocked"] += 1

    total_actions = safe_count + blocked_count
    safe_ratio = round((safe_count / total_actions) * 100, 2) if total_actions else 0.0

    event_counter = Counter([str(event.event_type or "UNKNOWN") for event in event_rows])
    top_threats = [{"event_type": key, "count": value} for key, value in event_counter.most_common(5)]
    trend = [
        {"date": day, "safe": values["safe"], "blocked": values["blocked"]}
        for day, values in sorted(daily_totals.items())
    ]

    return {
        "window_days": window_days,
        "safe_actions": safe_count,
        "blocked_actions": blocked_count,
        "safe_ratio_percent": safe_ratio,
        "top_threats": top_threats,
        "daily_trend": trend,
    }


@app.post("/analytics/calibration/feedback")
async def create_calibration_feedback(
    payload: CalibrationFeedbackRequest,
    user: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    db.add(
        RiskCalibrationFeedback(
            session_id=payload.session_id.strip(),
            expected_decision=payload.expected_decision,
            actual_decision=payload.actual_decision,
            risk_score=payload.risk_score,
            notes=payload.notes.strip(),
            recorded_by=user.username,
        )
    )
    db.commit()
    global risk_calibration_bias
    risk_calibration_bias = _compute_calibration_bias(db)
    metrics_store.increment("calibration_feedback_total")
    return {"status": "ok", "current_bias": risk_calibration_bias}


@app.get("/analytics/calibration/summary")
async def get_calibration_summary(
    limit: int = Query(default=200, ge=10, le=1000),
    _: DashboardUser = Depends(verify_dashboard_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(RiskCalibrationFeedback)
        .order_by(RiskCalibrationFeedback.created_at.desc())
        .limit(limit)
        .all()
    )
    false_positive = 0
    false_negative = 0
    for row in rows:
        if row.expected_decision == "safe" and row.actual_decision == "blocked":
            false_positive += 1
        if row.expected_decision == "blocked" and row.actual_decision == "safe":
            false_negative += 1
    total = len(rows)
    return {
        "sample_size": total,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "bias": risk_calibration_bias,
        "recommended_action": (
            "tighten_rules"
            if false_negative > false_positive
            else "reduce_overblocking"
            if false_positive > false_negative
            else "stable"
        ),
        "recent_feedback": [
            {
                "session_id": item.session_id,
                "expected_decision": item.expected_decision,
                "actual_decision": item.actual_decision,
                "risk_score": item.risk_score,
                "recorded_by": item.recorded_by,
                "created_at": item.created_at,
            }
            for item in rows[:25]
        ],
    }


@app.post("/ops/logs/archive")
async def archive_old_logs(
    days: int = Query(default=30, ge=7, le=3650),
    user: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    archive_result = _archive_old_logs_internal(
        db,
        days=days,
        archived_by=user.username,
    )
    db.commit()
    metrics_store.increment("manual_archive_runs_total")
    return archive_result

@app.get("/ops/logs/archives")
async def list_log_archives(_: DashboardUser = Depends(verify_dashboard_user)):
    files = sorted(ARCHIVE_DIR.glob("archive-*.json"), reverse=True)
    return [
        {"name": item.name, "path": str(item), "size": item.stat().st_size, "modified_at": item.stat().st_mtime}
        for item in files[:100]
    ]


@app.get("/ops/api-keys")
async def list_api_keys(
    _: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    keys = db.query(RotatingApiKey).order_by(RotatingApiKey.created_at.desc()).all()
    return [
        {
            "id": item.id,
            "label": item.label,
            "active": item.active,
            "created_by": item.created_by,
            "created_at": item.created_at,
        }
        for item in keys
    ]


@app.post("/ops/api-keys/rotate")
async def rotate_api_key(
    payload: RotateApiKeyRequest,
    user: DashboardUser = Depends(require_admin),
    db: Session = Depends(get_db),
):
    raw_key = _rotate_api_key_internal(
        db,
        label=payload.label,
        created_by=user.username,
        deactivate_old_keys=payload.deactivate_old_keys,
    )
    db.commit()
    metrics_store.increment("api_key_rotation_total")
    return {"new_api_key": raw_key, "label": payload.label, "active": True}


@app.get("/ops/api-keys/rotation-policy")
async def get_rotation_policy(_: DashboardUser = Depends(verify_dashboard_user)):
    return {
        "auto_rotate_days": AUTO_ROTATE_API_KEYS_DAYS,
        "deactivate_old": AUTO_ROTATE_DEACTIVATE_OLD,
        "label": AUTO_ROTATE_LABEL,
        "export_path": AUTO_ROTATE_EXPORT_PATH or None,
    }


@app.post("/ops/backup/create")
async def create_backup(
    user: DashboardUser = Depends(require_admin),
):
    db_path = _sqlite_db_path()
    if not db_path or not db_path.exists():
        raise HTTPException(status_code=400, detail="Backup is currently supported for local SQLite deployments only.")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_file = BACKUP_DIR / f"aegismind-backup-{stamp}.sqlite"
    shutil.copy2(db_path, backup_file)
    metrics_store.increment("backup_create_total")
    return {
        "status": "ok",
        "backup_file": str(backup_file),
        "created_by": user.username,
        "size_bytes": backup_file.stat().st_size,
    }


@app.get("/ops/backups")
async def list_backups(_: DashboardUser = Depends(verify_dashboard_user)):
    files = sorted(BACKUP_DIR.glob("aegismind-backup-*.sqlite"), reverse=True)
    return [
        {"name": item.name, "path": str(item), "size": item.stat().st_size, "modified_at": item.stat().st_mtime}
        for item in files[:100]
    ]


@app.post("/ops/backup/restore")
async def restore_backup(
    payload: RestoreBackupRequest,
    user: DashboardUser = Depends(require_admin),
):
    db_path = _sqlite_db_path()
    if not db_path:
        raise HTTPException(status_code=400, detail="Restore is currently supported for local SQLite deployments only.")

    backup_name = Path(payload.backup_file).name
    backup_file = BACKUP_DIR / backup_name
    if not backup_file.exists():
        raise HTTPException(status_code=404, detail="Backup file not found.")

    if payload.dry_run:
        return {
            "status": "dry_run",
            "backup_file": str(backup_file),
            "target_database": str(db_path),
            "message": "Dry run only. Re-submit with dry_run=false to restore.",
        }

    engine.dispose()
    shutil.copy2(backup_file, db_path)
    metrics_store.increment("backup_restore_total")
    return {
        "status": "restored",
        "backup_file": str(backup_file),
        "target_database": str(db_path),
        "restored_by": user.username,
    }


@app.get("/ops/backup-checklist")
async def backup_checklist(_: DashboardUser = Depends(verify_dashboard_user)):
    return {
        "database_backup": [
            "Run daily logical backup (pg_dump or sqlite copy).",
            "Store encrypted backups in off-site storage.",
            "Test restore procedure weekly.",
        ],
        "config_backup": [
            "Version policy exports and threat intel snapshots.",
            "Backup dashboard user accounts and API key metadata.",
            "Document secret rotation dates and owners.",
        ],
        "disaster_recovery": [
            "Define RTO/RPO targets for the platform.",
            "Keep rollback runbook for recent deployments.",
            "Perform quarterly disaster recovery drill.",
        ],
    }


@app.get("/observability/slo")
async def observability_slo(_: DashboardUser = Depends(verify_dashboard_user)):
    total_http = sum(value for key, value in metrics_store._counts.items() if key.startswith("http_status_"))
    error_http = sum(
        value
        for key, value in metrics_store._counts.items()
        if key.startswith("http_status_5")
    )
    availability = round(((total_http - error_http) / total_http) * 100, 3) if total_http else 100.0

    latency_samples = []
    for values in metrics_store._latencies.values():
        latency_samples.extend(values)
    latency_samples.sort()
    p95_ms = round((latency_samples[max(0, int(len(latency_samples) * 0.95) - 1)] * 1000), 2) if latency_samples else 0.0

    return {
        "availability_percent": availability,
        "p95_latency_ms": p95_ms,
        "targets": {
            "availability_percent": SLO_TARGET_AVAILABILITY,
            "p95_latency_ms": SLO_TARGET_P95_MS,
        },
        "status": {
            "availability": "ok" if availability >= SLO_TARGET_AVAILABILITY else "breach",
            "latency": "ok" if p95_ms <= SLO_TARGET_P95_MS else "breach",
        },
    }


@app.websocket("/ws/security-stream")
async def security_stream(websocket: WebSocket):
    await stream_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await stream_manager.disconnect(websocket)

