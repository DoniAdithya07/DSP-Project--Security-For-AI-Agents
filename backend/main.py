import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .db.config import engine, get_db, Base
from .models.api import ExecuteRequest
from .models.schema import AuditLog, SecurityEvent
from .core.firewall import firewall
from .core.gateway import secure_gateway
from .core.healing import self_healing_engine

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized")
    yield


app = FastAPI(title="AegisMind Security Framework", lifespan=lifespan)
cors_origins = [origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _create_audit_log(
    db: Session,
    *,
    session_id: str,
    action: str,
    status: str,
    input_text: str,
    output_text: str,
    agent_id: str = "agent-001",
) -> None:
    db.add(
        AuditLog(
            session_id=session_id,
            agent_id=agent_id,
            action=action,
            status=status,
            input_text=input_text,
            output_text=output_text,
        )
    )


def _create_security_event(
    db: Session,
    *,
    session_id: str,
    event_type: str,
    risk_score: float,
    details: Dict[str, Any],
) -> None:
    db.add(
        SecurityEvent(
            session_id=session_id,
            event_type=event_type,
            risk_score=risk_score,
            details=details,
        )
    )


def _infer_tool(prompt: str) -> str:
    lowered = prompt.lower()
    if "calculate" in lowered or "math" in lowered:
        return "calculator"
    if "customer" in lowered and "lookup" in lowered:
        return "customer_lookup"
    if "issue" in lowered and "ticket" in lowered:
        return "issue_tracker"
    if "summarize" in lowered or "summary" in lowered:
        return "summarizer"
    if "db" in lowered and "read" in lowered:
        return "db_read"
    if "root" in lowered or "credentials" in lowered:
        return "get_root_credentials"
    if "db" in lowered or "table" in lowered:
        return "db_admin"
    return "web_search"


def verify_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> None:
    required_key = os.getenv("SECURITY_API_KEY")
    if not required_key:
        return
    if x_api_key != required_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


@app.get("/")
async def root():
    return {"message": "AegisMind API is online"}

@app.post("/agent/execute")
async def execute_task(
    payload: Optional[ExecuteRequest] = Body(default=None),
    prompt: Optional[str] = Query(default=None, max_length=4000),
    role: str = Query(default="researcher"),
    session_id: Optional[str] = Query(default=None, max_length=128),
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    request_payload = payload
    if request_payload is None:
        if prompt is None:
            raise HTTPException(status_code=422, detail="Provide request body or query prompt.")
        try:
            request_payload = ExecuteRequest(prompt=prompt, role=role, session_id=session_id)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    session_id = request_payload.session_id or str(uuid.uuid4())

    try:
        # 1. Prompt Firewall Scan
        firewall_result = firewall.scan(request_payload.prompt)
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
                output_text="Security violation detected in prompt.",
            )
            db.commit()
            return {
                "session_id": session_id,
                "firewall": firewall_result,
                "gateway": {
                    "allowed": False,
                    "status": "blocked",
                    "reason": "Security violation detected in prompt.",
                    "remediation": remediation,
                },
            }

        # 2. Tool selection and secure gateway evaluation
        selected_tool = request_payload.requested_tool or _infer_tool(request_payload.prompt)
        tool_args = request_payload.tool_args or {"query": request_payload.prompt}
        gateway_result = secure_gateway.request_tool_execution(
            session_id=session_id,
            role=request_payload.role,
            tool_name=selected_tool,
            args=tool_args,
        )

        # 3. Audit logs for all outcomes
        _create_audit_log(
            db,
            session_id=session_id,
            action=selected_tool,
            status=gateway_result["status"],
            input_text=request_payload.prompt,
            output_text=gateway_result.get("result") or gateway_result.get("reason", "N/A"),
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

        db.commit()
        return {"session_id": session_id, "firewall": firewall_result, "gateway": gateway_result}
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Database error during execution")
        raise HTTPException(status_code=500, detail="Database failure while processing request.") from exc

@app.get("/logs/security")
async def get_security_logs(db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    return db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(50).all()

@app.get("/logs/audit")
async def get_audit_logs(db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
