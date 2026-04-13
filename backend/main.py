import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .db.config import engine, get_db, Base
from .models.api import ExecuteRequest
from .models.schema import AuditLog, SecurityEvent, AgentIdentity
from .core.firewall import firewall
from .core.gateway import secure_gateway
from .core.healing import self_healing_engine
from .core.crypto import crypto_manager
from .core.rate_limit import rate_limiter
from .core.agent_reasoner import agent_reasoner

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


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
    agent_id: str
) -> None:
    db.add(
        AuditLog(
            session_id=session_id,
            agent_id=agent_id,
            action=action,
            status=status,
            # Data-at-Rest Protection
            input_text=crypto_manager.encrypt_text(input_text),
            output_text=crypto_manager.encrypt_text(output_text),
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
    # Encrypt prompt if present in details
    if "prompt" in details:
        details["prompt"] = crypto_manager.encrypt_text(details["prompt"])
        
    db.add(
        SecurityEvent(
            session_id=session_id,
            event_type=event_type,
            risk_score=risk_score,
            details=details,
        )
    )



# Removed _infer_tool: Now using AgentReasoner for LLM-driven inference.


def verify_agent(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_agent_id: Optional[str] = Header(default=None, alias="X-Agent-Id"),
    db: Session = Depends(get_db)
) -> AgentIdentity:
    # 1. Strong Authentication: Validate explicit agent ID mapping
    if x_api_key and x_agent_id:
        agent = db.query(AgentIdentity).filter(AgentIdentity.agent_id == x_agent_id, AgentIdentity.is_active == True).first()
        if agent and crypto_manager.hash_api_key(x_api_key) == agent.api_key_hash:
            return agent
            
    # 2. Legacy Fallback: Using raw SECURITY_API_KEY without Agent-ID (acts as root agent-001)
    required_key = os.getenv("SECURITY_API_KEY")
    if required_key and x_api_key == required_key:
        return AgentIdentity(agent_id="legacy-agent-001", role="researcher")
    
    raise HTTPException(status_code=401, detail="Invalid Agent credentials or unauthorized identity.")

def verify_agent_optional(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_agent_id: Optional[str] = Header(default=None, alias="X-Agent-Id"),
    db: Session = Depends(get_db)
) -> Optional[AgentIdentity]:
    if not x_api_key:
        return None
    return verify_agent(x_api_key=x_api_key, x_agent_id=x_agent_id, db=db)

@app.get("/")
async def root():
    return {"message": "AegisMind API is online"}

@app.post("/agent/execute")
async def execute_task(
    request: Request,
    payload: Optional[ExecuteRequest] = Body(default=None),
    prompt: Optional[str] = Query(default=None, max_length=4000),
    session_id: Optional[str] = Query(default=None, max_length=128),
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
            request_payload = ExecuteRequest(prompt=prompt, role=agent.role, session_id=session_id)
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
                output_text=f"Blocked: {', '.join(firewall_result['threats'])}",
                agent_id=agent.agent_id
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
        reasoning = {"tool_name": request_payload.requested_tool, "args": request_payload.tool_args, "thought": "Manually requested."}
        
        if not request_payload.requested_tool:
            reasoning = agent_reasoner.infer_tool(request_payload.prompt, agent.role)
            
        selected_tool = reasoning["tool_name"]
        tool_args = reasoning["args"] or {"query": request_payload.prompt}
        
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

        db.commit()
        return {"session_id": session_id, "firewall": firewall_result, "gateway": gateway_result}
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Database error during execution")
        raise HTTPException(status_code=500, detail="Database failure while processing request.") from exc

@app.get("/logs/security")
async def get_security_logs(db: Session = Depends(get_db), _: Optional[AgentIdentity] = Depends(verify_agent_optional)):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(50).all()
    # Security events might contain prompt snippets in details
    for event in events:
        if isinstance(event.details, dict) and "prompt" in event.details:
            try:
                event.details["prompt"] = crypto_manager.decrypt_text(event.details["prompt"])
            except Exception:
                pass
    return events

@app.get("/logs/audit")
async def get_audit_logs(db: Session = Depends(get_db), _: Optional[AgentIdentity] = Depends(verify_agent_optional)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
    for log in logs:
        try:
            log.input_text = crypto_manager.decrypt_text(log.input_text)
            log.output_text = crypto_manager.decrypt_text(log.output_text)
        except Exception:
            # Fallback for old unencrypted or malformed logs
            pass
    return logs

