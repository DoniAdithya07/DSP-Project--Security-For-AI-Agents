from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import uuid

from .db.config import engine, get_db, Base
from .models.schema import AuditLog, SecurityEvent
from .core.firewall import firewall
from .core.gateway import secure_gateway

# Initialize DB
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AegisMind Security Framework")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "AegisMind API is online"}

@app.post("/agent/execute")
async def execute_task(prompt: str, role: str = "researcher", db: Session = Depends(get_db)):
    session_id = str(uuid.uuid4())
    
    # 1. Prompt Firewall Scan
    firewall_result = firewall.scan(prompt)
    
    if firewall_result["is_blocked"]:
        # Log security event
        event = SecurityEvent(
            session_id=session_id,
            event_type="FIREWALL_BLOCK",
            risk_score=firewall_result["risk_score"],
            details={"prompt": prompt, "threats": firewall_result["threats"]}
        )
        db.add(event)
        db.commit()
        return {"status": "blocked", "reason": "Security violation detected in prompt.", "threats": firewall_result["threats"]}

    # 2. Simulated Agent Logic (LangChain-like loop)
    # For the demo, we simulate a tool decision
    suggested_tool = "web_search"
    if "root" in prompt.lower() or "credentials" in prompt.lower():
        suggested_tool = "get_root_credentials" # Honeypot trigger
    elif "db" in prompt.lower() or "table" in prompt.lower():
        suggested_tool = "db_admin" # Policy denial for researcher
        
    # 3. Secure Gateway Enforcement
    gateway_result = secure_gateway.request_tool_execution(
        session_id=session_id,
        role=role,
        tool_name=suggested_tool,
        args={"query": prompt}
    )
    
    # 4. Audit Logging
    audit = AuditLog(
        session_id=session_id,
        agent_id="agent-001",
        action=suggested_tool,
        status=gateway_result["status"],
        input_text=prompt,
        output_text=gateway_result.get("result", "N/A")
    )
    db.add(audit)
    
    if gateway_result["status"] == "blocked":
        event = SecurityEvent(
            session_id=session_id,
            event_type="GATEWAY_BLOCK",
            risk_score=1.0,
            details={"tool": suggested_tool, "reason": gateway_result["reason"]}
        )
        db.add(event)
        
    db.commit()
    
    return {
        "session_id": session_id,
        "firewall": firewall_result,
        "gateway": gateway_result
    }

@app.get("/logs/security")
async def get_security_logs(db: Session = Depends(get_db)):
    return db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(50).all()

@app.get("/logs/audit")
async def get_audit_logs(db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
