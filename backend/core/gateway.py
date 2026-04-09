from .firewall import firewall
from .policy import policy_engine
from .behavioral import behavioral_engine
from .honeypot import honeypot_layer
from .healing import self_healing_engine
from .dlp import dlp_module

class SecureToolGateway:
    def __init__(self):
        pass

    def request_tool_execution(self, session_id: str, role: str, tool_name: str, args: dict) -> dict:
        """
        Coordinates all security checks before allowing a tool call.
        """
        # 0. Check if session is locked
        if self_healing_engine.is_session_locked(session_id):
            return {"allowed": False, "reason": "Session is in CRITICAL LOCKDOWN mode.", "status": "blocked"}

        # 1. Behavioral Check
        behavior_result = behavioral_engine.log_activity(session_id, tool_name)
        if behavior_result["is_blocked"]:
            self_healing_engine.execute_remediation("HIGH_RISK_BEHAVIOR", session_id, behavior_result)
            return {"allowed": False, "reason": "Suspicious behavior detected.", "status": "blocked"}

        # 2. Honeypot Check
        if honeypot_layer.is_honeypot_tool(tool_name):
            alert = honeypot_layer.trigger_alert(session_id, tool_name, "tool")
            self_healing_engine.execute_remediation("HONEYPOT_TRIGGERED", session_id, alert)
            return {"allowed": False, "reason": "Unauthorized access to restricted system asset.", "status": "blocked"}

        # 3. Policy Engine Check
        policy_result = policy_engine.validate_action(role, tool_name, behavior_result["risk_score"])
        if not policy_result["allowed"]:
            return {"allowed": False, "reason": policy_result["reason"], "status": "denied"}

        # 4. Sandbox Execution (Simulated)
        # In a real system, we'd run the tool in a Docker container here
        execution_result = f"Successfully executed {tool_name} with args {args}"
        
        # 5. Output DLP Check
        dlp_result = dlp_module.scrub(str(execution_result))
        
        return {
            "allowed": True,
            "status": "executed",
            "result": dlp_result["scrubbed_content"],
            "dlp_findings": dlp_result["findings"]
        }

# Singleton instance
secure_gateway = SecureToolGateway()
