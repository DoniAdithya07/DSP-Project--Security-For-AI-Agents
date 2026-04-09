from enum import Enum
from typing import List, Dict

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PolicyEngine:
    def __init__(self):
        # Default policy mapping
        self.roles = {
            "researcher": {
                "allowed_tools": ["web_search", "calculator", "summarizer"],
                "max_risk_score": 0.4
            },
            "admin": {
                "allowed_tools": ["*"],
                "max_risk_score": 0.9
            },
            "support": {
                "allowed_tools": ["customer_lookup", "issue_tracker"],
                "max_risk_score": 0.5
            }
        }
        
        self.global_blocklist = ["rm -rf", "drop table", "shutdown"]

    def validate_action(self, role: str, tool_name: str, current_risk_score: float) -> dict:
        """
        Validates if an action is allowed based on role and current security state.
        """
        if role not in self.roles:
            return {"allowed": False, "reason": f"Invalid role: {role}"}
            
        role_policy = self.roles[role]
        
        # Check risk budget
        if current_risk_score > role_policy["max_risk_score"]:
            return {
                "allowed": False, 
                "reason": f"Risk score ({current_risk_score}) exceeds budget for {role} ({role_policy['max_risk_score']})"
            }

        # Check tool permissions
        allowed_tools = role_policy["allowed_tools"]
        if "*" not in allowed_tools and tool_name not in allowed_tools:
            return {"allowed": False, "reason": f"Tool '{tool_name}' not allowed for role '{role}'"}

        return {"allowed": True, "reason": "Policy check passed"}

# Singleton instance
policy_engine = PolicyEngine()
