from typing import Dict, Iterable, List, Optional, Set, Tuple


class PolicyEngine:
    def __init__(self):
        self.role_policies: Dict[str, Dict[str, object]] = {
            "researcher": {
                "allowed_tools": {"web_search", "calculator", "summarizer"},
                "blocked_tools": {"db_admin", "file_system", "network_config", "shell_exec", "db_read"},
                "max_risk_score": 0.35,
            },
            "support": {
                "allowed_tools": {"customer_lookup", "issue_tracker", "summarizer"},
                "blocked_tools": {"db_admin", "file_system", "network_config", "shell_exec", "db_read"},
                "max_risk_score": 0.45,
            },
            "admin": {
                "allowed_tools": {"web_search", "calculator", "summarizer", "customer_lookup", "issue_tracker", "db_read"},
                "blocked_tools": {"get_root_credentials", "access_shadow_db", "debug_bypass_auth"},
                "max_risk_score": 0.75,
            },
        }

        self.global_blocked_tools: Set[str] = {
            "get_root_credentials",
            "access_shadow_db",
            "debug_bypass_auth",
            "shell_exec",
            "file_system",
            "network_config",
        }

        # Unsafe tool chaining patterns to prevent high-risk lateral moves.
        self.unsafe_tool_chains: Set[Tuple[str, str]] = {
            ("web_search", "db_admin"),
            ("web_search", "db_read"),
            ("db_read", "db_admin"),
            ("customer_lookup", "db_admin"),
            ("issue_tracker", "db_admin"),
        }

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 0.8:
            return "critical"
        if score >= 0.6:
            return "high"
        if score >= 0.3:
            return "medium"
        return "low"

    def _chain_violation(self, recent_tools: Iterable[str], next_tool: str) -> Optional[str]:
        recent = list(recent_tools or [])
        if not recent:
            return None

        last_tool = recent[-1]
        if (last_tool, next_tool) in self.unsafe_tool_chains:
            return f"Unsafe tool chaining blocked: '{last_tool}' -> '{next_tool}'"
        return None

    def validate_action(
        self,
        role: str,
        tool_name: str,
        current_risk_score: float,
        recent_tools: Optional[List[str]] = None,
    ) -> dict:
        """
        Validate role permissions, risk limits, global deny rules, and chain safety.
        """
        if role not in self.role_policies:
            return {"allowed": False, "reason": f"Invalid role: {role}", "reason_code": "INVALID_ROLE"}

        risk_level = self._risk_level(current_risk_score)
        if risk_level in {"high", "critical"} and role != "admin":
            return {
                "allowed": False,
                "reason": f"Risk level '{risk_level}' requires admin approval",
                "reason_code": "HUMAN_APPROVAL_REQUIRED",
            }

        if tool_name in self.global_blocked_tools:
            return {
                "allowed": False,
                "reason": f"Tool '{tool_name}' is globally blocked by security policy",
                "reason_code": "GLOBAL_TOOL_BLOCK",
            }

        role_policy = self.role_policies[role]
        max_risk = float(role_policy["max_risk_score"])
        if current_risk_score > max_risk:
            return {
                "allowed": False,
                "reason": f"Risk score ({current_risk_score:.2f}) exceeds budget for role '{role}' ({max_risk:.2f})",
                "reason_code": "RISK_BUDGET_EXCEEDED",
            }

        blocked_tools = set(role_policy["blocked_tools"])
        if tool_name in blocked_tools:
            return {
                "allowed": False,
                "reason": f"Tool '{tool_name}' is denied for role '{role}'",
                "reason_code": "ROLE_TOOL_DENY",
            }

        allowed_tools = set(role_policy["allowed_tools"])
        if "*" not in allowed_tools and tool_name not in allowed_tools:
            return {
                "allowed": False,
                "reason": f"Tool '{tool_name}' not allow-listed for role '{role}'",
                "reason_code": "ROLE_TOOL_NOT_ALLOWED",
            }

        chain_reason = self._chain_violation(recent_tools or [], tool_name)
        if chain_reason:
            return {"allowed": False, "reason": chain_reason, "reason_code": "UNSAFE_TOOL_CHAIN"}

        return {
            "allowed": True,
            "reason": f"Policy check passed (risk level: {risk_level})",
            "reason_code": "ALLOW",
        }


policy_engine = PolicyEngine()
