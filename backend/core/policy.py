from typing import Dict, Iterable, List, Optional, Set, Tuple
from copy import deepcopy


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
        self.human_approval_risk_threshold = 0.45

    def export_policy(self) -> Dict[str, object]:
        serialized_roles: Dict[str, Dict[str, object]] = {}
        for role, conf in self.role_policies.items():
            serialized_roles[role] = {
                "allowed_tools": sorted(list(conf.get("allowed_tools", set()))),
                "blocked_tools": sorted(list(conf.get("blocked_tools", set()))),
                "max_risk_score": float(conf.get("max_risk_score", 0.5)),
            }
        return {
            "role_policies": serialized_roles,
            "global_blocked_tools": sorted(self.global_blocked_tools),
            "unsafe_tool_chains": [list(item) for item in sorted(self.unsafe_tool_chains)],
            "human_approval_risk_threshold": self.human_approval_risk_threshold,
        }

    def apply_policy(self, policy: Dict[str, object]) -> Dict[str, object]:
        role_policies = policy.get("role_policies")
        global_blocked = policy.get("global_blocked_tools")
        unsafe_chains = policy.get("unsafe_tool_chains")
        approval_threshold = policy.get("human_approval_risk_threshold", self.human_approval_risk_threshold)

        if not isinstance(role_policies, dict):
            raise ValueError("role_policies must be an object")

        normalized_roles: Dict[str, Dict[str, object]] = {}
        for role, conf in role_policies.items():
            if not isinstance(conf, dict):
                raise ValueError(f"Invalid role policy for '{role}'")
            normalized_roles[str(role)] = {
                "allowed_tools": set(conf.get("allowed_tools", [])),
                "blocked_tools": set(conf.get("blocked_tools", [])),
                "max_risk_score": float(conf.get("max_risk_score", 0.5)),
            }

        if not isinstance(global_blocked, list):
            raise ValueError("global_blocked_tools must be an array")
        normalized_global = {str(tool) for tool in global_blocked}

        if not isinstance(unsafe_chains, list):
            raise ValueError("unsafe_tool_chains must be an array")
        normalized_chains: Set[Tuple[str, str]] = set()
        for pair in unsafe_chains:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise ValueError("Each unsafe_tool_chains entry must contain exactly two tools")
            normalized_chains.add((str(pair[0]), str(pair[1])))

        self.role_policies = normalized_roles
        self.global_blocked_tools = normalized_global
        self.unsafe_tool_chains = normalized_chains
        self.human_approval_risk_threshold = float(approval_threshold)
        return self.export_policy()

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

        if tool_name in self.global_blocked_tools:
            return {
                "allowed": False,
                "reason": f"Tool '{tool_name}' is globally blocked by security policy",
                "reason_code": "GLOBAL_TOOL_BLOCK",
            }

        role_policy = self.role_policies[role]
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

        risk_level = self._risk_level(current_risk_score)
        if current_risk_score >= self.human_approval_risk_threshold and role != "admin":
            return {
                "allowed": False,
                "reason": f"Risk level '{risk_level}' requires admin approval",
                "reason_code": "HUMAN_APPROVAL_REQUIRED",
            }

        max_risk = float(role_policy["max_risk_score"])
        if current_risk_score > max_risk:
            return {
                "allowed": False,
                "reason": f"Risk score ({current_risk_score:.2f}) exceeds budget for role '{role}' ({max_risk:.2f})",
                "reason_code": "RISK_BUDGET_EXCEEDED",
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
