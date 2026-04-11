import ast
import operator
import re
from typing import Any, Callable, Dict

from .policy import policy_engine
from .behavioral import behavioral_engine
from .honeypot import honeypot_layer
from .healing import self_healing_engine
from .dlp import dlp_module

class SecureToolGateway:
    def __init__(self):
        self.allowed_tools = {
            "web_search": self._tool_web_search,
            "calculator": self._tool_calculator,
            "summarizer": self._tool_summarizer,
            "customer_lookup": self._tool_customer_lookup,
            "issue_tracker": self._tool_issue_tracker,
            "db_read": self._tool_db_read,
        }
        self._tool_name_pattern = re.compile(r"^[a-z_]{2,40}$")
        self._arg_key_pattern = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,40}$")
        self._safe_math_ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Pow: operator.pow,
            ast.USub: operator.neg,
        }

    def _validate_tool_name(self, tool_name: str) -> bool:
        return bool(self._tool_name_pattern.match(tool_name))

    def _validate_args(self, args: Dict[str, Any]) -> tuple[bool, str]:
        if not isinstance(args, dict):
            return False, "Tool arguments must be a JSON object."
        if len(args) > 10:
            return False, "Too many tool arguments."

        for key, value in args.items():
            if not isinstance(key, str) or not self._arg_key_pattern.match(key):
                return False, f"Invalid argument key: '{key}'"
            if isinstance(value, str) and len(value) > 2000:
                return False, f"Argument '{key}' exceeds maximum length."
            if not isinstance(value, (str, int, float, bool, dict, list, type(None))):
                return False, f"Argument '{key}' has unsupported type."
        return True, "ok"

    def _safe_eval_math(self, expression: str) -> float:
        def _eval(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            if isinstance(node, ast.Num):
                return node.n
            if isinstance(node, ast.BinOp) and type(node.op) in self._safe_math_ops:
                return self._safe_math_ops[type(node.op)](_eval(node.left), _eval(node.right))
            if isinstance(node, ast.UnaryOp) and type(node.op) in self._safe_math_ops:
                return self._safe_math_ops[type(node.op)](_eval(node.operand))
            raise ValueError("Unsafe expression")

        parsed = ast.parse(expression, mode="eval")
        return float(_eval(parsed.body))

    def _tool_web_search(self, args: Dict[str, Any]) -> str:
        query = str(args.get("query", "")).strip()
        if not query:
            raise ValueError("Missing required argument: query")
        return f"Web search completed for query: {query}"

    def _tool_calculator(self, args: Dict[str, Any]) -> str:
        expression = str(args.get("expression", "")).strip()
        if not expression:
            raise ValueError("Missing required argument: expression")
        if len(expression) > 120:
            raise ValueError("Expression too long")
        if not re.match(r"^[0-9\.\+\-\*/\(\)\s\^]+$", expression):
            raise ValueError("Expression contains forbidden characters")
        expression = expression.replace("^", "**")
        result = self._safe_eval_math(expression)
        return f"Calculator result: {result}"

    def _tool_summarizer(self, args: Dict[str, Any]) -> str:
        text = str(args.get("text", args.get("query", ""))).strip()
        if not text:
            raise ValueError("Missing required argument: text")
        sentence = text.split(".")[0][:220].strip()
        return f"Summary: {sentence}" if sentence else "Summary: (empty)"

    def _tool_customer_lookup(self, args: Dict[str, Any]) -> str:
        customer_id = str(args.get("customer_id", "")).strip()
        if not re.match(r"^[A-Za-z0-9\-]{3,32}$", customer_id):
            raise ValueError("Invalid customer_id")
        return f"Customer record for {customer_id}: access approved (simulated)."

    def _tool_issue_tracker(self, args: Dict[str, Any]) -> str:
        issue_id = str(args.get("issue_id", "")).strip()
        if not re.match(r"^[A-Za-z0-9\-]{3,32}$", issue_id):
            raise ValueError("Invalid issue_id")
        return f"Issue {issue_id} status: OPEN (simulated)."

    def _tool_db_read(self, args: Dict[str, Any]) -> str:
        table = str(args.get("table", "")).strip().lower()
        if not re.match(r"^[a-z_]{2,32}$", table):
            raise ValueError("Invalid table name")
        return f"Read-only query on table '{table}' completed (simulated)."

    def request_tool_execution(self, session_id: str, role: str, tool_name: str, args: dict, ip_address: str = "Unknown") -> dict:
        """
        Coordinates all security checks before allowing a tool call.
        """
        # 0. Check if session is locked
        if self_healing_engine.is_session_locked(session_id):
            return {
                "allowed": False,
                "reason": f"Session is in {self_healing_engine.get_session_state(session_id)} mode.",
                "status": "blocked",
            }

        if self_healing_engine.is_session_restricted(session_id):
            read_only_tools = {"web_search", "summarizer", "calculator"}
            if tool_name not in read_only_tools:
                return {
                    "allowed": False,
                    "reason": "Session is in RESTRICTED_MODE; only read-only tools are allowed.",
                    "status": "blocked",
                }

        # Validate requested tool and arguments before any execution.
        if not self._validate_tool_name(tool_name):
            return {"allowed": False, "reason": "Invalid tool name format.", "status": "blocked"}
        if tool_name not in self.allowed_tools and not honeypot_layer.is_honeypot_tool(tool_name):
            return {"allowed": False, "reason": f"Unknown tool '{tool_name}' requested.", "status": "blocked"}
        args_ok, args_reason = self._validate_args(args)
        if not args_ok:
            return {"allowed": False, "reason": args_reason, "status": "blocked"}

        # 1. Behavioral Check
        behavior_result = behavioral_engine.log_activity(session_id, tool_name, status="requested")
        if behavior_result["is_blocked"]:
            remediation = self_healing_engine.execute_remediation("HIGH_RISK_BEHAVIOR", session_id, behavior_result)
            return {
                "allowed": False,
                "reason": "Suspicious behavior detected.",
                "status": "blocked",
                "remediation": remediation,
            }

        # 2. Honeypot Check (GHOST DECEPTION)
        if honeypot_layer.is_honeypot_tool(tool_name):
            # Capture behavioral profile for the alert
            profile = behavior_result.get("threats", [])
            if not profile:
                profile = ["Direct sensitive asset probing"]
            
            alert = honeypot_layer.trigger_alert(session_id, tool_name, "tool", ip_address=ip_address, behavior_summary=profile)
            # Subtle remediation: Put them in a restricted sandbox instead of a hard block
            remediation = self_healing_engine.execute_remediation("HONEYPOT_TRIGGERED", session_id, alert)
            
            # GHOST RESPONSE: Return as 'executed' but with fake data
            return {
                "allowed": True,
                "status": "executed", # Keep them thinking it worked!
                "result": honeypot_layer.get_deceptive_response(tool_name),
                "is_deception": True,
                "remediation": remediation,
            }

        # 3. Policy Engine Check
        recent_tools = behavioral_engine.get_recent_tools(session_id, limit=5)
        policy_result = policy_engine.validate_action(role, tool_name, behavior_result["risk_score"], recent_tools=recent_tools)
        if not policy_result["allowed"]:
            return {"allowed": False, "reason": policy_result["reason"], "status": "blocked"}

        # 4. Sandboxed tool execution via allow-listed handlers only.
        try:
            execution_result = self.allowed_tools[tool_name](args)
        except Exception as exc:
            return {"allowed": False, "reason": f"Tool execution validation failed: {exc}", "status": "blocked"}

        # 5. Output DLP Check
        dlp_result = dlp_module.scrub(str(execution_result))
        if dlp_result["should_block"]:
            return {
                "allowed": False,
                "status": "blocked",
                "reason": "DLP blocked sensitive output.",
                "dlp_findings": dlp_result["findings"],
            }

        status = "modified" if dlp_result["is_breached"] else "executed"
        return {
            "allowed": True,
            "status": status,
            "result": dlp_result["scrubbed_content"],
            "dlp_findings": dlp_result["findings"],
            "policy": {"reason": policy_result["reason"], "reason_code": policy_result["reason_code"]},
            "behavior": {"risk_score": behavior_result["risk_score"], "threats": behavior_result["threats"]},
        }


secure_gateway = SecureToolGateway()
