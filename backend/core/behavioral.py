import time
from collections import deque
from threading import Lock
from typing import Dict, List

class BehavioralThreatDetector:
    def __init__(self):
        # Tracking recent calls per session/agent
        # In a real app, this would be in Redis
        self.history: Dict[str, deque] = {}
        self._lock = Lock()
        self.call_threshold = 10  # Max calls in a window
        self.window_seconds = 60
        self.sensitive_tools = {"db_admin", "file_system", "network_config", "shell_exec", "db_read"}
        
    def log_activity(self, session_id: str, tool_name: str, status: str = "requested") -> dict:
        """
        Logs a tool call and checks for behavioral anomalies.
        """
        now = time.time()

        with self._lock:
            if session_id not in self.history:
                self.history[session_id] = deque()

            calls = self.history[session_id]
            calls.append({"time": now, "tool": tool_name, "status": status})

            # Cleanup old calls
            while calls and calls[0]["time"] < now - self.window_seconds:
                calls.popleft()

            recent_snapshot = list(calls)

        risk_score = 0.0
        threats: List[str] = []

        if len(recent_snapshot) > self.call_threshold:
            threats.append("Excessive tool invocation velocity")
            risk_score += min((len(recent_snapshot) - self.call_threshold) * 0.08, 0.5)

        recent_sensitive = [entry for entry in recent_snapshot if entry["tool"] in self.sensitive_tools]
        if len(recent_sensitive) >= 3:
            threats.append("Sensitive tool chaining detected")
            risk_score += 0.45

        recent_same_tool = [entry for entry in recent_snapshot if entry["tool"] == tool_name]
        if len(recent_same_tool) >= 5 and tool_name in self.sensitive_tools:
            threats.append("Repeated sensitive tool probing detected")
            risk_score += 0.35

        risk_score = min(risk_score, 1.0)
        return {
            "is_blocked": risk_score >= 0.8,
            "risk_score": round(risk_score, 4),
            "threats": threats,
            "status": "monitored",
            "recent_tools": [entry["tool"] for entry in recent_snapshot[-5:]],
        }

    def get_recent_tools(self, session_id: str, limit: int = 5) -> List[str]:
        with self._lock:
            entries = list(self.history.get(session_id, []))
        return [entry["tool"] for entry in entries[-limit:]]


behavioral_engine = BehavioralThreatDetector()
