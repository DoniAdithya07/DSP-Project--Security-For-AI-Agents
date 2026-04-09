import time
from collections import deque

class BehavioralThreatDetector:
    def __init__(self):
        # Tracking recent calls per session/agent
        # In a real app, this would be in Redis
        self.history = {}
        self.call_threshold = 10  # Max calls in a window
        self.window_seconds = 60
        
    def log_activity(self, session_id: str, tool_name: str) -> dict:
        """
        Logs a tool call and checks for behavioral anomalies.
        """
        now = time.time()
        
        if session_id not in self.history:
            self.history[session_id] = deque()
            
        calls = self.history[session_id]
        calls.append({"time": now, "tool": tool_name})
        
        # Cleanup old calls
        while calls and calls[0]["time"] < now - self.window_seconds:
            calls.popleft()
            
        risk_score = 0.0
        threats = []
        
        # Check Frequency
        if len(calls) > self.call_threshold:
            threats.append("Excessive API/Tool Invocation (Velocity Attack)")
            risk_score += (len(calls) - self.call_threshold) * 0.1
            
        # Check for repeated failures (simulated)
        # In a real system, we'd pass 'status' to this log_activity
        
        # Check for sensitive tool sequences
        sensitive_tools = ["db_admin", "file_system", "network_config"]
        recent_sensitive = [c for c in calls if c["tool"] in sensitive_tools]
        if len(recent_sensitive) > 3:
            threats.append("Sensitive Tool Chaining Detected")
            risk_score += 0.5
            
        risk_score = min(risk_score, 1.0)
        
        return {
            "is_blocked": risk_score >= 0.8,
            "risk_score": risk_score,
            "threats": threats,
            "status": "monitored"
        }

# Singleton instance
behavioral_engine = BehavioralThreatDetector()
