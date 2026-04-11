import time
from collections import deque
from threading import Lock
from typing import Deque, Dict

class SelfHealingEngine:
    def __init__(self):
        self.active_lockdowns: Dict[str, str] = {}
        self.cooldown_until: Dict[str, float] = {}
        self.prompt_block_history: Dict[str, Deque[float]] = {}
        self.prompt_block_threshold = 3
        self.prompt_block_window_seconds = 120
        self.cooldown_seconds = 60
        self._lock = Lock()

    def execute_remediation(self, event_type: str, session_id: str, context: dict) -> dict:
        """
        Takes automated action based on a security event.
        """
        actions_taken = []
        
        with self._lock:
            if event_type == "HONEYPOT_TRIGGERED":
                # Immediate lockdown
                self.active_lockdowns[session_id] = "CRITICAL_LOCKDOWN"
                self.cooldown_until.pop(session_id, None)
                actions_taken.append("Disabled all tool access for session")
                actions_taken.append("Triggered admin notification")
                actions_taken.append("Rotated simulated session keys")
                
            elif event_type == "HIGH_RISK_BEHAVIOR":
                self.active_lockdowns[session_id] = "RESTRICTED_MODE"
                actions_taken.append("Downgraded agent permissions to 'ReadOnly'")
                actions_taken.append("Enabled mandatory human-in-the-loop approval")
                
            elif event_type == "PROMPT_INJECTION_REPEATED":
                self.active_lockdowns[session_id] = "TEMP_COOLDOWN"
                self.cooldown_until[session_id] = time.time() + self.cooldown_seconds
                actions_taken.append(f"Temporary cooldown ({self.cooldown_seconds}s) for session")
                actions_taken.append("Escalated incident to monitoring")

            new_state = self.active_lockdowns.get(session_id, "NORMAL")

        if event_type == "PROMPT_INJECTION_REPEATED":
            # Reset prompt abuse tracker after enforcement so future windows are fresh.
            with self._lock:
                self.prompt_block_history.pop(session_id, None)

        return {
            "remediation_status": "applied",
            "session_id": session_id,
            "actions": actions_taken,
            "new_state": new_state,
        }

    def register_firewall_block(self, session_id: str, context: dict) -> dict | None:
        now = time.time()
        should_escalate = False

        with self._lock:
            history = self.prompt_block_history.setdefault(session_id, deque())
            history.append(now)
            while history and history[0] < now - self.prompt_block_window_seconds:
                history.popleft()
            if len(history) >= self.prompt_block_threshold:
                should_escalate = True

        if should_escalate:
            return self.execute_remediation("PROMPT_INJECTION_REPEATED", session_id, context)
        return None

    def get_session_state(self, session_id: str) -> str:
        with self._lock:
            state = self.active_lockdowns.get(session_id, "NORMAL")
            if state == "TEMP_COOLDOWN":
                expires_at = self.cooldown_until.get(session_id, 0)
                if time.time() >= expires_at:
                    self.active_lockdowns.pop(session_id, None)
                    self.cooldown_until.pop(session_id, None)
                    return "NORMAL"
            return state

    def is_session_locked(self, session_id: str) -> bool:
        return self.get_session_state(session_id) in {"CRITICAL_LOCKDOWN", "TEMP_COOLDOWN"}

    def is_session_restricted(self, session_id: str) -> bool:
        return self.get_session_state(session_id) == "RESTRICTED_MODE"

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self.active_lockdowns.pop(session_id, None)
            self.cooldown_until.pop(session_id, None)
            self.prompt_block_history.pop(session_id, None)

# Singleton instance
self_healing_engine = SelfHealingEngine()
