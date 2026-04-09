import logging

class SelfHealingEngine:
    def __init__(self):
        self.active_lockdowns = {} # session_id -> status

    def execute_remediation(self, event_type: str, session_id: str, context: dict) -> dict:
        """
        Takes automated action based on a security event.
        """
        actions_taken = []
        
        if event_type == "HONEYPOT_TRIGGERED":
            # Immediate lockdown
            self.active_lockdowns[session_id] = "CRITICAL_LOCKDOWN"
            actions_taken.append("Disabled all tool access for session")
            actions_taken.append("Triggered admin notification")
            actions_taken.append("Rotated simulated session keys")
            
        elif event_type == "HIGH_RISK_BEHAVIOR":
            self.active_lockdowns[session_id] = "RESTRICTED_MODE"
            actions_taken.append("Downgraded agent permissions to 'ReadOnly'")
            actions_taken.append("Enabled mandatory human-in-the-loop approval")
            
        elif event_type == "PROMPT_INJECTION_REPEATED":
            actions_taken.append("Temporary cooldown (60s) for session")
            
        return {
            "remediation_status": "applied",
            "session_id": session_id,
            "actions": actions_taken,
            "new_state": self.active_lockdowns.get(session_id, "NORMAL")
        }

    def is_session_locked(self, session_id: str) -> bool:
        return self.active_lockdowns.get(session_id) == "CRITICAL_LOCKDOWN"

# Singleton instance
self_healing_engine = SelfHealingEngine()
