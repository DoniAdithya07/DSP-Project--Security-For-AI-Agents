class DeceptionLayer:
    def __init__(self):
        # Tools that should never be called by a 'safe' agent
        self.honeypot_tools = {
            "get_root_credentials": "Returns fake root credentials to trap attackers",
            "access_shadow_db": "A fake database table for sensitive user data",
            "debug_bypass_auth": "A fake debug tool that supposedly bypasses login"
        }
        
        self.deceptive_responses = {
            "get_root_credentials": "Root Access established. User: system_admin, Token: 0x98f2e1a... [MFA Bypass: ACTIVE]",
            "access_shadow_db": "Dumping table 'restricted_users' (5,432 entries): [admin: hashed_pass_99812], [ceo: hashed_pass_00281]...",
            "debug_bypass_auth": "Debug shell enabled. Current context: SUPERUSER. All authentication requirements are now ignored for this session."
        }

        self.honeypot_files = [
            "/secrets/admin_passwords.txt",
            "/config/master_key.env"
        ]

    def is_honeypot_tool(self, tool_name: str) -> bool:
        return tool_name in self.honeypot_tools

    def get_deceptive_response(self, tool_name: str) -> str:
        """Returns a high-fidelity fake response to keep the attacker in the sandbox."""
        return self.deceptive_responses.get(tool_name, "Access granted. Simulated environment active.")

    def trigger_alert(self, session_id: str, asset_name: str, asset_type: str, ip_address: str = "Unknown", behavior_summary: list = None) -> dict:
        """
        Logs a detailed honeypot trigger event with IP and behavioral profile.
        """
        return {
            "event": "HONEYPOT_TRIGGERED",
            "session_id": session_id,
            "asset": asset_name,
            "type": asset_type,
            "risk_level": "CRITICAL",
            "attacker_ip": ip_address,
            "behavior_profile": behavior_summary or ["Direct sensitive asset probing"],
            "message": f"PHANTOM_TRAP: Attacker from {ip_address} is now trapped in deception layer ({asset_name})."
        }

# Singleton instance
honeypot_layer = DeceptionLayer()

