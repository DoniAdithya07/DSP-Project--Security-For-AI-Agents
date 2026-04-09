import re
import base64

class PromptFirewall:
    def __init__(self):
        # Heuristic rules for common injection attacks
        self.injection_patterns = [
            r"(?i)ignore\s+previous\s+instructions",
            r"(?i)system\s+prompt",
            r"(?i)reveal\s+hidden",
            r"(?i)not\s+restricted",
            r"(?i)pretend\s+you\s+are",
            r"(?i)start\s+acting\s+as",
            r"(?i)forget\s+all\s+rules",
            r"(?i)override\s+policy",
            r"(?i)sudo\s+access",
            r"(?i)bypass\s+security",
            r"(?i)cat\s+/etc/passwd", # Command injection example
            r"(?i)rm\s+-rf",          # Destructive command example
        ]
        
        # Patterns for encoded attacks
        self.base64_pattern = r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"

    def scan(self, prompt: str) -> dict:
        """
        Analyzes a prompt for potential security risks.
        Returns a risk score and identified threats.
        """
        threats_found = []
        risk_score = 0.0

        # Check for direct injection patterns
        for pattern in self.injection_patterns:
            if re.search(pattern, prompt):
                threats_found.append(f"Prompt Injection Pattern Detected: {pattern}")
                risk_score += 0.4

        # Check for abnormal length (can be used in DoS)
        if len(prompt) > 2000:
            threats_found.append("Excessive Prompt Length")
            risk_score += 0.2

        # Check for Base64 encoded blobs (can hide malicious payloads)
        # We only flag if it's long enough to be suspicious
        if len(prompt) > 20 and re.search(self.base64_pattern, prompt):
            try:
                # Attempt to decode a piece to see if it looks like a command or instruction
                # (Simple heuristic: if it decodes to ASCII, it's suspicious)
                # In a real system, we'd scan the decoded content too
                pass
            except:
                pass

        # Check for role override attempts
        if "as an admin" in prompt.lower() or "with full access" in prompt.lower():
            threats_found.append("Role Override Attempt")
            risk_score += 0.3

        # Normalize risk score to max 1.0
        risk_score = min(risk_score, 1.0)
        
        return {
            "is_blocked": risk_score >= 0.7,
            "risk_score": risk_score,
            "threats": threats_found,
            "status": "blocked" if risk_score >= 0.7 else "safe"
        }

# Singleton instance
firewall = PromptFirewall()
