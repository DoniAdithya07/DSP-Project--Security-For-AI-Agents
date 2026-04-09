import re

class DLPModule:
    def __init__(self):
        # Patterns for sensitive data
        self.pii_patterns = {
            "API_KEY": r"(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "PHONE": r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
            "CREDIT_CARD": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        }

    def scrub(self, content: str) -> dict:
        """
        Scans content for sensitive information and masks it.
        """
        masked_content = content
        findings = []
        
        for name, pattern in self.pii_patterns.items():
            matches = re.finditer(pattern, masked_content)
            for match in matches:
                findings.append(f"Sensitive Data Detected: {name}")
                # Mask the middle of the string
                found_str = match.group(0)
                if len(found_str) > 8:
                    masked_str = found_str[:4] + "*" * (len(found_str) - 8) + found_str[-4:]
                else:
                    masked_str = "********"
                
                # Careful with replacement to avoid overlapping or multiple replacements
                # Simplified for demo:
                masked_content = masked_content.replace(found_str, masked_str)

        return {
            "original_content": content,
            "scrubbed_content": masked_content,
            "findings": list(set(findings)),
            "is_breached": len(findings) > 0
        }

# Singleton instance
dlp_module = DLPModule()
