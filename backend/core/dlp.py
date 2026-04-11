import re
from typing import Dict, List

class DLPModule:
    def __init__(self):
        # Pattern map: name -> regex + severity
        self.patterns: Dict[str, Dict[str, object]] = {
            "OPENAI_KEY": {"regex": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "severity": "critical"},
            "AWS_ACCESS_KEY": {"regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "severity": "high"},
            "GENERIC_TOKEN": {"regex": re.compile(r"(?i)\b(?:api[_-]?key|token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"), "severity": "high"},
            "PASSWORD_ASSIGNMENT": {"regex": re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\";]{6,})['\"]?"), "severity": "critical"},
            "BEARER_TOKEN": {"regex": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*\b"), "severity": "high"},
            "PRIVATE_KEY_BLOCK": {"regex": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "severity": "critical"},
            "EMAIL": {"regex": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "severity": "low"},
            "PHONE": {"regex": re.compile(r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"), "severity": "low"},
            "CREDIT_CARD": {"regex": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"), "severity": "high"},
        }

    @staticmethod
    def _mask_segment(segment: str) -> str:
        if len(segment) <= 6:
            return "*" * len(segment)
        return f"{segment[:2]}{'*' * (len(segment) - 4)}{segment[-2:]}"

    def scrub(self, content: str) -> dict:
        """
        Scan content for sensitive information and mask detected values.
        """
        findings: List[Dict[str, str]] = []
        masked_content = content

        # Replace each match exactly once using re.sub callback to avoid overlapping mistakes.
        for name, cfg in self.patterns.items():
            regex = cfg["regex"]
            severity = cfg["severity"]

            def _repl(match):
                matched_text = match.group(0)
                findings.append({"type": name, "severity": severity})
                return self._mask_segment(matched_text)

            masked_content = regex.sub(_repl, masked_content)

        has_critical = any(item["severity"] == "critical" for item in findings)
        has_findings = len(findings) > 0

        return {
            "original_content": content,
            "scrubbed_content": masked_content,
            "findings": findings,
            "is_breached": has_findings,
            "should_block": has_critical,
        }


dlp_module = DLPModule()
