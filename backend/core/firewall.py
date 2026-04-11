import base64
import re
from typing import Any, Dict, List


class PromptFirewall:
    def __init__(self):
        # Scoring-based rules: id, regex, human-readable reason, score contribution
        self.rulebook = [
            ("prompt_override", re.compile(r"(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior)\s+instructions\b"), "Prompt override attempt", 0.85),
            ("system_prompt_exfil", re.compile(r"(?i)\bsystem\s+prompt\b"), "System prompt exfiltration attempt", 0.85),
            ("hidden_instruction_exfil", re.compile(r"(?i)\breveal\s+hidden\b"), "Hidden instruction exfiltration attempt", 0.75),
            ("role_manipulation", re.compile(r"(?i)\b(as an?|act as|pretend to be|switch to|you are now(?: in)?|from now on you are)\s+(?:the\s+)?(admin|developer|root|system)\b"), "Role manipulation attempt", 0.85),
            ("policy_bypass", re.compile(r"(?i)\b(override|bypass|disable|ignore)\s+(policy(?:\s+engine)?|guardrails|security|firewall)\b"), "Policy bypass attempt", 0.80),
            ("secret_exfiltration", re.compile(r"(?i)\b(show|reveal|get|dump)\b.{0,30}\b(secret|secrets|credentials|keys|tokens)\b"), "Sensitive secret exfiltration attempt", 0.85),
            ("destructive_db", re.compile(r"(?i)\bdrop\s+(database|table)\b"), "Destructive database intent", 0.80),
            ("destructive_shell", re.compile(r"(?i)\brm\s+-rf\b|\bcat\s+/etc/passwd\b"), "Destructive shell payload", 1.0),
            ("encoded_instruction_execution", re.compile(r"(?i)\bdecode\b.*\bbase64\b|\bbase64\b.*\bdecode\b"), "Encoded instruction execution attempt", 0.80),
            ("indirect_injection", re.compile(r"(?i)\b(from|inside|in)\s+(website|pdf|email|api|attachment|document)\b.{0,80}\b(ignore|override|bypass|reveal)\b"), "Indirect prompt injection pattern", 0.70),
        ]

        self.base64_blob_pattern = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
        self.decoded_malicious_markers = [
            re.compile(r"(?i)\bignore\s+previous\s+instructions\b"),
            re.compile(r"(?i)\bsystem\s+prompt\b"),
            re.compile(r"(?i)\broot\s+credentials\b"),
            re.compile(r"(?i)\bdrop\s+table\b"),
            re.compile(r"(?i)\brm\s+-rf\b"),
            re.compile(r"(?i)\bbypass\s+security\b"),
        ]
        self.block_threshold = 0.70
        self.review_threshold = 0.45

    def _analyze_base64(self, prompt: str) -> Dict[str, Any]:
        findings: List[str] = []
        matched_rules: List[str] = []
        score = 0.0

        for candidate in self.base64_blob_pattern.findall(prompt):
            # Base64 data length must be a multiple of 4
            if len(candidate) % 4 != 0:
                continue
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            except Exception:
                continue

            for marker in self.decoded_malicious_markers:
                if marker.search(decoded):
                    findings.append("Malicious payload detected in Base64 content")
                    matched_rules.append("base64_decoded_malicious")
                    score += 0.85
                    return {"score": score, "findings": findings, "rules": matched_rules}

        return {"score": score, "findings": findings, "rules": matched_rules}

    def scan(self, prompt: str) -> dict:
        """
        Analyze prompt risk and return structured decision details.
        """
        normalized_prompt = (prompt or "").strip()
        threats_found: List[str] = []
        matched_rules: List[str] = []
        risk_score = 0.0

        for rule_id, pattern, reason, weight in self.rulebook:
            if pattern.search(normalized_prompt):
                matched_rules.append(rule_id)
                threats_found.append(reason)
                risk_score += weight

        # Long prompts increase uncertainty and abuse risk
        if len(normalized_prompt) > 4000:
            matched_rules.append("oversized_prompt")
            threats_found.append("Excessive prompt length")
            risk_score += 0.25

        b64_result = self._analyze_base64(normalized_prompt)
        risk_score += b64_result["score"]
        threats_found.extend(b64_result["findings"])
        matched_rules.extend(b64_result["rules"])

        risk_score = min(risk_score, 1.0)
        if risk_score >= self.block_threshold:
            decision = "block"
            status = "blocked"
        elif risk_score >= self.review_threshold:
            decision = "review"
            status = "review"
        else:
            decision = "allow"
            status = "safe"

        # Preserve stable response shape for existing callers while adding richer context
        return {
            "is_blocked": decision == "block",
            "status": status,
            "decision": decision,
            "risk_score": round(risk_score, 4),
            "threats": sorted(set(threats_found)),
            "matched_rules": sorted(set(matched_rules)),
        }


firewall = PromptFirewall()
