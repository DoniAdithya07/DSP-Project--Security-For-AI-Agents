import base64
import re
from typing import Any, Dict, List

from .ml_model import ml_engine
from .llm_evaluator import llm_evaluator

class PromptFirewall:
    def __init__(self):
        # Scoring-based rules: id, regex, human-readable reason, score contribution
        self.rulebook = [
            # Standard injection & prompt overrides
            ("prompt_override", re.compile(r"(?i)\b(ignore|disregard|forget|skip)\s+(all\s+)?(previous|prior|core|system)\s+(instructions|prompts|rules|guardrails|constraints)\b"), "Prompt override attempt", 0.90),
            ("system_prompt_exfil", re.compile(r"(?i)\b(system\s+prompt|core\s+instructions|initial\s+prompt)\b"), "System prompt exfiltration attempt", 0.85),
            ("hidden_instruction_exfil", re.compile(r"(?i)\b(reveal|show|print|output)\s+(hidden|internal|secret)\s+(instructions|data)\b"), "Hidden instruction exfiltration attempt", 0.75),
            
            # Jailbreak & Personas
            ("jailbreak_dan", re.compile(r"(?i)\b(DAN|do anything now|developer mode|unrestricted mode|god mode|always respond)\b"), "Jailbreak persona attempt (DAN/DevMode)", 1.0),
            ("role_manipulation", re.compile(r"(?i)\b(as an?|act as|pretend to be|switch to|you are now(?: in)?|from now on you are)\s+(?:the\s+)?(admin|developer|root|system|hacker)\b"), "Role manipulation attempt", 0.85),
            ("policy_bypass", re.compile(r"(?i)\b(override|bypass|disable|ignore|turn off)\s+(policy(?:\s+engine)?|guardrails|security|firewall|filters|censorship)\b"), "Policy bypass attempt", 0.90),
            
            # Data Mining & Exfiltration
            ("secret_exfiltration", re.compile(r"(?i)\b(show|reveal|get|dump|list)\b.{0,40}\b(secret|secrets|credentials|keys|tokens|passwords|api[_\s]?keys)\b"), "Sensitive secret exfiltration attempt", 0.90),
            ("pii_extraction", re.compile(r"(?i)\b(extract|dump|list)\b.{0,40}\b(emails|phone numbers|ssn|social security|credit cards|personal data)\b"), "PII bulk extraction attempt", 0.90),
            
            # Code Execution & OS attacks
            ("destructive_db", re.compile(r"(?i)\b(drop\s+(database|table)|delete\s+from|truncate\s+table)\b"), "Destructive database intent", 0.90),
            ("destructive_shell", re.compile(r"(?i)\b(rm\s+-rf|cat\s+/etc/(passwd|shadow)|mkfs|dd\s+if=)\b"), "Destructive shell payload", 1.0),
            ("command_injection", re.compile(r"(?i)\b(curl|wget|nc|netcat|nmap|ping)\s+[-a-z0-9]+\b|\b(import\s+(os|subprocess|pty))\b|\b(eval|exec)\s*\("), "System command/network intent", 1.0),
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
        Analyze prompt risk utilizing a 3-Tier cascade: Rule-Based -> ML -> LLM Reasoning.
        """
        normalized_prompt = (prompt or "").strip()
        threats_found: List[str] = []
        matched_rules: List[str] = []
        risk_score = 0.0

        # TIER 1: RULE-BASED ENGINE
        for rule_id, pattern, reason, weight in self.rulebook:
            if pattern.search(normalized_prompt):
                matched_rules.append(rule_id)
                threats_found.append(reason)
                risk_score += weight

        if len(normalized_prompt) > 4000:
            matched_rules.append("oversized_prompt")
            threats_found.append("Excessive prompt length")
            risk_score += 0.25

        fence_count = len(re.findall(r"(```|###|\-\-\-|\*\*\*)", normalized_prompt))
        if fence_count >= 3:
            matched_rules.append("excessive_fencing")
            threats_found.append("Unusual boundary/fence manipulation")
            risk_score += 0.30

        b64_result = self._analyze_base64(normalized_prompt)
        risk_score += b64_result["score"]
        threats_found.extend(b64_result["findings"])
        matched_rules.extend(b64_result["rules"])

        # Early short-circuit if regex clearly blocked it.
        risk_score = min(risk_score, 1.0)
        if risk_score >= self.block_threshold:
            return {
                "is_blocked": True,
                "status": "blocked",
                "decision": "block",
                "risk_score": round(risk_score, 4),
                "threats": sorted(set(threats_found)),
                "matched_rules": sorted(set(matched_rules)),
            }

        # TIER 2: ML CLASSIFICATION LAYER
        try:
            ml_risk = ml_engine.predict_risk(normalized_prompt)
            if ml_risk >= 0.70:
                matched_rules.append("ml_semantic_threat")
                threats_found.append(f"ML semantic adversarial intent (Confidence: {ml_risk:.2f})")
                risk_score += max(0.5, ml_risk)
            else:
                # Bump the base risk natively so gray areas trigger the LLM review threshold
                risk_score += ml_risk
        except Exception:
            pass

        # Check threshold again
        risk_score = min(risk_score, 1.0)
        if risk_score >= self.block_threshold:
            return {
                "is_blocked": True,
                "status": "blocked",
                "decision": "block",
                "risk_score": round(risk_score, 4),
                "threats": sorted(set(threats_found)),
                "matched_rules": sorted(set(matched_rules)),
            }

        # TIER 3: LLM REASONING LAYER
        # Evaluate "gray area" prompts that regex & ML suspect but don't strictly block
        if risk_score >= self.review_threshold:
            llm_result = llm_evaluator.evaluate(normalized_prompt)
            if llm_result["is_malicious"] and llm_result["confidence"] >= 0.60:
                matched_rules.append("llm_reasoning_threat")
                threats_found.append(f"LLM Cognitive Security failure: {llm_result['reason']} (Confidence: {llm_result['confidence']:.2f})")
                risk_score = 1.0

        # Final verdict
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

        return {
            "is_blocked": decision == "block",
            "status": status,
            "decision": decision,
            "risk_score": round(risk_score, 4),
            "threats": sorted(set(threats_found)),
            "matched_rules": sorted(set(matched_rules)),
        }

firewall = PromptFirewall()
