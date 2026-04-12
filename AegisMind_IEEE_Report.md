# AegisMind: A Defense-in-Depth Security Framework for Agentic AI Workflows

**Course:** Data Security and Privacy (DS-208)  
**Professor:** Dr Girish Revadigar  
**Team Members:**  
- A. Doni Adithya (23bds007)  
- E. Hari Teja (23bds019)  
- Hari Prasad L. (23bds022)  
- L. Sahith Akash Manikanta (23bds031)

---

## Abstract
Agentic AI systems increasingly combine natural language reasoning with external tool execution, database access, and multi-step action planning. This capability improves automation but also expands the attack surface to include prompt injection, role manipulation, unsafe tool chaining, data exfiltration, and denial-of-wallet style abuse. This project presents **AegisMind**, a FastAPI-based security framework that applies a defense-in-depth architecture before any agent action is executed. The framework combines (i) a three-tier prompt firewall (rule-based, machine learning, and LLM-assisted reasoning), (ii) role-based policy and risk-budget enforcement, (iii) a secure tool gateway with strict allow-listing and argument validation, (iv) data leakage prevention with masking/blocking, (v) behavioral anomaly detection with adaptive self-healing responses, and (vi) comprehensive audit and security event logging with encryption at rest. A web dashboard provides operational visibility through threat metrics and live logs. Experimental validation through automated tests and targeted adversarial prompts demonstrates practical blocking of injection-style and encoded attacks while preserving safe interactions. The report details architecture, implementation, evaluation, and limitations, and outlines a roadmap for production-hardening.

**Keywords:** Agentic AI security, prompt injection defense, policy engine, data leakage prevention, honeypot deception, adaptive remediation, secure tool execution.

---

## I. Introduction
Large Language Models (LLMs) are rapidly moving from passive chat interfaces to **agentic systems** that can call APIs, query data stores, and execute workflows. This transition introduces high-impact security and privacy risks. Traditional perimeter security is insufficient because adversarial instructions may be embedded directly inside user prompts or secondary data sources (documents, web pages, encoded text). In addition, unsafe tool usage can escalate privileges or expose secrets.

The AegisMind project addresses this gap by implementing a layered, runtime security architecture that governs an agent request from input validation to output sanitization. Instead of relying on a single classifier or static deny-list, AegisMind combines multiple detection and control layers with explicit auditability.

The project was developed as part of **DS-208 (Data Security and Privacy)** and focuses on practical controls that can be demonstrated, tested, and iteratively hardened.

---

## II. Problem Definition and Threat Model

### A. Problem Statement
Given a user prompt and optional tool request, determine whether the action should be allowed, modified, reviewed, or blocked, while protecting system integrity, confidentiality, and operational availability.

### B. Security Objectives
1. Prevent prompt-level attacks (injection, role override, policy bypass).  
2. Restrict tool execution by role, risk score, and chaining behavior.  
3. Block or redact sensitive output data before response delivery.  
4. Maintain forensic-quality logs and explainable decisions.  
5. Adaptively respond to repeated or high-confidence malicious behavior.

### C. Adversary Model
The framework assumes adversaries may:
- Issue direct malicious prompts.
- Use indirect/encoded instructions (e.g., Base64).
- Attempt identity spoofing or privilege escalation.
- Probe restricted tools repeatedly.
- Trigger high-rate calls to degrade availability.

The framework does **not** assume trusted prompt content, and therefore performs explicit, staged verification.

---

## III. System Architecture

### A. High-Level Pipeline
1. Client request enters `/agent/execute`.  
2. Identity and API key validation are applied.  
3. Rate limiting is checked per agent identity.  
4. Prompt firewall computes risk and decision (`safe`, `review`, `blocked`).  
5. For non-blocked flows, tool selection/inference is performed.  
6. Secure gateway enforces policy, behavior, and honeypot/deception checks.  
7. Tool output passes through DLP masking/blocking.  
8. Final response and security metadata are logged.

### B. Core Components
- **Prompt Firewall:** Rule + ML + LLM multi-tier analysis.  
- **Policy Engine:** Role-based authorization and risk budgeting.  
- **Secure Tool Gateway:** Allow-list execution only, with strict argument validation.  
- **DLP Module:** Sensitive content detection and masking/blocking.  
- **Behavioral Detector:** Session-level anomaly scoring.  
- **Self-Healing Engine:** Automatic containment modes.  
- **Honeypot Layer:** Deception for sensitive probing.  
- **Rate Limiter:** Abuse control using Redis with fallback.

---

## IV. Implementation Details

### A. Backend Service
The backend is implemented with FastAPI and SQLAlchemy. Key endpoints:
- `POST /agent/execute`
- `GET /logs/security`
- `GET /logs/audit`

Authentication supports:
- `X-API-Key` + `X-Agent-Id` mapped to stored identity hashes.
- Optional legacy mode via `SECURITY_API_KEY`.

On first startup, an initial admin identity is created if none exists.

### B. Prompt Firewall Design
The firewall performs staged analysis:
1. **Rule-Based Layer**: regex patterns for jailbreak, role manipulation, secret exfiltration, destructive commands, and encoded-instruction intent.
2. **ML Layer**: semantic adversarial scoring using TF-IDF + Logistic Regression.
3. **LLM Layer**: cognitive reasoning for gray-zone prompts.

Decision thresholds in current implementation:
- Review threshold: `0.30`
- Block threshold: `0.60`

The final risk score is normalized and returned with matched rule identifiers for explainability.

### C. Policy and Authorization
The policy engine enforces:
- Role-specific allow/deny tool sets.
- Per-role maximum risk budgets.
- Global blocked tool list.
- Unsafe chain detection across recent tool calls.

Current role risk budgets:
- `researcher`: `0.35`
- `support`: `0.45`
- `admin`: `0.75`

### D. Secure Tool Gateway
The gateway:
- Validates tool names and argument keys/types.
- Uses allow-listed handlers only (`web_search`, `calculator`, `summarizer`, `customer_lookup`, `issue_tracker`, `db_read`).
- Applies behavioral checks before execution.
- Calls policy engine before tool execution.
- Applies output DLP scrub before returning result.

No arbitrary shell execution pathway is exposed in tool handlers.

### E. Data Leakage Prevention
The DLP module scans tool output for:
- API keys/tokens/password assignments
- bearer tokens
- private key blocks
- emails/phone numbers/credit card patterns

If findings are low/high severity, output is masked and status may become `modified`.  
If critical leakage is detected, output is blocked.

### F. Behavioral Detection and Adaptive Self-Healing
Behavioral controls track per-session tool usage and apply risk increments for:
- Excessive invocation velocity
- Sensitive tool chaining
- Repeated sensitive probing

Adaptive remediation states:
- `TEMP_COOLDOWN`
- `RESTRICTED_MODE`
- `CRITICAL_LOCKDOWN`

Repeated firewall blocks can trigger automated cooldown and escalation.

### G. Honeypot Deception
Access attempts to prohibited high-value tools trigger deception responses and monitoring events. This supports adversary observation while reducing direct exposure risk.

### H. Encryption and Storage
Database entities:
- `agent_identities`
- `security_events`
- `audit_logs`

Prompt and output fields are encrypted using Fernet.  
API keys are stored as SHA-256 hashes.  
If `ENCRYPTION_KEY` is not configured, an ephemeral key is generated at runtime.

---

## V. Frontend Monitoring Dashboard
The React dashboard provides:
- Security playground for prompt execution.
- Master key entry and session persistence.
- Threat metrics and risk timeline charts.
- Live security alerts.
- Audit log table with action/status/output summaries.

It is designed for operator visibility and demo-driven verification of controls.

---

## VI. Deployment and Operations

### A. Containerized Deployment
`docker-compose.yml` orchestrates:
- PostgreSQL database
- Backend API
- Redis
- Frontend (Vite dev server)

Default service URLs:
- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

### B. Runtime Configuration
Important environment variables:
- `SECURITY_API_KEY`
- `CORS_ALLOW_ORIGINS`
- `ENCRYPTION_KEY`
- `LLM_PROVIDER`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `GEMINI_API_KEY`
- `REDIS_HOST`, `REDIS_PORT`

---

## VII. Experimental Evaluation

### A. Test Methodology
Evaluation used:
1. Automated backend tests (`pytest`) for core security behavior.
2. Adversarial prompt demonstrations from the dashboard.
3. Inspection of audit/security logs for decision traceability.

### B. Attack Scenarios Demonstrated
- Prompt injection attempts
- Role manipulation prompts
- Base64 decode-and-execute intent
- Unauthorized tool usage
- DLP-triggering secret-like outputs
- Rate-limit enforcement behavior

### C. Current Test Snapshot
In the latest observed run:
- Total tests: `16`
- Passed: `13`
- Failed: `3`

Failure causes were primarily test-harness level (authentication expectation and rate-limit state interactions), not a complete failure of detection layers. This indicates a need for improved test isolation and deterministic reset procedures.

### D. Qualitative Outcomes
AegisMind consistently produced structured block responses for high-risk prompts and provided actionable reasons in logs. Safe prompts proceeded through the normal execution path with auditable outcomes.

---

## VIII. Discussion
The project demonstrates that combining orthogonal defenses yields better practical resilience than single-point filtering. Rule-based checks provide fast deterministic coverage, ML contributes semantic sensitivity, and LLM-based evaluation improves handling of ambiguous intent. Policy and gateway controls reduce blast radius even when model inference is imperfect.

The architecture also supports operational security through explainable events and adaptive response states, which are crucial in real-world SOC workflows.

---

## IX. Limitations
1. LLM-based evaluation depends on provider availability/latency.  
2. Regex and synthetic ML training data may miss novel attack patterns.  
3. Ephemeral encryption keys reduce post-restart decryptability without key management.  
4. Current frontend has additional tabs that can be expanded for full operator workflows.  
5. Test suite requires better state reset for rate-limiting and identity assumptions.

---

## X. Future Work
1. Integrate managed key vault/KMS for production-grade key lifecycle.  
2. Add SIEM/webhook connectors for enterprise monitoring integration.  
3. Expand adversarial corpus and benchmark framework robustness.  
4. Add model confidence calibration and policy-driven human approvals.  
5. Improve chaos/security testing under high concurrency and mixed benign/adversarial loads.

---

## XI. Conclusion
AegisMind provides a practical defense-in-depth security framework for agentic AI execution pipelines. By combining multi-tier prompt analysis, strict policy enforcement, secure tool mediation, DLP, adaptive remediation, and encrypted observability, the system significantly improves robustness against common AI-agent attack vectors while preserving usability for legitimate tasks. The project fulfills DS-208 goals by translating core data security and privacy principles into a functioning, testable architecture.

---

## Acknowledgment
This project was completed for **Data Security and Privacy (DS-208)** under the guidance of **Dr Girish Revadigar**.

---

## References
[1] FastAPI Documentation. [Online]. Available: https://fastapi.tiangolo.com/  
[2] SQLAlchemy Documentation. [Online]. Available: https://docs.sqlalchemy.org/  
[3] Redis Documentation. [Online]. Available: https://redis.io/docs/  
[4] Docker Documentation. [Online]. Available: https://docs.docker.com/  
[5] Scikit-learn Documentation. [Online]. Available: https://scikit-learn.org/stable/  
[6] Pydantic Documentation. [Online]. Available: https://docs.pydantic.dev/  
[7] Cryptography (Fernet) Documentation. [Online]. Available: https://cryptography.io/  
[8] OWASP Top 10 for LLM Applications Project. [Online]. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/
