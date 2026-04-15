# AegisMind: Defense-in-Depth Security Framework for Agentic AI (Current Version Report)

**Course:** Data Security and Privacy (DS-208)  
**Professor:** Dr Girish Revadigar  
**Team Members:**  
- A. Doni Adithya (23bds007)  
- E. Hari Teja (23bds019)  
- Hari Prasad L. (23bds022)  
- L. Sahith Akash Manikanta (23bds031)  
**Version Snapshot Date:** April 14, 2026

---

## Abstract
Agentic AI systems increase automation power but also expand the attack surface to prompt injection, role abuse, unsafe tool calls, secret leakage, and operational overload. This report presents the current production-oriented version of **AegisMind**, a FastAPI + React security framework that enforces layered controls before and during tool execution. The system combines multi-model prompt risk scoring (regex + ML + LLM voting), role-aware policy enforcement, per-tool risk profiles, human approval workflow, DLP output protection, behavioral anomaly handling, encrypted audit/event logging, and operational governance APIs. The latest version adds dashboard user authentication, policy versioning with change audit, threat-intel feed sync, backup/restore and archive operations, scheduled maintenance controls, calibration feedback for risk tuning, realtime security streaming, scorecard analytics, and dependency automation. Validation shows stable behavior on backend and frontend quality checks.

**Keywords:** Agentic AI security, prompt firewall, policy governance, human approval, DLP, threat intelligence, observability.

---

## I. Introduction
AI agents now execute actions across tools, APIs, and data systems. A single unsafe prompt can propagate into tool misuse or sensitive data exposure. AegisMind addresses this through runtime security-by-design: every execution request is filtered, scored, authorized, monitored, and logged with explainability.

This report reflects the **current implemented version** of AegisMind after security-hardening and operations upgrades.

---

## II. Problem Statement and Threat Model

### A. Problem Statement
Given an incoming prompt and optional tool request, decide whether execution should be allowed, modified, approval-gated, or blocked while preserving confidentiality, integrity, and availability.

### B. Threats Considered
1. Prompt injection and jailbreak language.  
2. Role manipulation and policy bypass attempts.  
3. Encoded malicious intent (including Base64 patterns).  
4. Unauthorized or high-risk tool invocation.  
5. Sensitive output exfiltration (tokens, keys, credentials, PII).  
6. Denial-of-wallet and traffic spikes.

### C. Security Goals
1. Strong prevention before tool execution.  
2. Enforced least-privilege role and tool access.  
3. Human-in-the-loop for medium/high risk operations.  
4. Forensic observability with tamper-resistant records.  
5. Operational reliability under load.

---

## III. System Architecture (Current)

### A. End-to-End Flow
1. Request enters `/agent/execute`.  
2. Auth is verified via agent key headers or dashboard bearer token.  
3. Rate-limiter and queue/backpressure guardrails are enforced.  
4. Prompt firewall computes risk and decision (`safe` vs `blocked`, with explainability).  
5. Tool selection is validated against policy and per-tool risk profiles.  
6. Human approval may be required for elevated risk operations.  
7. Secure gateway executes allow-listed tools only.  
8. DLP scans and modifies/blocks risky output.  
9. Audit + security events are stored (encrypted fields).  
10. Realtime events are broadcast over WebSocket.

### B. Major Components
1. Prompt Firewall (regex + ML + LLM + vote metadata).  
2. Policy Engine (role policies, global denies, chain restrictions, approval threshold).  
3. Secure Tool Gateway (strict tool and argument validation).  
4. DLP Module (mask/block secrets and sensitive patterns).  
5. Behavioral + Self-Healing Engine (cooldown/restricted/lockdown).  
6. Threat Intel Feed (manual import + remote sync + scheduled refresh).  
7. Ops Layer (archives, key rotation, backup/restore, SLO metrics).  
8. Governance APIs (policy versioning, change audit trail, approvals).

---

## IV. Key Features Implemented

### A. Authentication and Access
1. Dashboard login with bearer tokens (`/auth/login`, `/auth/logout`, `/auth/me`).  
2. Role/team-aware user records (`viewer`, `analyst`, `admin`).  
3. Admin user management endpoint (`/auth/users`).  
4. Optional strict log access mode (`LOGS_REQUIRE_DASHBOARD_AUTH`).

### B. Secrets and Key Lifecycle
1. Secret loading supports `/run/secrets` + environment fallback.  
2. Rotating API keys table with active/inactive states.  
3. Manual rotation endpoint (`/ops/api-keys/rotate`).  
4. Scheduled auto-rotation controls via env configuration.

### C. Prompt Risk and Explainability
1. Multi-model guard output with component scores and vote summary.  
2. Safe/Block zone policy configured as:
   - **Safe Zone:** `0–60%`  
   - **Block Zone:** `60–100%`  
3. Explainability payload includes matched rules, threats, model votes, and calibration metadata.

### D. Policy Governance
1. Policy export/apply with validation.  
2. Policy versions and change audit trail tables.  
3. Publish endpoint with change note (`/policy/publish`).  
4. Policy Studio UI in Ops tab.

### E. Human Approval Workflow
1. Pending approval creation for high-risk operations.  
2. Reviewer decision API (`approve` / `reject`).  
3. Pending approvals dashboard view and actions.

### F. Threat Intelligence
1. Manual rule import (`/threat-intel/import`).  
2. Remote feed sync (`/threat-intel/sync`).  
3. Feed status endpoint with last sync/error telemetry.  
4. Scheduled polling support through maintenance loop.

### G. Session Replay and Realtime Stream
1. Session replay API (`/sessions/{id}/replay`).  
2. WebSocket live stream (`/ws/security-stream`).  
3. Ops UI displays replay timeline and live events.

### H. Scorecard and Calibration
1. Security scorecard API (`/analytics/scorecard`) with safe-vs-blocked trend.  
2. Calibration feedback collection (`/analytics/calibration/feedback`).  
3. Bias summary endpoint (`/analytics/calibration/summary`) for tuning.

### I. Reliability and Operations
1. Queue limit, semaphore concurrency cap, timeout budget, backpressure responses.  
2. Archive endpoint + archive index (`/ops/logs/archive`, `/ops/logs/archives`).  
3. Backup create/list/restore (`/ops/backup/create`, `/ops/backups`, `/ops/backup/restore`).  
4. SLO snapshot endpoint (`/observability/slo`).  
5. Optional OpenTelemetry bootstrap hook.

### J. CI and Dependency Security
1. CI workflow for backend tests, frontend lint/build, optional audits.  
2. Pinned backend dependency versions.  
3. Dependabot automation for pip, npm, and GitHub Actions.

---

## V. Frontend (Current Dashboard)
The frontend now includes:
1. `Dashboard` tab: prompt execution, simulator, explainability, guidance.  
2. `Agent` tab: decision pipeline and reasoning trace.  
3. `Logs` tab: filtered audit stream and exports.  
4. `Settings` tab: runtime connection configuration.  
5. **`Ops` tab**: login, policy studio, approvals, threat intel, tool profiles, replay, realtime stream, scorecard, calibration, key rotation, backups, and user management.

---

## VI. Experimental Verification (Current Snapshot)
Validation performed on current codebase:

1. Backend tests (`pytest`): **18 passed**.  
2. Frontend lint (`npm run lint`): **passed**.  
3. Frontend production build (`npm run build`): **passed**.  
4. Frontend e2e (`npm run test:e2e`): **3 passed**.

This indicates the current version is stable across API security checks, UI quality gates, and key user workflows.

---

## VII. Discussion
The current version moves beyond a demo firewall and into an operations-aware security platform. The combination of model-layer risk analysis, policy governance, approval gating, and incident operations features creates practical defense-in-depth for agent workflows.

The most important improvement is integration: detection, authorization, and operational response are now linked in one system (including auditability and admin controls).

---

## VIII. Limitations
1. OpenTelemetry is optional and depends on additional package availability in target deployment.  
2. Advanced team-scope enforcement is currently represented in data model and admin UX; enterprise IAM federation is not yet integrated.  
3. Threat feed quality depends on external source quality and curation.  
4. Calibration currently uses operator feedback; broader ground-truth pipelines can improve robustness.

---

## IX. Future Work
1. External identity integration (OIDC/SAML) for enterprise SSO.  
2. Dedicated notification adapters for email/Slack templates and escalation policies.  
3. Rich SLO dashboards (Grafana) and long-term telemetry storage.  
4. Automated policy simulation tests before policy publish.  
5. Expanded adversarial benchmark suite under high-concurrency mixed traffic.

---

## X. Conclusion
The current AegisMind version provides a comprehensive security control plane for agentic AI execution. It now includes runtime protection, policy governance, approval workflows, threat feed integration, operational backup/archive tooling, realtime visibility, and verified quality gates. This aligns strongly with DS-208 objectives by translating security and privacy principles into a deployable, testable system.

---

## References
[1] FastAPI Documentation. [Online]. Available: https://fastapi.tiangolo.com/  
[2] SQLAlchemy Documentation. [Online]. Available: https://docs.sqlalchemy.org/  
[3] Redis Documentation. [Online]. Available: https://redis.io/docs/  
[4] Docker Documentation. [Online]. Available: https://docs.docker.com/  
[5] Scikit-learn Documentation. [Online]. Available: https://scikit-learn.org/stable/  
[6] Pydantic Documentation. [Online]. Available: https://docs.pydantic.dev/  
[7] Cryptography (Fernet) Documentation. [Online]. Available: https://cryptography.io/  
[8] OWASP Top 10 for LLM Applications. [Online]. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/
