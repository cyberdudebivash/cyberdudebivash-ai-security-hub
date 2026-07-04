# Vendor Security Questionnaire Pack (CAIQ-lite)

> Pre-answered vendor-security questionnaire for enterprise procurement
> (Fortune 500 / bank / MSSP due-diligence). Every answer is evidence-bounded:
> where the honest answer is "no" or "not yet", it says so — this platform's
> procurement posture is disclosure, not marketing. Companion documents:
> `FORTUNE500_SECURITY_TRUST_OVERVIEW.md`, `SUB_PROCESSOR_LIST.md`,
> `DATA_PROCESSING_AGREEMENT_TEMPLATE.md`.
> **Last verified:** 2026-07-04 (Phase IV remediation pass).

## 1. Company & governance

| Question | Answer |
|---|---|
| Legal entity | CyberDudeBivash Pvt. Ltd. (India) · cyberdudebivash.in |
| Third-party certifications (SOC 2 / ISO 27001) | **None yet.** SOC 2 Type I is the declared first milestone (Global Release Decision, condition 7). Interim assurance: this evidence-backed audit trail (`docs/audit-history/`) |
| Security team / on-call | **Single-operator company** (disclosed, risk R-10). Alerts: Telegram + email + external GitHub probe. Escalation deputy: not yet in place |
| Insurance / continuity assurances | Not yet available — request via enterprise contact |

## 2. Architecture & data

| Question | Answer |
|---|---|
| Hosting | Cloudflare (Workers/Pages/D1/KV/R2/Queues), serverless edge; no self-managed servers, no customer-premise components |
| Data stored | Account data (email, bcrypt-hashed secrets, hashed API keys), scan targets & results, billing metadata. No cardholder data (payments via Razorpay) |
| Data residency | Cloudflare global edge; no residency pinning offered yet (disclosed limitation for regulated buyers) |
| Encryption | TLS 1.2+ in transit (HSTS preload); provider-managed encryption at rest (Cloudflare D1/KV/R2) |
| Sub-processors | Fully disclosed in `SUB_PROCESSOR_LIST.md`: LLM providers (Groq, DeepSeek, OpenRouter, Together, Anthropic, Cloudflare AI), Google Analytics 4, Razorpay, Cloudflare, GitHub |
| Backups & recovery | Nightly integrity-gated D1 export (SHA-256, 90-day retention) + **weekly automated restore drill against the real artifact** (`d1-restore-drill.yml`); RPO/RTO per store in `DISASTER_RECOVERY_RUNBOOK.md` |

## 3. Access control & tenant isolation

| Question | Answer |
|---|---|
| Customer isolation | Logical multi-tenant isolation, **live-probed** (Phase III): cross-tenant access uniformly 404; write-path IDORs fixed and regression-locked |
| AuthN | JWT sessions, hashed API keys, TOTP MFA (+backup codes), OIDC SSO (PKCE, RS256, alg-confusion rejected). Live IdP round-trip with a customer tenant: pending (disclosed) |
| AuthZ | RBAC + entitlement tables; 158 auth gates audited against a canonical real-principal check (`authGateRealUser`, 25 tests) |
| Admin access | Owner-gated admin surfaces; least-privilege CI token (cannot edit zone routes) |
| Report links | Default: unguessable capability URL, 7-day expiry. **Auth-gated `visibility:"private"` mode available** for regulated tenants (owner-bound download) |

## 4. Secure development & operations

| Question | Answer |
|---|---|
| SDLC gates (every deploy) | 1,267+ unit/regression tests · Playwright E2E · axe accessibility · security-header assertions · Lighthouse · bundle-size gate · gitleaks secret scanning |
| Change control | Deploys only via gated CI (serialized, post-deploy smoke + version verification); schema changes only via migration workflow with pre-migration export |
| Logging & monitoring | Structured request logs w/ request-ID correlation, `system_errors` ledger, deduped ops alerts, health/uptime endpoints, **external uptime probe outside the platform's failure domain** (every 15 min) |
| Vulnerability management (self) | Global exception boundary; security regression suite covers fixed classes (2FA bypass, IDORs, MFA anonymous enrollment, CSV injection, BOLA); no external pentest report yet (disclosed) |
| Incident response | `INCIDENT_RESPONSE_RUNBOOK.md` (severity ladder, comms steps). Breach-notification commitments per DPA template |

## 5. Privacy & compliance

| Question | Answer |
|---|---|
| GDPR | Erasure **proven live** (account deletion purges keys/history/jobs incl. queued; login blocked after). DPA template + Art. 28 sub-processor disclosure published |
| AI transparency | AI outputs grounded in the platform's own data; unknowns are acknowledged, never invented (regression-locked). LLM sub-processors disclosed; no customer data sold |
| Uptime/SLA | "99.9% uptime SLA target" (explicitly a target, not a contractual SLA). Honest availability accounting with `degraded_pct` separated. Contractual SLAs: not offered until reconciliation completes (EA-03) |
| PCI | Out of scope — payments processed by Razorpay (webhook HMAC-verified); no card data touches the platform |

## 6. Honest gaps a reviewer will find (so you don't have to)

1. No third-party attestation yet (SOC 2 planned first).
2. Single-operator support/on-call; no ticketing SLA instrumentation.
3. Live payment and live SSO IdP round-trips pending (both contract/e2e-test verified).
4. No data-residency pinning or BAA offering.
5. KV rate counters are best-effort (bounded overshoot; fail-open on KV outage) — accepted risk R-14.
