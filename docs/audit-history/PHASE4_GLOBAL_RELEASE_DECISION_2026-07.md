# Phase IV — Final Global Release Decision

**Program:** Global Enterprise Readiness & Competitive Certification — the final gate before worldwide release.
**Authority:** Independent Enterprise Release Authority · **Date:** 2026-07-04
**Production at decision time:** v40.0, commit `56ab74f` (deploy #616 green) · **Suite:** 1251 tests / 118 files passing (re-run this session)
**Release taxonomy (exactly one per capability):** GLOBAL RELEASE APPROVED · ENTERPRISE APPROVED · PILOT READY · LIMITED RELEASE · NEEDS REMEDIATION · BLOCKED

> Decision rule applied: a capability is approved **only** on customer-verified, evidence-backed, commercially valuable, operationally sustainable grounds — never because code exists, tests pass, or deployment succeeded. All live-production evidence is same-day (2026-07-04, Phases II–III); this session added runtime, CI-telemetry, cold-start, and source evidence (production egress was policy-blocked from this sandbox — disclosed in the Enterprise Readiness Report §0).

## 1. Capability decisions

| # | Capability | Decision | Deciding evidence / condition |
|---|---|---|---|
| 1 | Signup · login · session · API keys | **GLOBAL RELEASE APPROVED** | Live-proven repeatedly (3 fresh accounts created/exercised/deleted same-day); regression-locked |
| 2 | AI security scan (async, real data) | **GLOBAL RELEASE APPROVED** | Live `live_dns` results, real NS/IPs/DNSSEC; queue drain proven; 3-way concurrency intake proven |
| 3 | Scan history (per-user) | **GLOBAL RELEASE APPROVED** | Live-verified scoping; isolation probed |
| 4 | Report generation & download | **ENTERPRISE APPROVED** | Live 201+200 after Phase II fix; capability-URL sharing model is disclosed; auth-gated download option required before regulated-tenant use |
| 5 | Dashboards & platform metrics | **GLOBAL RELEASE APPROVED** | SSOT-sourced real data live-verified; honest 503-with-nulls degradation verified this session |
| 6 | AI copilot + MYTHOS analyst (grounded) | **ENTERPRISE APPROVED** | Anti-fabrication live-proven and regression-locked; external-LLM dependency disclosed (sub-processors); keep under continuous eval |
| 7 | Threat-intel feed & metered API | **ENTERPRISE APPROVED** | Live real KEV data, quotas enforced (429); STIX/TAXII gap keeps it below "global" for SOC interop buyers |
| 8 | Multi-tenant isolation (incl. MSSP primitives) | **ENTERPRISE APPROVED** | Live cross-tenant probing: uniform 404s, zero identity-based leakage; MSSP *commercials* separately PILOT READY (#10) |
| 9 | GDPR erasure & privacy surfaces | **GLOBAL RELEASE APPROVED** | Erasure proven live twice incl. queued jobs; sub-processor disclosure + DPA template published |
| 10 | Paid conversion (Razorpay) & billing | **PILOT READY** | Full path proven through the real worker in tests; pricing integrity re-verified (PL-1 = misdiagnosis, no overcharge); **gate to ENTERPRISE APPROVED: one live ₹ transaction** |
| 11 | SSO/OIDC + MFA enterprise onboarding | **PILOT READY** | Code-path round-trips proven (PKCE, RS256, alg-confusion rejection; TOTP+backup codes); **gate: one live IdP round-trip with a pilot tenant** |
| 12 | Marketplace & checkout | **ENTERPRISE APPROVED** | Real catalog + server-issued checkout URLs live-verified; fabricated fallbacks removed and locked |
| 13 | Alerting/ops observability (in-band) | **ENTERPRISE APPROVED** | Structured logs, error boundary, deduped alerts, honest uptime — all source/CI-verified; external probe tracked at #15 |
| 14 | Support & customer success (enterprise) | **NEEDS REMEDIATION** | Single-operator support, no ticketing/SLA instrumentation, no external status page — remediation list in Customer Success report §5 |
| 15 | Contractual SLA / uptime commitments | **NEEDS REMEDIATION** | Honest availability accounting exists, but no external probe (R-11) and definitions unreconciled (EA-03); **do not sign SLAs until closed** |
| 16 | Developer/integrator repo documentation | **NEEDS REMEDIATION** | `docs/api-contract.md` (v3.0) and `docs/architecture.md` contradict the live platform; live api-docs page is current — fix the repo docs or mark them superseded |
| 17 | Regulated-segment production procurement (bank/gov/healthcare/defense) | **BLOCKED** | Organizational gates: no third-party attestation (SOC 2/ISO), bus-factor-1 support, no SLA machinery, no residency/BAA options — see Procurement Review §2–3 |
| 18 | Fortune 500 / critical-infrastructure use | **LIMITED RELEASE** | Evaluation and external-posture/advisory use approved; production procurement follows #17's flip conditions |

## 2. Segment release decisions

| Segment | Decision |
|---|---|
| Free / self-serve (founder, developer, analyst) | **GLOBAL RELEASE APPROVED** — open the funnel |
| SMB paid tiers | **PILOT READY** → approved for paid pilots now; GA on first live payment (#10) |
| MSSP | **PILOT READY** — isolation proven; one real partner tenant through billing/white-label before scale-out |
| Enterprise (non-regulated) | **ENTERPRISE APPROVED with documented limitations** (#4, #11, #14, #15) — sell evaluations and white-glove pilots |
| Regulated enterprise | **BLOCKED** for production; evaluation sandboxes permitted |

## 3. Conditions register (what advances each decision)

1. **One live payment** → #10 to ENTERPRISE APPROVED (owner; needs real card/UPI).
2. **One live SSO IdP round-trip** → #11 to ENTERPRISE APPROVED (needs pilot tenant).
3. **External uptime probe + SLA definition reconciliation** → #15 closed (owner, ~hours).
4. **Support escalation path + response tracking + status page** → #14 closed.
5. **Auth-gated report-download option** → #4 usable by regulated tenants.
6. **Refresh or supersede stale repo docs** → #16 closed (hours).
7. **SOC 2 Type I** (then II) → begins unlocking #17 (quarters, not days — start when regulated pipeline is real).
8. **Real-artifact restore drill (R-06)** — not gating any release above, but the top operational IOU; artifacts now exist.

## 4. Final decision

**PILOT RELEASE: AUTHORIZED** across all segments within the decisions above — free/self-serve fully open, paid SMB and MSSP as pilots, enterprise as evaluations/white-glove pilots.
**GENERAL AVAILABILITY: NOT YET** — gated precisely on conditions 1–4 (all fast, owner-actionable) — and **regulated-segment GA additionally on condition 7**.

Per the release sequence this program follows, the platform now proceeds: Phase IV ✅ → **Pilot Release** → Early Enterprise Customers → Production Monitoring → GA.

No "100%", "bug-free", or blanket-stability claim is made anywhere in this decision; every status above is bounded by the cited evidence, and the remaining limitations are disclosed rather than deferred. Signed as the honest state of the platform on 2026-07-04.
