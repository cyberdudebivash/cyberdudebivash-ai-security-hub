# Phase IV — Enterprise Procurement Review

**Date:** 2026-07-04 · **Lens:** independent buyer's procurement board — five approval chairs (procurement, engineering, security, legal/compliance, operations) across nine buyer segments. Verdicts are evidence-bounded; where a chair would demand artifacts that do not exist, the verdict is NO regardless of product quality.

## 1. Approval-chair review (segment-independent)

| Chair | Verdict | Basis |
|---|---|---|
| **Engineering** | ✅ APPROVE | Real data end-to-end (live-verified), 1251-test regression suite, gated deploys (616 runs, last 30 green), structured errors, request correlation, honest degradation (503 with nulls, never fabricated metrics), cold-start local run works in two commands |
| **Security** | ✅ APPROVE (scope-bounded) | 2FA bypass + 3 IDORs + MFA anon-enrollment closed with regression locks; 158 auth gates audited; tenant isolation live-probed; gitleaks + header gates in CI. Notes: report links are capability URLs (by design, disclosed); recommend auth-gated option for regulated tenants |
| **Legal** | ⚠️ CONDITIONAL | ToS/privacy/refund policies published; DPA template + sub-processor disclosure present (GDPR Art. 28 satisfied). Conditions: no contractual uptime SLA until availability definitions + external probe exist (EA-03/R-11); confirm data-residency language before EU/regulated contracts |
| **Compliance** | ⚠️ CONDITIONAL | GDPR erasure proven live (strongest artifact); but **vendor holds no third-party attestation (SOC 2 / ISO 27001)** — self-assessments and this evidence trail substitute only for non-regulated buyers |
| **Operations** | ⚠️ CONDITIONAL | Runbooks (IR/DR/deploy) current; nightly backups live (2/2 green); migration workflow with pre-export. Conditions: restore never drilled against a real artifact (R-06), single-operator on-call (R-10), monitoring self-hosted in the monitored system (R-11) |
| **Procurement (vendor risk)** | ❌ WITHHOLD for production contracts | Single-operator company: bus factor 1, no support SLA, no certifications, no financial/continuity assurances. Standard vendor-risk scoring fails on organizational — not technical — grounds. Evaluation/pilot procurement: approve |

## 2. Segment verdicts

| Segment | Procurement outcome | Rationale |
|---|---|---|
| **Fortune 500** | **LIMITED RELEASE** — evaluation/pilot only | Product evidence would pass a technical bake-off; vendor-risk chairs (cert, SLA, continuity) block production procurement |
| **Bank / financial services** | **BLOCKED** for production; sandbox evaluation OK | Regulated outsourcing rules require vendor attestation + exit/continuity plans that do not exist |
| **Government** | **BLOCKED** | No accreditation path evidence (no FedRAMP-equivalent, residency guarantees, or sovereign hosting); public-cloud US/EU edge only |
| **Healthcare** | **BLOCKED** for PHI-adjacent use; OK for external-posture use with no PHI | No BAA offering; HIPAA content exists as advisory product, not as vendor compliance |
| **Critical infrastructure** | **LIMITED RELEASE** — advisory/monitoring complement only | External-scan + intel value is real; no OT/ICS capability claimed (correctly) |
| **Defense** | **BLOCKED** | No clearance/ITAR/sovereign controls; do not pursue until deliberate |
| **MSSP** | **PILOT READY** | Isolation proven live (the segment's #1 gate); needs one real partner tenant through billing/white-label before scale-out |
| **Startup** | **APPROVED** | Self-serve lifecycle proven live; free tier genuinely functional; instant API access |
| **SMB** | **APPROVED (pilot pricing)** | Full surface verified; recommend closing the one live-payment proof before aggressive paid acquisition |

## 3. What flips the blocked segments (in order of leverage)

1. **SOC 2 Type I → Type II** — single highest-leverage artifact; converts F500 "evaluation" to "procurable" and opens bank/healthcare conversations.
2. **Formal support & continuity plan** — documented escalation beyond one operator, source-escrow or continuity statement (R-10).
3. **Contractual SLA machinery** — external uptime probe (R-11) + reconciled availability accounting (EA-03), then a defensible SLA schedule.
4. **Live SSO + live payment proofs** — already top of the Phase III roadmap; procurement checklists ask for both.
5. **Residency/BAA options** — only if healthcare/EU-regulated pipeline justifies it; do not build speculatively.

## 4. Honest bottom line

This platform's *product* evidence is stronger than its *organization's* procurement posture — the reverse of most early vendors. Nothing in this review found the platform overclaiming; the blocked verdicts above are structural facts of a single-operator company, disclosed rather than disguised. Sell where the evidence supports it today (startup, SMB, MSSP pilot, enterprise evaluation) while the certification and support tracks close the rest.
