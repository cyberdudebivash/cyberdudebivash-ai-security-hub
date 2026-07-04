# Phase IV — Competitive Gap Matrix

**Date:** 2026-07-04 · **Method:** capability-category comparison against recognized enterprise expectations for each product class. Per program instruction, **no named-vendor feature-for-feature claims** are made — we did not evaluate competitor products hands-on, so vendor comparisons would be speculative. "Platform" columns are evidence-backed from Phases I–IV; "enterprise expectation" columns describe what buyers of that category conventionally require.

Legend: ✅ competitive · ◐ partial · ✗ missing

## 1. Threat Intelligence Platform (TIP) category

| Enterprise expectation | Platform | Evidence / gap |
|---|---|---|
| Curated vulnerability/threat feed, machine-readable | ✅ | Live KEV-sourced feed: 1,637 CVEs, 1,631 KEV, refreshed 4×/day (cron slot 2); tiered JSON API verified live |
| Grounded analyst assistance | ✅ (differentiator) | AI analyst answers grounded in the platform's own intel DB with **verified anti-fabrication behavior** — rare in this category |
| Freshness/authenticity guarantees | ✅ | `data_source: d1, live: true`; freshness guard tests in CI |
| STIX/TAXII interchange | ✗ | No STIX/TAXII endpoint in the route inventory — expected by mature SOC buyers |
| Multi-source fusion (commercial feeds, dark web, OSINT breadth) | ◐ | KEV/NVD-centric + OSINT enrichment; no multi-vendor feed fusion or confidence scoring |
| Intel sharing / community (ISAC-style) | ✗ | Not present |

## 2. Vulnerability Management (VM) category

| Enterprise expectation | Platform | Evidence / gap |
|---|---|---|
| CVE tracking, severity & risk scoring | ✅ | Real CVSS/KEV/ransomware flags; recalibrated severity pipeline; 1,626 published CVE advisories |
| Report generation for stakeholders | ✅ | Live-verified: 201 generate + 200 download, styled HTML |
| Authenticated internal asset scanning (agents/network) | ✗ | Scans are external (DNS/TLS/DNSSEC/subdomain/identity posture) — no agent or internal network scanner |
| Ticketing/workflow integrations (Jira/ServiceNow) | ✗ | Not present; exports + webhooks only |
| Patch orchestration | ✗ | Out of scope by design |

## 3. Attack Surface Management (ASM) category

| Enterprise expectation | Platform | Evidence / gap |
|---|---|---|
| External posture scan (DNS/TLS/DNSSEC/subdomains) | ✅ | Live-verified real scan data (`live_dns`, real NS/IPs, DNSSEC validation) |
| Continuous unknown-asset discovery | ◐ | On-demand + scheduled scans of known targets; no seed-expansion discovery of unknown assets |
| Port/service/cloud-resource enumeration breadth | ◐ | Domain-centric; no broad port scanning or cloud-account enumeration |
| Risk-graded findings with remediation | ✅ | Graded findings with recommendations, premium depth tiers |

## 4. AI Security Tooling category (the platform's declared focus)

| Enterprise expectation | Platform | Evidence / gap |
|---|---|---|
| AI/LLM use-case risk assessment | ✅ (differentiator) | AI scanner across use-cases; OWASP-LLM, prompt-injection-defense, AI-governance content and scorecards |
| AI that doesn't hallucinate security facts | ✅ (differentiator, **proven**) | Live-verified: unknown CVE → explicit uncertainty; known CVE → real facts; regression-locked. Most of the market cannot evidence this |
| Runtime LLM firewall / guardrail proxy | ✗ | Advisory/assessment only — no inline runtime protection product |
| Automated model red-teaming at depth | ◐ | AI red-team module exists (scoped scenarios); not a full adversarial-eval harness |
| AI governance & compliance mapping | ✅ | Governance frameworks, PDF, scorecard pages |

## 5. Exposure Management category

| Enterprise expectation | Platform | Evidence / gap |
|---|---|---|
| Unified risk scoring across findings | ✅ | Risk scores/grades unified across scan modules |
| Attack-path / asset-graph analysis | ✗ | No graph model of customer environment |
| Prioritization by exploitability (KEV/EPSS-style) | ◐ | KEV integration real; no EPSS-style probabilistic scoring surfaced |

## 6. Security Operations (SOC) Tooling category

| Enterprise expectation | Platform | Evidence / gap |
|---|---|---|
| Investigations with tenant isolation | ✅ | Cross-tenant write/read isolation proven (IDOR fixes + live probes) |
| Detection-rule authoring (Sigma/KQL/YARA/Splunk) | ✅ | Deterministic rule scaffolds, honestly labeled as templates |
| MITRE ATT&CK mapping | ✅ | Mapped scenarios and content |
| SIEM-grade ingestion / log pipeline | ✗ | Not a SIEM; SIEM export formats exist |
| SOAR playbook automation | ◐ | Automation/agents exist for platform-internal ops; no customer-facing playbook engine |
| On-call integrations (PagerDuty/Opsgenie) | ✗ | Telegram/email alerting only |

## 7. Differentiation summary

**Why buy this:**
1. **Verified AI honesty** — the only claim category where this platform holds evidence most competitors don't publish: grounded AI with regression-locked anti-fabrication, live-proven.
2. **Radical transparency** — public trust center with honest metrics, disclosed sub-processors, corrected marketing claims; procurement teams reward this.
3. **Price-to-capability** — ₹499–₹9,999/mo (~$6–$120) for a unified intel + external-posture + AI-analyst stack that undercuts per-seat enterprise tooling by orders of magnitude.
4. **Zero-ops serverless edge architecture** — no appliance, no deployment burden for the customer; MSSP-grade multi-tenancy primitives proven.
5. **Content/SEO moat** — 1,626 CVE advisory pages + blog + academy feeding organic acquisition.

**Why a buyer would hesitate (honest weaknesses):**
1. Single-operator vendor (viability, support SLA, bus factor) — the dominant objection for enterprise procurement.
2. No vendor certifications (SOC 2 / ISO 27001) — hard gate in regulated segments.
3. External-only scanning — cannot replace internal VM programs; positions as complement, not replacement.
4. No STIX/TAXII, ticketing, or on-call ecosystem integrations yet.
5. Two pending live proofs (payment, SSO) before paid/enterprise GA claims.

**Innovation opportunities (highest leverage first):** (1) productize the anti-hallucination grounding as a marketed, testable guarantee ("evidence-or-abstain AI"); (2) STIX/TAXII export — cheap to add, unlocks SOC interop checklists; (3) EPSS-style prioritization atop existing KEV data; (4) runtime prompt-injection defense as a product (content already leads there); (5) Jira/ServiceNow webhook templates.

## 8. Positioning conclusion

The platform should sell as an **AI-native security intelligence and external-exposure hub for SMB/MSSP/startup buyers, and an evaluation-grade complement for enterprises** — not as a full TIP/VM/SIEM replacement. Within that positioning, every strong-cell claim above is evidence-backed; the gaps are roadmap, not misrepresentation.
