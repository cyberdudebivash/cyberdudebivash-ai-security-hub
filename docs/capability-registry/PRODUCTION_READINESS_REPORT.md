# Enterprise Production Readiness Report

> **GENERATED FILE — do not hand-edit.** Produced by
> `scripts/registry/generate-report.mjs` from
> `docs/capability-registry/domains/*.json`. Every number below is computed
> from those entries. To change a number here, correct the underlying
> registry entry (with real evidence) and re-run the generator — never edit
> this file directly. This is the CEAP instrument described in
> `docs/ENGINEERING_STANDARDS.md` §10/§12; it does not replace
> `KPI_DASHBOARD.md` (the outcome scoreboard) — this report measures
> structural completeness and parity, not customer outcomes.

Generated: 2026-07-12T12:31:10.826Z
Capabilities catalogued: 97

## Overall Completion

| Dimension | % |
|---|---|
| Backend | 89.7% |
| Frontend | 71.6% |
| Parity (backend **and** frontend both exist) | 67% |
| Customer Journeys complete (dynamic_browser-verified) | 3.1% |

## Gaps by Priority

| Severity | Priority | Count | Meaning |
|---|---|---|---|
| Critical | P1 | 9 | Broken customer journey |
| High | P2 | 24 | Backend exists, frontend missing |
| Medium | P3 | 7 | Backend+frontend exist, navigation missing |
| Medium | P4 | 6 | RBAC not enforced |
| Low | P5 | 0 | Subscription gating missing |
| Low | P6 | 37 | No test coverage |
| Low | P7 | 14 | Documentation missing |

**Rollup:** Critical 9 · High 24 · Medium 13 · Low 51

## Structural Findings

| Metric | Count | Definition |
|---|---|---|
| Hidden features | 21 | Backend exists, but not discoverable via navigation |
| Backend-only features | 14 | Backend exists, zero frontend surface |
| Duplicate systems | 4 | Backend marked `duplicate` (two implementations of one capability) |
| Broken journeys | 9 | Priority P1 |

## Production Readiness Verdict: **NOT READY**

Computed, not asserted: NOT READY if any broken journey (P1) exists or
parity is below 80%; GA APPROVED WITH DOCUMENTED LIMITATIONS if parity is
below 95% or any P2 (backend-only) gaps remain; GA APPROVED otherwise. Uses
the fixed vocabulary from `docs/ENGINEERING_STANDARDS.md` §9 — never "100%
complete", "bug free", or "guaranteed".

## Capabilities by Domain

### academy (2 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-ACAD-001 | Training Academy: Course Purchase, Verification & Access | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-ACAD-002 | Homepage Course Buy Buttons | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |

### administration (4 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-ADMIN-001 | Ops Admin Console — Business & Platform Visibility | ✓ | ✓ | ✗ | NOT READY | P6 |
| CAP-ADMIN-002 | Platform Infrastructure Ops APIs (Incidents, Maintenance, Deployments, SSO Config, Email Health, Data Seeding) | ✓ | ✗ | ✗ | NOT READY | P6 |
| CAP-ADMIN-003 | Owner-Only Revenue & Growth Business-Intelligence APIs | ✓ | ✗ | ✗ | NOT READY | P6 |
| CAP-ADMIN-004 | Admin Surfaces — Users, Organizations (done); Marketplace, Academy, Affiliate, CRM, Support (missing) | ◐ | ◐ | ✓ | PILOT ONLY | P2 |

### affiliate-partner (2 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-AFF-001 | Affiliate Program: Join, Status, Payout, Leaderboard | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-AFF-002 | Outbound Sponsor/Affiliate Click Tracking | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |

### commercial-billing (3 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-BILL-001 | Coupon Redemption at Checkout | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-BILL-002 | Coupon Administration | ✓ | ✗ | ✗ | NOT READY | P2 |
| CAP-BILL-003 | Subscription Plans & Billing Portal | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |

### compliance-store (5 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-COMP-001 | Global Compliance Packs Store | ✓ | ✓ | ✓ | PILOT ONLY | P1 |
| CAP-COMP-002 | Compliance Assessment / Readiness Engine (CDB-COMP-001) | ✓ | ✓ | ✓ | PILOT ONLY | P2 |
| CAP-COMP-003 | Tools Marketplace Compliance Toolkits | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-COMP-004 | DPDP Act 2023 Compliance Management Engine | ✓ | ✓ | ✓ | PILOT ONLY | P2 |
| CAP-COMP-005 | Trust Center Compliance Framework Alignment | ✓ | ✓ | ✓ | PILOT ONLY | P2 |

### customer-portal (4 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-PORTAL-001 | Profile & Security Settings | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-PORTAL-002 | Scan History & Reports | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-PORTAL-003 | Session Management (Active Sessions / Per-Session Revoke) | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-PORTAL-004 | Support Ticket System | ✗ | ✗ | ✗ | NOT READY | P2 |

### dashboard-personalization (3 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-DASH-001 | CISO Hub Metrics (Risk Posture, Compliance, Incidents) | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-DASH-002 | Executive Hub / Command Center | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-DASH-003 | Product & Growth Analytics (Funnel, Feature Adoption) | ✓ | ✗ | ✗ | NOT READY | P2 |

### developer-portal-apikeys (4 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-DEVPORTAL-001 | API Key Management (canonical) | ✓ | ✓ | ✓ | PILOT ONLY | P7 |
| CAP-DEVPORTAL-002 | Self-Service Automation API Keys | ✓ | ✓ | ✓ | PILOT ONLY | P1 |
| CAP-DEVPORTAL-003 | Developer Portal — API Explorer, SDK Generation, OpenAPI/Postman Docs, and Key Self-Serve | ✓ | ◐ | ✗ | PILOT ONLY | P1 |
| CAP-DEVPORTAL-004 | Growth/Plan API Key Provisioning | ✓ | ✗ | ✗ | PILOT ONLY | P1 |

### identity (3 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-IDN-001 | Login / Sign-in Entry Point | ✓ | ✓ | ✓ | PILOT ONLY | P1 |
| CAP-IDN-002 | Sign-Up / Account Creation Entry Point | ✓ | ✓ | ✓ | PILOT ONLY | P1 |
| CAP-IDN-003 | MFA Second-Factor Login Completion | ✓ | ✓ | ✓ | PILOT ONLY | P1 |

### masoc (2 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-MASOC-001 | Multi-Agent SOC — 9 Parallel AI Security Agents | ✓ | ✓ | ✓ | NOT READY | P4 |
| CAP-MASOC-002 | Autonomous Defense Engine (SAFE / ASSISTED / AGGRESSIVE auto-response) | ✓ | ✓ | ✓ | PILOT ONLY | P4 |

### mssp (5 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-MSSP-001 | MSSP Partner Onboarding (Checkout / Free Trial → Portal Access) | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P1 |
| CAP-MSSP-002 | Partner Revenue, Client Roster & White-Label Branding | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-MSSP-003 | Multi-Tenant Sub-Account Drill-Down (Per-Client Dashboard, Billing, Usage, API Keys) | ✓ | ◐ | ✓ | PILOT ONLY | P2 |
| CAP-MSSP-004 | Delegated Admin Permissions (MSSP Staff Sub-Accounts) | ✗ | ✗ | ✗ | NOT READY | P2 |
| CAP-MSSP-005 | MSSP Client Portfolio + White-Label Panel (embedded in Executive Hub) | ✓ | ◐ | ✓ | PILOT ONLY | P6 |

### mythos-godmode (6 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-MYTHOS-001 | MYTHOS GOD MODE — 16-Phase Autonomous Security Orchestrator | ✓ | ✓ | ✓ | PILOT ONLY | P4 |
| CAP-MYTHOS-002 | MYTHOS Orchestrator Core (legacy v1.0 defense-tool generation pipeline) | ✓ | ✓ | ✓ | PILOT ONLY | P4 |
| CAP-MYTHOS-003 | MYTHOS Revenue Engine (real domain-scan + compliance-benchmark, paywall-aware) | ✓ | ✗ | ✗ | PILOT ONLY | P2 |
| CAP-MYTHOS-004 | MYTHOS Platform Governor (autonomous health monitor + auto-repair) | ✓ | ✗ | ✗ | PILOT ONLY | P6 |
| CAP-MYTHOS-005 | MYTHOS AI Provider / "APEX NEXUS" (multi-provider AI routing library) | ✓ | ✗ | ✗ | PILOT ONLY | P7 |
| CAP-MYTHOS-006 | MYTHOS AI Enrichment Engine (cross-cutting scan-report enrichment) | ✓ | ◐ | ✓ | PILOT ONLY | P6 |

### navigation (1 capability)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-NAV-001 | Server-Driven Navigation Engine (role/plan/feature-flag-based) | ✗ | ✗ | ✗ | NOT READY | P2 |

### notifications (4 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-NOTIF-001 | Multi-Channel Notification Preferences & Delivery Log | ✓ | ✗ | ✗ | NOT READY | P2 |
| CAP-NOTIF-002 | In-App Notification Bell | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-NOTIF-003 | Outbound Webhooks (Developer + Organization) | ✗ | ✗ | ✗ | NOT READY | P2 |
| CAP-NOTIF-004 | Transactional & Lifecycle Email Engine | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |

### organizations (2 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-ORG-001 | Organization Management | ✓ | ✓ | ✓ | PILOT ONLY | P2 |
| CAP-ORG-002 | Organization Activity Log (Audit Trail) | ✓ | ✓ | ✓ | PILOT ONLY | P4 |

### production-readiness (4 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-PROD-001 | CI Quality & Security Gates (Headers, Accessibility, Performance, Dependencies, Secrets, E2E) | ✓ | ✗ | ✗ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-PROD-002 | Rate Limiting & Structured Request-ID Correlation | ✓ | ✗ | ✗ | NOT READY | P6 |
| CAP-PROD-003 | Distributed Tracing / APM | ✗ | ✗ | ✗ | NOT READY | P2 |
| CAP-PROD-004 | Consolidated OWASP ASVS / API Security Top-10 Checklist | ✗ | ✗ | ✗ | NOT READY | P7 |

### rbac (2 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-RBAC-001 | Platform Staff Role Management | ✓ | ✓ | ✗ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-RBAC-002 | Role/Plan-Based Frontend Feature Gating | ◐ | ◐ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P4 |

### sales-crm (8 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-CRM-001 | Homepage Enterprise Inquiry & Book-Demo Widgets | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-CRM-002 | Dedicated Booking Page (Lead Capture + Demo Booking) | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P3 |
| CAP-CRM-003 | Customer Personalized Risk Radar & Asset Inventory | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-CRM-004 | Customer Success Health Scoring | ✗ | ✗ | ✗ | NOT READY | P2 |
| CAP-CRM-005 | Proposal Generation | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-CRM-006 | Security Assessment Booking | ✗ | ✗ | ✗ | NOT READY | P2 |
| CAP-CRM-007 | Conversion Trigger & Funnel Tracking | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P1 |
| CAP-CRM-008 | Growth & Revenue Automation Suite | ✓ | ✗ | ✗ | NOT READY | P2 |

### security-scanners (10 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-SCAN-001 | Domain Vulnerability Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-002 | AI Security Scanner (OWASP LLM Top 10) | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-003 | Red Team Simulation | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-004 | Identity & Zero Trust Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-005 | Compliance Report Generator | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-006 | Cloud Security Posture Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-007 | Dark Web Exposure Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-008 | AppSec / DAST Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-009 | MCP Security Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-SCAN-010 | Vibe Code Security Scanner | ✓ | ✓ | ✓ | PILOT ONLY | P6 |

### sentinel-apex-marketplace (6 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-MKT-001 | Sentinel APEX Defense Solutions Storefront | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-MKT-002 | Marketplace Catalog & Checkout (Generic) | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P3 |
| CAP-MKT-003 | Sentinel-Specific Purchase Flow | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-MKT-004 | Security Tools Marketplace | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-MKT-005 | Sentinel APEX Marketplace Mega-Dispatcher (Subscriptions, Entitlements, ROI Calculator) | ✓ | ◐ | ✓ | PILOT ONLY | P2 |
| CAP-MKT-006 | Threat Intel Programmatic API (IOC/CVE/Actor/TTP/Risk) | ✗ | ✗ | ✗ | NOT READY | P2 |

### threat-hunting-intel (17 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-TIH-001 | Threat Hunting Engine (KQL/Sigma/YARA) | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-TIH-002 | Threat Intelligence Feed & Versioned API (Sentinel APEX v2.0) | ✓ | ✓ | ✓ | PILOT ONLY | P2 |
| CAP-TIH-003 | Threat Intel Pro Workbench (MITRE ATT&CK, APT Actors, STIX/TAXII, AI Analyst) | ✓ | ✓ | ✓ | NOT READY | P6 |
| CAP-TIH-004 | Threat Intelligence Graph (backend) — distinct from the dashboard's client-side Threat Graph | ✓ | ✗ | ✗ | NOT READY | P2 |
| CAP-TIH-005 | AI Attack Library (MITRE ATLAS / OWASP LLM techniques) | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-TIH-006 | Agent Threat Advisories (AI agent framework CVEs/advisories) | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P6 |
| CAP-TIH-007 | AI Threat Intelligence Feed & Agent Security (Pillar 4/5) | ✓ | ✓ | ✓ | PILOT ONLY | P3 |
| CAP-TIH-008 | Global Threat Intel Firehose (worldwide OSINT) | ✓ | ✓ | ✗ | PILOT ONLY | P3 |
| CAP-TIH-009 | Threat Intelligence API Economy (monetized IOC/CVE/Actor/TTP/Risk) | ✓ | ✓ | ✓ | PILOT ONLY | P2 |
| CAP-TIH-010 | Production IOC Enrichment | ✓ | ✓ | ✓ | PILOT ONLY | P6 |
| CAP-TIH-011 | Threat Confidence & Exploitability Engine | ✓ | ✓ | ✗ | NOT READY | P6 |
| CAP-TIH-012 | Customer/MSSP Personalized Intelligence | ✓ | ✓ | ✗ | NOT READY | P3 |
| CAP-TIH-013 | Enterprise Premium Intelligence API | ✓ | ✓ | ✓ | PILOT ONLY | P3 |
| CAP-TIH-014 | Intelligence Preview (freemium teaser cards) | ✓ | ✓ | ✓ | NOT READY | P2 |
| CAP-TIH-015 | Public Threat-Intel Feeds & Monetization Tier Matrix | ✓ | ◐ | ✗ | PILOT ONLY | P3 |
| CAP-TIH-016 | Attack Graph from Scan Results | ✓ | ◐ | ✓ | NOT READY | P6 |
| CAP-TIH-017 | Scan-Finding to CVE Correlation (legacy) | ✓ | ✗ | ✗ | NOT READY | P7 |

---
*Regenerate with `node scripts/registry/generate-report.mjs` after any
change to `docs/capability-registry/domains/*.json`.*
