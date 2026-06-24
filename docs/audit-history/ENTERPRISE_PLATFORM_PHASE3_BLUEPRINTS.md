# CYBERDUDEBIVASH® AI Security Hub
# ENTERPRISE PLATFORM PHASE 3 — MATURITY, COMMERCIAL SCALE & PRODUCTION EXCELLENCE
# Pre-Implementation Reviews + 10-Workstream Implementation Roadmap

---

## PRE-IMPLEMENTATION REVIEW 1: ARCHITECTURE REVIEW

### Current Platform Architecture (v32.0 baseline)

```
┌─────────────────────────────────────────────────────────────────────┐
│                  CYBERDUDEBIVASH® AI SECURITY HUB                   │
│                    Cloudflare Edge Architecture                      │
├─────────────────────────────────────────────────────────────────────┤
│  FRONTEND (Static Assets — Cloudflare CDN)                          │
│  ├── index.html (21,000+ lines — enterprise dashboard)              │
│  ├── dashboard-live.js (Phase 1 — real-time SSE data bus)           │
│  ├── enterprise-ux.js  (Phase 2 — command palette, notifications)   │
│  ├── revenue-center.js (Phase 2 — MRR/ARR dashboard)               │
│  ├── mssp-workspace.js (Phase 2 — MSSP customer directory)          │
│  ├── soc-investigations.js (Phase 2 — case management)              │
│  ├── cti-workbench.js  (Phase 2 — threat actor + IOC search)        │
│  └── platform-health.js (Phase 2 — observability dashboard)         │
├─────────────────────────────────────────────────────────────────────┤
│  WORKER (Single Cloudflare Worker — 488+ routes)                    │
│  ├── Auth Layer: JWT Bearer → API Key → IP fallback (FREE)          │
│  ├── CORS + Security Headers middleware                             │
│  ├── Rate limiting + subscription paywall engine                    │
│  ├── Sentinel APEX (threat intelligence, SOC automation)            │
│  ├── MYTHOS Engine (AI analysis, attack graphs, forecasting)        │
│  ├── Scan Engines: domain, AI, redteam, identity, compliance        │
│  ├── Phase 2 Handlers: revenue, MSSP, SOC cases, CTI, health        │
│  └── Cron workers: monitoring, ingestion, detection, defense        │
├─────────────────────────────────────────────────────────────────────┤
│  DATA LAYER                                                         │
│  ├── D1 (SQLite) — primary structured data, 25+ tables              │
│  ├── KV — caching (5-30s TTL), session tokens, health probes        │
│  ├── R2 — report storage, scan artifacts, large payloads            │
│  └── Queues — async job processing, email delivery                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 3 Architectural Principles

1. **Additive-only pattern** — All Phase 3 code is new files or new route blocks. Zero modification of existing handlers, services, or schema tables.
2. **Namespace isolation** — Phase 3 frontend: `window.CDB_P3_*`. Phase 3 API prefix: `/api/p3/*` where ambiguous, else domain-specific prefixes.
3. **D1 as source of truth** — All new tables use `CREATE TABLE IF NOT EXISTS`. KV caches all hot reads with 60s TTL.
4. **Virtual tenancy** — All Phase 3 multi-tenant data uses `org_id` column (already established in Phase 2). No new isolation boundary.
5. **Graceful degradation** — Every Phase 3 API returns safe defaults on empty tables. Frontend modules handle 401/403 with informative UI states, never crash.
6. **Event-driven where possible** — Product analytics events written to `analytics_events` table on API calls; no client-side tracking pixels.

### Phase 3 Topology Addition

```
Phase 3 adds 8 new handler modules + 6 new frontend modules:

Worker (new imports, additive):
  handlers/customerSuccess.js      → /api/customer-success/*
  handlers/reportingEngine.js      → /api/reports/*
  handlers/globalSearch.js         → /api/search
  handlers/workflowAutomation.js   → /api/workflows/*
  handlers/whiteLabelMSSP.js       → /api/white-label/*
  handlers/productAnalytics.js     → /api/analytics/p3/*
  handlers/notificationPlatform.js → /api/notifications/*
  handlers/reliabilityEngineering.js → /api/reliability/*

Frontend (new self-injecting modules):
  customer-success.js     → "Customer Success" tab
  reporting-center.js     → "Reports" tab
  global-search-v2.js     → enhances command palette search
  workflow-builder.js     → "Workflows" tab
  white-label-config.js   → "Branding" tab (MSSP Admin only)
  growth-analytics.js     → "Growth" tab (Admin only)

D1 Schema (schema_phase3.sql):
  customer_health, report_jobs, saved_searches, workflows,
  workflow_executions, tenant_themes, analytics_events,
  notification_preferences, notification_log  (9 tables)
```

---

## PRE-IMPLEMENTATION REVIEW 2: SECURITY REVIEW

### Threat Model

| Threat | Vector | Mitigation |
|--------|--------|------------|
| Tenant data leakage | Multi-tenant API without org_id filter | All P3 queries filter by `org_id` from JWT claim |
| Unauthorized workflow execution | Workflow trigger endpoint | Requires `admin` or `mssp_admin` role; trigger tokens are single-use |
| Notification spoofing | Webhook delivery impersonation | Webhook payloads signed with HMAC-SHA256 using tenant secret |
| Saved search injection | SQLi via search query | All search queries use D1 parameterized queries, no string interpolation |
| Report data exfiltration | Unauthenticated report download | Report download URLs are time-limited signed tokens (KV TTL 1h) |
| Analytics event stuffing | Spam event ingestion | Rate-limited to 100 events/min per org; server-side event type whitelist |
| Theme CSS injection | Custom CSS in white-label config | CSS sanitized server-side; only color hex values and URLs accepted |
| Privilege escalation | Modifying own role via profile API | Role updates require `admin` actor; checked in auth middleware |

### RBAC Model (Phase 3 extensions)

```
Role                Capabilities Added in Phase 3
────────────────    ──────────────────────────────────────────────────
admin               All P3 features including branding, growth analytics
mssp_admin          Customer success, white-label config, MSSP reports
enterprise          Reports (own org), workflows (read + create), notifications
pro                 Reports (own org, read only), saved searches
FREE                No P3 features (graceful 403 with upgrade prompt)
```

### API Security Checklist

- [x] All `/api/customer-success/*` routes: require auth, filter by org_id
- [x] All `/api/reports/*` routes: require auth; download token validated separately
- [x] `/api/search` route: auth required; results scoped to caller's org_id
- [x] All `/api/workflows/*` routes: require admin|mssp_admin|enterprise
- [x] `/api/white-label/*` routes: require mssp_admin|admin only
- [x] `/api/analytics/p3/*` routes: write = auth required; read = admin only
- [x] `/api/notifications/*` routes: preferences = own user only; log = admin
- [x] `/api/reliability/*` routes: read = enterprise+; write = admin only
- [x] No new CORS relaxations — inherits existing withCors() middleware
- [x] No new secrets in code — all credentials from `env` bindings

### Tenant Isolation Verification

Phase 3 adds no new isolation primitives — it extends the Phase 2 virtual tenancy model. All new D1 tables with tenant data include `org_id TEXT DEFAULT 'default'`. Worker handlers extract `org_id` from the JWT payload (`req.user.org_id` or `'default'`). No cross-tenant queries are possible as `WHERE org_id = ?` is always applied.

---

## PRE-IMPLEMENTATION REVIEW 3: SCALABILITY REVIEW

### D1 Scalability Analysis

| Table | Expected Growth | Mitigation |
|-------|----------------|------------|
| analytics_events | HIGH (100K+ events/day at scale) | Partition by month; auto-prune events >90 days |
| notification_log | MEDIUM (10K+ per day) | Auto-prune >30 days |
| workflow_executions | MEDIUM | Prune completed >180 days |
| customer_health | LOW (1 row/org, updated daily) | N/A |
| report_jobs | LOW (archived to R2, row cleaned up) | Archive completed jobs |
| saved_searches | LOW | N/A |
| workflows | LOW | N/A |
| tenant_themes | LOW (1 row/org) | N/A |
| notification_preferences | LOW (1 row/user) | N/A |

**D1 Limits at Phase 3 scale:** 10GB storage, 50k rows/table (D1 beta). Analytics events table is the only table at risk at scale; we include a `created_at` index and a cron-based pruning endpoint.

### KV Cache Strategy (Phase 3)

| Cache Key | TTL | Size |
|-----------|-----|------|
| `customer_health_{org_id}` | 300s | <2KB |
| `search_results_{hash}` | 30s | <50KB |
| `report_job_{id}` | 3600s | URL only |
| `tenant_theme_{org_id}` | 600s | <5KB |
| `growth_metrics_v3` | 300s | <10KB |
| `reliability_snapshot` | 60s | <5KB |

### Cloudflare Worker CPU Budget

Cloudflare Workers enforce a 50ms CPU time limit per request (Bundled plan) or 30s (Unbound). The existing Worker is already on Unbound (scan engines require long CPU time). Phase 3 handlers are all lightweight D1 reads/writes — no CPU budget risk.

### Scalability Decisions

1. **Global search** uses SQLite LIKE queries across D1 tables — acceptable at <100K rows total. At scale, this is replaced by Cloudflare Vectorize or D1 FTS extension.
2. **Report generation** is async — job queued to D1, report rendered client-side or via Worker in background. Heavy PDF generation offloaded to R2 pre-rendering.
3. **Workflow execution** is synchronous for simple triggers (<100ms), async for multi-step via Cloudflare Queues for steps >3.
4. **Notification delivery** is fire-and-forget — logged to D1, delivery to external channels (Slack, email) via existing email/webhook infrastructure.

---

## PRE-IMPLEMENTATION REVIEW 4: ROLLBACK REVIEW

### Rollback Strategy

Phase 3 is designed for zero-downtime rollback at any point:

1. **Frontend rollback:** Remove 6 `<script defer>` tags from index.html. All Phase 2 and Phase 1 functionality is untouched.
2. **Route rollback:** Comment out 8 import blocks and ~30 route blocks from index.js. All 488+ existing routes unaffected.
3. **Schema rollback:** Phase 3 tables are new; DROP TABLE is safe. Existing tables never modified.
4. **Handler rollback:** Delete 8 new handler files. Zero impact on existing handlers.

### Regression Protection

- Phase 3 routes all use path prefixes not used by any existing route (verified by `grep` audit below)
- No changes to: auth.js, subscription.js, threatIntel.js, soc.js, sentinelApex.js, analytics.js (existing), growth.js
- No changes to: existing D1 tables, KV key naming, R2 bucket structure
- All Phase 3 frontend modules check for DOM prerequisites before injecting — if Phase 1/2 structure is absent, they retry with exponential backoff and log a warning

### Route Conflict Audit (Phase 3 prefixes vs. existing)

```
/api/customer-success/*  — NEW (no conflict)
/api/reports/*           — NEW (existing /api/report/* is report download; no conflict)
/api/search              — NEW (existing /api/start-search is different; no conflict)
/api/workflows/*         — NEW (no conflict)
/api/white-label/*       — NEW (no conflict)
/api/analytics/p3/*      — NEW (existing /api/analytics is different; no conflict; p3/ sub-path)
/api/notifications/*     — NEW (no conflict)
/api/reliability/*       — NEW (existing /api/platform/health/* is different; no conflict)
```

---

## PRE-IMPLEMENTATION REVIEW 5: IMPLEMENTATION ROADMAP

### Deployment Order (zero-regression sequence)

```
Step 1  — schema_phase3.sql (D1 migration — additive, safe)
Step 2  — handlers/customerSuccess.js
Step 3  — handlers/reportingEngine.js
Step 4  — handlers/globalSearch.js
Step 5  — handlers/workflowAutomation.js
Step 6  — handlers/whiteLabelMSSP.js
Step 7  — handlers/productAnalytics.js
Step 8  — handlers/notificationPlatform.js
Step 9  — handlers/reliabilityEngineering.js
Step 10 — workers/src/index.js (import + route registration)
Step 11 — frontend/customer-success.js
Step 12 — frontend/reporting-center.js
Step 13 — frontend/global-search-v2.js
Step 14 — frontend/workflow-builder.js
Step 15 — frontend/white-label-config.js
Step 16 — frontend/growth-analytics.js
Step 17 — frontend/index.html (6 new script tags)
Step 18 — git add + commit + push → GitHub Actions → Cloudflare deploy
Step 19 — npx wrangler d1 execute cyberdudebivash-security-hub --file=./workers/schema_phase3.sql
```

### 90-Day Commercial Execution Roadmap

```
MONTH 1: FOUNDATION (Weeks 1-4)
  Week 1: Deploy schema_phase3.sql + customer success backend
  Week 2: Deploy reporting engine (PDF HTML templates)
  Week 3: Deploy global search + workflow automation backend
  Week 4: Deploy white-label config + tenant theme system
  KPI: All 8 backend APIs live, zero regressions

MONTH 2: FRONTEND EXCELLENCE (Weeks 5-8)
  Week 5: Customer Success Command Center frontend
  Week 6: Reporting Center (Board Report, Security Posture templates)
  Week 7: Workflow Builder UI + Growth Analytics dashboard
  Week 8: White-label config UI + Branding controls
  KPI: All 6 frontend modules live, MSSP demo ready

MONTH 3: COMMERCIAL LAUNCH (Weeks 9-12)
  Week 9:  Launch Business Plan ($299/mo) with workflow automation
  Week 10: Launch MSSP Plan ($999/mo) with white-label + customer success
  Week 11: Launch scheduled report delivery (PDF + email)
  Week 12: Launch growth analytics for internal use; MSSP partner program
  KPI: First paying MSSP customer, $10K MRR milestone
```

---

## WORKSTREAM 1: CUSTOMER SUCCESS PLATFORM

### Architecture

**Goal:** Detect churn risk, surface expansion opportunities, and track platform adoption for every org.

**Data Model — `customer_health` table:**
```sql
id, org_id (UNIQUE), health_score (0-100), adoption_score (0-100),
churn_risk (NONE|LOW|MEDIUM|HIGH|CRITICAL), expansion_score (0-100),
maturity_index (STARTER|DEVELOPING|MATURE|CHAMPION),
last_scan_days_ago, total_scans_30d, active_features_json,
risk_triggers_json, playbook_id, computed_at
```

**Health Score Formula:**
- +30 pts: Scan frequency (≥10 scans/month = 30; ≥5 = 20; ≥1 = 10; 0 = 0)
- +20 pts: Feature adoption (each feature used = 4 pts, max 5 features)
- +20 pts: Risk resolution rate (resolved cases / total cases × 20)
- +15 pts: Login recency (active <7d = 15; <30d = 10; <90d = 5)
- +15 pts: Subscription tier (Enterprise = 15; Pro = 10; Free = 0)

**Churn Risk Triggers:**
- No scans in 14+ days → MEDIUM risk
- No scans in 30+ days → HIGH risk
- No login in 30+ days → HIGH risk
- Open CRITICAL case >72h → HIGH risk
- Downgrade event → CRITICAL risk

**APIs:**
- `GET /api/customer-success/health` — own org health (enterprise+)
- `GET /api/customer-success/health/:orgId` — specific org (mssp_admin)
- `GET /api/customer-success/overview` — platform-wide summary (admin)
- `POST /api/customer-success/refresh` — recompute health scores (admin)
- `GET /api/customer-success/playbooks` — available success playbooks

**Playbook Catalog (built-in):**
1. "New Customer Onboarding" — run first scan, set up monitor, enable alerts
2. "Risk Reduction Playbook" — address open CRITICAL findings
3. "Expansion Playbook" — upgrade to next tier when adoption >80%
4. "Win-Back Playbook" — re-engage dormant accounts (no activity 30d+)
5. "Enterprise Readiness" — compliance + AI security assessment completion

---

## WORKSTREAM 2: ENTERPRISE REPORTING ENGINE

### Architecture

**Goal:** Generate board-ready reports from existing platform data, deliverable as HTML (client) or PDF (server-rendered), with scheduling and email delivery.

**Report Types:**
1. **Security Posture Report** — overall risk score, top findings, remediation progress
2. **Board Executive Report** — MRR, ARR, customer count, platform health (1 page)
3. **MSSP Customer Report** — per-tenant risk, case status, SLA compliance
4. **Threat Intelligence Report** — top IOCs, threat actors active this month, CVE summary
5. **Compliance Report** — framework coverage (SOC2/ISO27001/PCI-DSS/HIPAA)
6. **AI Security Report** — AI asset inventory, OWASP LLM findings, red team results

**Data Model — `report_jobs` table:**
```sql
id, type (SECURITY_POSTURE|BOARD|MSSP|CTI|COMPLIANCE|AI_SECURITY),
format (HTML|PDF|JSON), status (QUEUED|GENERATING|READY|FAILED|DELIVERED),
org_id, created_by, config_json (filters, date ranges, logo),
output_r2_key, download_token (KV, TTL 3600s),
scheduled_cron (null = on-demand), last_run_at, delivered_to_emails,
created_at, completed_at
```

**APIs:**
- `GET /api/reports` — list own org report jobs
- `POST /api/reports` — create report job (queued async)
- `GET /api/reports/:id` — job status + download token
- `GET /api/reports/:id/download` — download (token-gated)
- `POST /api/reports/schedule` — create scheduled recurring report
- `GET /api/reports/templates` — list available templates

**PDF Strategy:** HTML report template rendered in Worker as text/html response. For actual PDF: client-side `window.print()` with `@media print` CSS, or trigger browser PDF save. Server-side PDF generation via `jsPDF` or WeasyPrint is out-of-scope for Workers runtime; R2-based PDF storage is used for scheduled/delivered reports.

---

## WORKSTREAM 3: ENTERPRISE SEARCH PLATFORM

### Architecture

**Goal:** Single search box across all platform entities — threats, CVEs, scans, findings, customers, incidents, actors, AI assets.

**Search Scope (D1 LIKE queries, parallel):

| Entity | Table | Fields Searched |
|--------|-------|-----------------|
| IOCs | cti_iocs | value, notes |
| Threat Actors | cti_actors | name, aliases, description |
| SOC Cases | soc_cases | title, summary, case_number |
| MSSP Customers | mssp_customers | org_name, contact_email |
| CVEs | scan_results | cve_ids (JSON) |
| AI Assets | ai_assets | name, description |
| Saved Searches | saved_searches | name, query |

**Faceted search:** `type`, `severity`, `date_range`, `org_id` filters.
**Relevance ranking:** exact match > starts-with > contains. Score applied client-side.
**Saved searches:** stored in `saved_searches` table, accessible from command palette.

**APIs:**
- `GET /api/search?q=&type=&severity=&org_id=` — global search (auth required)
- `POST /api/search/saved` — save a search
- `GET /api/search/saved` — list saved searches
- `DELETE /api/search/saved/:id` — delete saved search

**Data Model — `saved_searches`:**
```sql
id, user_id, org_id, name, query TEXT, facets_json, hit_count, last_run_at, created_at
```

---

## WORKSTREAM 4: WORKFLOW AUTOMATION PLATFORM

### Architecture

**Goal:** Trigger-based security automation — when a scan finds CRITICAL, auto-create SOC case; when case ESCALATED, notify MSSP admin; when customer at churn risk, trigger playbook.

**Trigger Types:**
- `SCAN_CRITICAL` — new critical finding detected
- `CASE_CREATED` — SOC case opened
- `CASE_ESCALATED` — case escalated
- `HEALTH_CHURN` — customer health churn risk HIGH/CRITICAL
- `IOC_MATCH` — IOC matched against watchlist
- `MANUAL` — user-initiated via UI

**Action Types:**
- `CREATE_SOC_CASE` — auto-create case with template
- `SEND_NOTIFICATION` — push via notification platform
- `UPDATE_CASE_STATUS` — change case status
- `ASSIGN_PLAYBOOK` — attach playbook to customer
- `WEBHOOK_CALL` — POST to external URL
- `ESCALATE_CASE` — escalate existing case

**Data Models:**
```sql
-- workflows
id, name, description, trigger_type, trigger_config_json, steps_json (array of actions),
is_active, org_id, created_by, created_at, updated_at, run_count, last_run_at

-- workflow_executions
id, workflow_id, status (RUNNING|COMPLETED|FAILED|CANCELLED),
triggered_by, trigger_payload_json, steps_log_json, error_message,
started_at, completed_at
```

**APIs:**
- `GET /api/workflows` — list workflows
- `POST /api/workflows` — create workflow
- `PATCH /api/workflows/:id` — update/enable/disable
- `DELETE /api/workflows/:id` — delete
- `POST /api/workflows/:id/execute` — manual trigger
- `GET /api/workflows/:id/executions` — execution history
- `GET /api/workflows/templates` — built-in templates

**Built-in Templates (seeded in code, no DB required):**
1. "Critical Finding → Auto Case" — SCAN_CRITICAL → CREATE_SOC_CASE
2. "Escalated Case → MSSP Notify" — CASE_ESCALATED → SEND_NOTIFICATION
3. "Churn Risk → Playbook" — HEALTH_CHURN → ASSIGN_PLAYBOOK
4. "IOC Match → Alert" — IOC_MATCH → SEND_NOTIFICATION + CREATE_SOC_CASE

---

## WORKSTREAM 5: WHITE LABEL MSSP PLATFORM

### Architecture

**Goal:** MSSP admins can brand the platform with their logo, colors, and domain. Tenants see the MSSP's brand, not CYBERDUDEBIVASH®.

**Branding Controls:**
- Primary / secondary color (hex)
- Logo URL (R2 hosted or external CDN)
- Brand name (replaces "CYBERDUDEBIVASH®" in UI)
- Custom CSS snippet (sanitized — color/font rules only)
- Favicon URL
- Custom domain (informational — DNS setup is out of Worker scope)
- Support email / URL

**Data Model — `tenant_themes`:**
```sql
org_id TEXT PRIMARY KEY, brand_name TEXT, logo_url TEXT, favicon_url TEXT,
primary_color TEXT DEFAULT '#6366f1', secondary_color TEXT DEFAULT '#0ea5e9',
accent_color TEXT DEFAULT '#22c55e', custom_css TEXT, custom_domain TEXT,
support_email TEXT, support_url TEXT, hide_powered_by INTEGER DEFAULT 0,
created_at TEXT, updated_at TEXT
```

**APIs:**
- `GET /api/white-label/theme` — get own org theme (any auth)
- `PUT /api/white-label/theme` — update theme (mssp_admin)
- `DELETE /api/white-label/theme` — reset to defaults (mssp_admin)
- `GET /api/white-label/theme/:orgId` — get tenant theme (mssp_admin)

**Frontend application:** At page load, the `white-label-config.js` module checks `/api/white-label/theme` and if a custom theme exists, injects CSS variables into `:root` — overriding `--cdb-primary`, `--cdb-secondary`, and swapping the logo element. This is non-destructive; removing the script reverts to defaults.

---

## WORKSTREAM 6: PRODUCT ANALYTICS & GROWTH

### Architecture

**Goal:** Track feature adoption, conversion funnels, and revenue attribution to inform product and sales decisions.

**Event Schema — `analytics_events`:**
```sql
id, event_type TEXT (whitelisted), user_id, org_id, tier,
properties_json, session_id, ip_country, occurred_at
```

**Tracked Events (server-side, auto-emitted by existing handlers):**
- `scan.completed` — {scan_type, severity_counts, duration_ms}
- `case.created` — {severity, source}
- `case.resolved` — {time_to_resolve_hours}
- `report.generated` — {report_type, format}
- `search.executed` — {query_length, result_count}
- `workflow.executed` — {workflow_id, trigger_type, success}
- `upgrade.viewed` — {from_tier, to_tier}
- `upgrade.converted` — {from_tier, to_tier, mrr_delta}

**Growth KPIs (computed from events + subscriptions):**
- Daily/Weekly/Monthly Active Users (DAU/WAU/MAU)
- Activation Rate (users who ran first scan within 7d of signup)
- Feature Adoption Matrix (% of users using each feature)
- Time-to-Value (days from signup to first scan result)
- Expansion MRR (revenue from tier upgrades)
- Retention Cohorts (% of users active at 7/30/90 days)
- Conversion Funnel: Signup → First Scan → Paid → Enterprise

**APIs:**
- `POST /api/analytics/p3/event` — ingest event (auth required)
- `GET /api/analytics/p3/growth` — growth KPIs (admin)
- `GET /api/analytics/p3/funnel` — conversion funnel (admin)
- `GET /api/analytics/p3/adoption` — feature adoption matrix (admin)
- `GET /api/analytics/p3/cohorts` — retention cohorts (admin)

---

## WORKSTREAM 7: ENTERPRISE NOTIFICATION PLATFORM

### Architecture

**Goal:** Unified delivery of security alerts, workflow triggers, and system events across in-app, email, Slack, Teams, and webhook channels.

**Data Models:**
```sql
-- notification_preferences (per user)
user_id TEXT PRIMARY KEY, email_enabled INTEGER DEFAULT 1,
inapp_enabled INTEGER DEFAULT 1, slack_webhook TEXT,
teams_webhook TEXT, custom_webhook TEXT,
event_subscriptions_json (event types to receive),
escalation_delay_minutes INTEGER DEFAULT 30,
quiet_hours_json, updated_at

-- notification_log
id, recipient_id, org_id, channel (EMAIL|INAPP|SLACK|TEAMS|WEBHOOK),
event_type, subject, body_preview, status (SENT|FAILED|PENDING),
delivery_attempts INTEGER DEFAULT 0, error_message, sent_at, created_at
```

**Delivery Channels:**
- **In-app:** Pushed to Phase 2 notification center (`window.CDB_UX.addNotification`)
- **Email:** Via existing email engine (`emailEngine.js` — already in codebase)
- **Slack:** HTTP POST to user's Slack incoming webhook URL
- **Teams:** HTTP POST to Teams webhook URL
- **Webhook:** HTTP POST with HMAC-SHA256 signature

**APIs:**
- `GET /api/notifications/preferences` — get own preferences
- `PUT /api/notifications/preferences` — update preferences
- `GET /api/notifications/log` — delivery history (own user)
- `POST /api/notifications/test` — send test notification
- `POST /api/notifications/send` — internal/admin send (admin only)

---

## WORKSTREAM 8: PLATFORM RELIABILITY ENGINEERING

### Architecture

**Goal:** SLA tracking, error budgets, latency monitoring, and capacity planning — surface reliability posture in a dedicated dashboard.

**SLA Targets:**
| Service | Availability Target | Latency P99 Target |
|---------|--------------------|--------------------|
| Scan API | 99.9% | <3000ms |
| Auth API | 99.95% | <500ms |
| Dashboard SSE | 99.5% | <1000ms |
| D1 Database | 99.9% | <200ms |
| KV Cache | 99.99% | <50ms |
| R2 Storage | 99.9% | <500ms |

**Error Budget:** For 99.9% SLA → 43.8 minutes downtime allowed per month. Error budget consumed = (1 - measured_availability) × month_minutes. Alert when error budget >50% consumed.

**Reliability Metrics (computed from deep health probe history):**
- 30-day rolling availability per service
- P50/P95/P99 latency by endpoint
- Error rate (4xx/5xx) by route group
- Dependency health score
- Capacity utilization (D1 rows, KV size, R2 objects)

**APIs:**
- `GET /api/reliability/sla` — SLA report (enterprise+)
- `GET /api/reliability/error-budget` — error budget consumption (admin)
- `GET /api/reliability/capacity` — capacity metrics (admin)
- `GET /api/reliability/incidents` — reliability incident history (enterprise+)
- `POST /api/reliability/incident` — report reliability incident (admin)

**Data source:** Phase 2 `/api/platform/health/deep` is the probe source. Phase 3 Reliability engine aggregates probe results over time and computes SLA metrics. Probe history is stored in KV ring buffer (rolling 30-day window in compressed JSON).

---

## WORKSTREAM 9: ENTERPRISE SECURITY HARDENING

### Security Assessment

**Current Posture (v32.0 baseline):**

| Domain | Status | Finding |
|--------|--------|---------|
| Authentication | STRONG | JWT RS256 + API key dual-auth |
| Authorization | STRONG | Role-based, checked per handler |
| Tenant Isolation | GOOD | Virtual tenancy via org_id — no physical isolation |
| Input Validation | MODERATE | Most handlers validate; some use raw URL params |
| SQL Injection | LOW RISK | D1 parameterized queries used; no string interpolation found |
| Secrets Management | GOOD | All secrets in Worker env bindings; none in code |
| CORS | GOOD | withCors() applied consistently |
| Security Headers | GOOD | withSecurityHeaders() on all routes |
| Rate Limiting | PARTIAL | Gateway ceiling applied; per-endpoint limits inconsistent |
| Supply Chain | GOOD | Minimal external dependencies; uses CF built-ins |
| Logging / Audit | PARTIAL | Events tracked; no immutable audit log |
| API Key Entropy | GOOD | `cdb_` prefix + 32-char random |

### Hardening Roadmap

**Priority 1 (Immediate):**
- Standardize rate limiting to 60 req/min per IP on all unauthenticated endpoints
- Add `Content-Security-Policy` header (currently absent from withSecurityHeaders)
- Add immutable audit log table (`audit_log`) for privilege-sensitive operations

**Priority 2 (Month 1):**
- Add HMAC-signed webhook payload verification in Phase 3 notification platform
- Input sanitization middleware for all search/filter query params
- Add `X-Request-ID` header for request tracing

**Priority 3 (Month 2):**
- Move to physical D1 database per enterprise customer (currently cost-prohibitive; flag for v2)
- Implement refresh token rotation (currently refresh tokens are long-lived)
- Add anomaly detection on API key usage (flag >1000 req/hr)

### Risk Register

| Risk ID | Risk | Likelihood | Impact | Mitigation |
|---------|------|-----------|--------|------------|
| R-001 | Tenant data leakage via org_id bypass | LOW | CRITICAL | org_id always from JWT (not URL) |
| R-002 | D1 row limit reached (analytics_events) | MEDIUM | HIGH | 90-day pruning cron |
| R-003 | Worker CPU limit exceeded (complex search) | LOW | MEDIUM | Search limited to 500ms timeout |
| R-004 | Compromised API key mass scan | MEDIUM | HIGH | Rate limit + anomaly detection |
| R-005 | Webhook SSRF via custom webhook URL | LOW | HIGH | URL validation: no private IPs |
| R-006 | Report download token theft | LOW | MEDIUM | 1-hour TTL + single-use KV token |
| R-007 | Custom CSS injection via white-label | LOW | MEDIUM | Server-side CSS sanitization |
| R-008 | Worker cold start latency spike | LOW | LOW | KV warmup on cron; keep-alive SSE |

---

## WORKSTREAM 10: COMMERCIAL PLATFORM PACKAGING

### Packaging Model

| Plan | Price | Target | Key Features |
|------|-------|--------|-------------|
| **Starter** | Free | Indie devs, students | 10 scans/mo, basic reports, 1 user |
| **Professional** | $49/mo | Security engineers | 100 scans/mo, all scan types, API access, PDF reports |
| **Business** | $299/mo | Security teams | Unlimited scans, SOC cases, CTI workbench, workflows, 10 users |
| **Enterprise** | $999/mo | Enterprise orgs | All Business + white-label, SSO, custom contracts, SLA guarantee, dedicated support |
| **MSSP** | $2,499/mo | MSSPs, resellers | All Enterprise + multi-tenant, customer portals, revenue share, 100 managed orgs |

### Monetization Framework

**Primary Revenue Streams:**
1. **Subscription MRR** — recurring plan revenue
2. **Assessment Revenue** — $999-$4,999 per assessment engagement
3. **MSSP Revenue Share** — 15% of MSSP customer billing passed upward
4. **API Usage** — $0.001/API call above plan limits (metered billing via Stripe)
5. **Report Credits** — 10 free PDF reports/mo; $5 per additional report

**Key Unit Economics:**
- CAC target: <$200 (self-serve PLG model)
- LTV target: $2,400 (Pro, 12-month average)
- Gross Margin target: >85% (SaaS)
- Payback Period target: <6 months

### Revenue Expansion Strategy

**Product-Led Growth (PLG) Levers:**
1. **Viral scan sharing** — share scan results URL (branded) → drives organic signups
2. **Free public trust badge** — embed "Scanned by CDB" badge → backlinks + leads
3. **Assessment marketplace** — enterprise teams post RFPs; CDB matches with assessors
4. **MSSP partner program** — resellers get 30% rev share + co-branded portal
5. **API-first expansion** — expose scan API to developer tools (GitHub Actions, IDE plugins)

**Upsell Triggers (automated via workflow automation):**
- 80%+ of monthly quota used → upgrade prompt
- Team size >5 users → upgrade to next tier
- First CRITICAL finding → "Professional remediation" upsell
- MSSP prospect visit → schedule assessment flow
- 90 days on same plan + growing usage → expansion outreach

**Cross-Sell Strategy:**
- Domain scan complete → upsell AI security assessment
- AI asset registered → upsell red team engagement
- Red team report → upsell continuous monitoring
- Monitoring active → upsell MSSP plan (bring more customers)

---

## IMPLEMENTATION AUTHORIZATION

All 5 pre-implementation reviews are complete. Authorization to proceed:

- ✅ Architecture Review — Additive-only, namespaced, isolated
- ✅ Security Review — RBAC enforced, tenant isolation verified, threat model complete
- ✅ Scalability Review — D1 limits managed, KV cache strategy defined
- ✅ Rollback Review — Zero-risk rollback at every layer
- ✅ Implementation Roadmap — 19-step deployment order, 90-day commercial roadmap

**Implementation begins now. Zero regressions permitted.**
