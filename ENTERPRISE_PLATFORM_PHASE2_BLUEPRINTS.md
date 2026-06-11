# CYBERDUDEBIVASH® AI Security Hub
## Enterprise Platform Phase 2 — Architecture Blueprints
**Version:** 2.0 | **Date:** 2026-06-11 | **Classification:** INTERNAL — PRINCIPAL ARCHITECTS

---

# BLUEPRINT 1 — ENTERPRISE ARCHITECTURE

## Platform Target State
```
CYBERDUDEBIVASH® Enterprise Security Operating System
┌─────────────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER (Cloudflare Pages CDN)                       │
│  index.html + dashboard-live.js [Phase 1]                        │
│  enterprise-ux.js · revenue-center.js · mssp-workspace.js       │
│  soc-investigations.js · cti-workbench.js · platform-health.js  │
├─────────────────────────────────────────────────────────────────┤
│  API GATEWAY LAYER (Cloudflare Workers — single worker)          │
│  488 existing routes [Phase 1 preserved]                         │
│  + 25 new Phase 2 routes                                         │
├─────────────────────────────────────────────────────────────────┤
│  DOMAIN SERVICES (handlers/ — additive only)                     │
│  Existing: Sentinel APEX · MYTHOS · CRM · Revenue · Auth        │
│  Phase 2:  revenueMetrics · msspWorkspace · socCases            │
│            ctiWorkbench · deepHealth                             │
├─────────────────────────────────────────────────────────────────┤
│  INFRASTRUCTURE (Cloudflare Primitives — unchanged)              │
│  D1 (schema_phase2.sql adds 5 tables, no existing table changes) │
│  KV · R2 · Queues · Workers AI · Cron Triggers                  │
└─────────────────────────────────────────────────────────────────┘
```

## Non-Negotiable Constraints
- All Phase 1 code: READ-ONLY (extend via new files, not edits)
- All existing D1 tables: READ-ONLY (additive tables only)
- All existing API routes: READ-ONLY (new routes only)
- All existing auth/RBAC: READ-ONLY (new role: `mssp_admin`)
- All existing payment flows: READ-ONLY

## New Role Model (additive)
```
Existing: FREE → PRO → ENTERPRISE → admin
Phase 2 adds: mssp_admin (superset of enterprise, sees all tenants)
              tenant_admin (enterprise scoped to own org_id)
```

---

# BLUEPRINT 2 — MSSP ARCHITECTURE

## Multi-Tenant Model
```
Virtual Tenancy via D1 + JWT claims (no separate workers per tenant)

mssp_customers table
  id (UUID) · org_name · contact_email · tier · risk_score
  created_at · last_seen · status · config_json

Tenant isolation:
  All existing scans have user_id — group by mssp_customer.assigned_user_ids
  New queries: WHERE org_id = ? (from JWT claim)
  Existing data: retroactively assigned to default "unassigned" tenant
```

## RBAC Model
```
mssp_admin  → sees all tenants, all metrics, all data
tenant_admin → sees own org only (org_id scoped)
enterprise  → own account only (unchanged)
```

## API Contracts (Phase 2)
```
GET  /api/mssp/customers              → customer list (mssp_admin)
POST /api/mssp/customers              → create customer
GET  /api/mssp/customers/:id/metrics  → per-customer KPIs
GET  /api/mssp/customers/:id/scans    → per-customer scan history
GET  /api/mssp/customers/:id/risk     → per-customer risk posture
PUT  /api/mssp/customers/:id          → update customer profile
GET  /api/mssp/overview               → aggregate MSSP dashboard
```

## Customer Workspace UX
```
Nav → MSSP → [All Customers] [Customer Switcher▼]
                    ↓
  Customer Card Grid: Name | Risk | Tier | Last Scan | Status
                    ↓
  Click customer → Customer Detail Workspace:
    Overview | Scans | CVEs | Compliance | Billing | Notes
```

## White-Label Readiness
- `config_json` on mssp_customers stores: logo_url, brand_color, report_prefix
- `/api/mssp/customers/:id/report` generates white-labeled PDF report
- Frontend reads config and applies per-customer styling to report views

---

# BLUEPRINT 3 — SOC PLATFORM BLUEPRINT

## Case Lifecycle
```
Alert → Triage → Investigation → Escalation → Resolution → Closed
  ↑         ↑           ↑              ↑             ↑
 Auto     Manual     Analyst        Senior          SOC Lead
trigger  creation   workspace        escalate       sign-off
```

## Data Model
```sql
soc_cases:
  id UUID PK · case_number TEXT UNIQUE · title TEXT
  severity TEXT CHECK(CRITICAL|HIGH|MEDIUM|LOW|INFO)
  status TEXT CHECK(OPEN|IN_PROGRESS|ESCALATED|RESOLVED|CLOSED)
  assignee_id TEXT · org_id TEXT · source TEXT
  alert_ids TEXT(JSON) · ioc_list TEXT(JSON)
  mitre_tactics TEXT(JSON) · playbook_id TEXT
  created_at · updated_at · resolved_at · sla_due_at

soc_case_comments:
  id UUID · case_id FK · author_id · body TEXT
  visibility TEXT(INTERNAL|EXTERNAL) · created_at
```

## API Contracts
```
GET    /api/soc/cases                → list (paginated, filterable)
POST   /api/soc/cases                → create case from alert
GET    /api/soc/cases/:id            → full case detail + timeline
PATCH  /api/soc/cases/:id            → update status/assignee/severity
POST   /api/soc/cases/:id/comments   → add investigation note
GET    /api/soc/cases/:id/timeline   → chronological event stream
GET    /api/soc/cases/metrics        → open/resolved/MTTR/SLA stats
```

## MITRE Mapping
- Cases store `mitre_tactics` JSON array: `["T1190","T1059","T1078"]`
- Display as MITRE Navigator heatmap overlay in SOC panel
- Tactic coverage % derived from all open cases (last 30 days)

## Playbooks
- Stored as static JSON in KV: `PLAYBOOK_<id>`
- Referenced by case's `playbook_id`
- Phase 2 ships 5 default playbooks: RansomwareResponse, PhishingTriage, CVEExploitation, InsiderThreat, SupplyChainCompromise

---

# BLUEPRINT 4 — CTI PLATFORM BLUEPRINT

## CTI Architecture
```
Intel Collection → Normalization → Enrichment → Storage → Distribution
     ↑                                              ↓
Sentinel APEX feed                          cti_actors / cti_iocs
Global Threat Feed                               ↓
Manual submissions                     /api/cti/* endpoints
                                              ↓
                                    CTI Workbench (frontend)
```

## Data Model
```sql
cti_actors:
  id UUID · name TEXT · aliases TEXT(JSON) · nation_state TEXT
  motivation TEXT · sophistication TEXT · active_since TEXT
  known_techniques TEXT(JSON) · known_tools TEXT(JSON)
  target_sectors TEXT(JSON) · description TEXT
  mitre_group_id TEXT · last_active · confidence_score

cti_iocs:
  id UUID · type TEXT(IP|DOMAIN|HASH|URL|EMAIL|CVE)
  value TEXT · severity TEXT · source TEXT
  first_seen · last_seen · tags TEXT(JSON)
  related_actor_id FK · related_campaign TEXT
  whois_data TEXT · geo_data TEXT · reputation_score
```

## API Contracts
```
GET  /api/cti/actors              → threat actor list
GET  /api/cti/actors/:id          → actor profile + TTPs
GET  /api/cti/ioc/search?q=&type= → IOC lookup + enrichment
POST /api/cti/ioc                 → submit IOC
GET  /api/cti/collections         → intel collection list
GET  /api/cti/watchlist           → active watchlist
POST /api/cti/watchlist           → add to watchlist
GET  /api/cti/stix/:id            → export in STIX 2.1 format
```

## Intel Sources (read from existing infrastructure)
- Sentinel APEX KV feed → seed `cti_iocs` on first query
- Global Threat Feed → enrichment data
- MITRE ATT&CK JSON (static, bundled in Worker KV)

---

# BLUEPRINT 5 — AI SECURITY BLUEPRINT

## Extended AI Security Architecture (Phase 2 additions)
```
Existing (Phase 1): /api/ai-security/dashboard · asset registry · governance

Phase 2 adds:
  /api/ai-security/agents          → AI agent inventory
  /api/ai-security/mcp-inventory   → MCP server registry
  /api/ai-security/prompt-monitor  → prompt injection detection log
  /api/ai-security/attack-sim      → AI attack simulation runner
  /api/ai-security/risk-forecast   → 30-day AI risk projection
```

## Agent Inventory Model
```
AI agents tracked in KV: AI_AGENT_<id>
  id · name · type(LLM|AGENT|RAG|MULTIMODAL)
  provider · model_id · deployment_env
  access_level · tool_permissions TEXT(JSON)
  last_scan_at · risk_score · owasp_findings TEXT(JSON)
```

## MCP Inventory
```
MCP servers tracked in KV: MCP_SERVER_<id>
  id · name · endpoint · capabilities TEXT(JSON)
  auth_method · exposed_tools TEXT(JSON)
  risk_level · last_assessed · assessment_findings
```

## OWASP LLM Risk Scoring
```
10 OWASP LLM risks → weighted score per AI asset
Risk weights: LLM01(20) LLM02(15) LLM03(10) LLM04(5) LLM05(10)
              LLM06(15) LLM07(5)  LLM08(10) LLM09(5) LLM10(5)
Overall risk = Σ(weight × detected_severity_multiplier) / 100
```

## Compliance Frameworks
```
EU AI Act: HIGH_RISK | LIMITED_RISK | MINIMAL_RISK classification
NIST AI RMF: GOVERN · MAP · MEASURE · MANAGE assessment status
ISO 42001: Gap analysis vs 38 control requirements
```

---

# BLUEPRINT 6 — EXECUTIVE DASHBOARD BLUEPRINT

## Revenue Metrics Architecture
```
Data sources (existing D1 tables, read-only):
  subscriptions → MRR/ARR/churn
  payments       → cash collected, ARPU
  users          → total accounts, conversion funnel
  assessments    → pipeline value, booking rate
  audit_events   → feature adoption, engagement

Computed KPIs:
  MRR  = SUM(active subscriptions × monthly_price)
  ARR  = MRR × 12
  NRR  = (MRR_end - MRR_start + expansion) / MRR_start × 100
  LTV  = ARPU × avg_lifetime_months
  CAC  = (marketing_spend) / new_customers_this_month
  Rule of 40 = ARR_growth_rate + profit_margin
```

## API Contract
```
GET /api/revenue/metrics → {
  mrr, arr, nrr, arpu, ltv_estimate,
  active_subscribers, new_this_month, churned_this_month,
  free_users, pro_users, enterprise_users,
  conversion_rate_free_to_pro, conversion_rate_pro_to_enterprise,
  pipeline_value, assessments_booked, assessments_completed,
  mrr_trend: [{month, mrr}] (12 months),
  subscriber_trend: [{month, count}] (12 months)
}
```

## SVG Chart Strategy
- MRR trend: SVG polyline (no library, 200×60 sparkline)
- Subscriber growth: SVG bar chart (200×60)
- Conversion funnel: SVG horizontal bars
- Plan distribution: SVG donut (CSS clip-path)

---

# BLUEPRINT 7 — UX SYSTEM BLUEPRINT

## Command Palette (Cmd+K / Ctrl+K)
```
Overlay: backdrop-blur + dark panel
Search input → debounced 200ms

Result categories:
  → Navigation   (go to Executive, SOC, Sentinel, etc.)
  → Quick Scan   (scan a domain/URL/IP right now)
  → Recent Scans (from API cache)
  → CVE Search   (search cached CVE data)
  → SOC Cases    (open/in-progress cases)
  → API Docs     (link to /api/docs)

Keyboard nav: ↑↓ arrows, Enter to select, Esc to close
```

## Global Keyboard Shortcuts
```
Cmd/Ctrl+K      → Open command palette
Cmd/Ctrl+/      → Open keyboard shortcut reference
g then d        → Go to dashboard
g then s        → Go to scanner
g then e        → Go to Executive Command Center
g then c        → Go to SOC Command Center
g then t        → Go to CTI Workbench
g then h        → Go to Observability
Esc             → Close any overlay
```

## Notification Center
```
Bell icon in nav → slide-in panel (right side)
  Recent alerts from SSE stream (last 20)
  Unread count badge
  Mark all read
  Click alert → go to relevant section
  Alert types: cve_alert | scan_complete | case_update | health_alert
```

## Toast System
```
Position: bottom-right
Duration: 4s (auto-dismiss)
Types: success(green) | warning(amber) | error(red) | info(blue)
Stacking: up to 3 visible, queue overflow
```

## Dark/Light Mode
```
CSS custom properties on :root → toggle via data-theme attribute
All existing colors use --bg-* / --text-* / --border-* variables
Toggle persists to localStorage key 'cdb-theme'
```

## Navigation Enhancement
```
Existing nav preserved.
Phase 2 adds:
  [⚔ Command Centers ▼] dropdown in nav
    → Executive
    → SOC Operations
    → Sentinel APEX
    → AI SecOps
    → MSSP
    → Revenue
    → CTI Workbench
    → Observability
  [🔔] notification bell (unread count badge)
  [⌘K] command palette trigger
```

## Accessibility
```
All overlays: role="dialog" aria-modal="true"
All modals: focus-trapped, Esc closes
All interactive elements: keyboard-accessible
Color contrast: WCAG AA minimum
Screen reader: aria-live regions for alerts/counts
```

---

# BLUEPRINT 8 — COMMERCIALIZATION BLUEPRINT

## Product-Led Growth Model
```
FREE tier → frictionless onboarding (no credit card)
   ↓ usage signals
PRO trigger: 3+ scans in 7 days OR hits scan limit
   ↓ conversion event
ENTERPRISE trigger: team > 1 OR API volume > 1000/month
   ↓ expansion event
MSSP trigger: multiple client management request
```

## Customer Health Score
```
Score 0-100 = weighted composite:
  Scan frequency (30%) — scans per week vs plan average
  Feature breadth (25%) — unique features used / total
  API usage (20%)       — API calls vs plan limit
  Support tickets (15%) — inverse: more tickets = lower
  Login frequency (10%) — DAU/MAU ratio

Health bands:
  80-100 → HEALTHY (expansion opportunity)
  60-79  → STABLE
  40-59  → AT RISK (intervention needed)
  0-39   → CHURN RISK (immediate outreach)
```

## Upsell Engine
```
Trigger conditions → Upsell action:
  scan_limit_80pct_used → banner: "Upgrade for unlimited scans"
  critical_cve_found    → tooltip: "Pro gets CVE remediation guides"
  team_invite_attempted → modal: "Upgrade to Enterprise for teams"
  api_key_created       → banner: "API rate limit: upgrade for higher limits"
  assessment_viewed     → CTA: "Book a real assessment"
```

## Usage Analytics API
```
GET /api/analytics/usage        → feature usage heatmap
GET /api/analytics/funnel       → conversion funnel stages
GET /api/analytics/cohorts      → monthly cohort retention
GET /api/analytics/health-score → customer health by account
```
Note: All analytics derive from existing audit_events table in D1.

---

# BLUEPRINT 9 — PRODUCTION HARDENING BLUEPRINT

## Error Boundary Strategy
```javascript
// Frontend: every async operation wrapped
async function safeLoad(fn, fallback = null) {
  try { return await fn(); }
  catch (e) { console.info('[CDB]', e.message); return fallback; }
}

// Worker: every handler wrapped at route level
try { return await handler(request, env, authCtx); }
catch (e) { return errorResponse(500, e.message, request); }
```

## Retry Architecture
```
Frontend fetches:
  AbortSignal.timeout(8000) — already in Phase 1
  Phase 2: exponential retry for non-SSE requests
  Retry: 3 attempts, delays: 0ms, 1000ms, 3000ms
  Conditions: retry on 5xx, network error; no retry on 4xx

SSE:
  Exponential backoff: 1s→2s→4s→max 30s — already in Phase 1
```

## Caching Strategy
```
KV cache TTLs (Phase 2 additions):
  revenue metrics   → 300s (5 min) — slow-moving data
  customer metrics  → 120s (2 min)
  deep health       → 30s           — fast needed
  cti actors list   → 900s (15 min) — rarely changes
  IOC enrichment    → 3600s (1h)    — stable data

Frontend cache (PlatformDataBus):
  Phase 1: already implements stale-while-revalidate
  Phase 2: no changes needed
```

## API Protection (additive)
```
Phase 2 endpoints:
  All POST routes: validateContentType('application/json')
  All admin routes: requireRole(['admin', 'mssp_admin'])
  All MSSP routes: validateOrgAccess(authCtx, orgId)
  Revenue metrics: requireRole(['admin', 'mssp_admin', 'enterprise'])
  SOC cases: requireAuth() — any authenticated user
  CTI workbench: requireAuth() with tier >= PRO
```

## Memory Management (Frontend)
```
Command palette: destroy DOM on close, rebuild on open
Notification center: cap at 50 items in memory (FIFO)
SSE events: ring buffer max 100 events
Feed lists: DOM virtualization for >50 items (IntersectionObserver)
Polling intervals: clearInterval on page unload
```

## Frontend Resilience
```
Offline detection: navigator.onLine + 'offline' event
  → Show "Offline — data may be stale" banner
  → Pause polling (no failed requests)
  → Resume + refresh on 'online' event

Visibility API: document.visibilitychange
  → Pause polling when tab hidden
  → Resume + immediate refresh when tab visible
  → Avoids wasted requests on background tabs
```

---

# BLUEPRINT 10 — 90-DAY EXECUTION ROADMAP

## Competitive Positioning
```
Platform           Strengths we match          Gaps we fill
CrowdStrike Falcon Endpoint XDR               AI-native, no agent needed
MS Defender XDR    SIEM integration            Cloudflare-native, faster
Palo Alto Cortex   AI analytics               API-first, developer-friendly
Datadog            Observability UX           Security-focused, not generic
Splunk ES          SOC workflow depth         Modern UX, no heavy infra
CF Security Center CF-native                  Full security platform, not infra
```

## 90-Day Roadmap

### Days 1-30: Foundation (Phase 2 — THIS SPRINT)
- [ ] Ship all Phase 2 blueprints ← THIS FILE
- [ ] Ship 5 new worker handlers
- [ ] Ship 6 new frontend modules
- [ ] Ship D1 schema_phase2.sql migration
- [ ] Command palette live
- [ ] Revenue dashboard live
- [ ] MSSP workspace live
- [ ] SOC cases live
- [ ] CTI workbench live
- [ ] Platform health live

### Days 31-60: Depth
- [ ] Real payment data wired to revenue dashboard (from existing Stripe/Razorpay data)
- [ ] White-label MSSP report generation (PDF via existing pdf skill)
- [ ] SOC playbook editor
- [ ] MITRE Navigator heatmap (interactive)
- [ ] CTI STIX export
- [ ] Customer health scoring engine
- [ ] Upsell trigger engine live
- [ ] AI attack simulation expanded

### Days 61-90: Scale
- [ ] Multi-tenant SSE (per-org SSE streams)
- [ ] SOAR integration (Webhook-based playbook execution)
- [ ] TAXII 2.1 server for CTI sharing
- [ ] Executive QBR report auto-generation
- [ ] Mobile-responsive command centers
- [ ] Accessibility audit + fixes

## Enterprise Packaging
```
STARTER   ($0/mo)    → Scanner only, 10 scans/day, public CVE feed
PRO       ($49/mo)   → All scanners, API access, CVE alerts, SOC view (read)
ENTERPRISE($299/mo)  → Full platform, SOC cases, CTI workbench, AI SecOps
MSSP      ($999/mo)  → Everything + multi-tenant, white-label, custom reports
CUSTOM    (negotiate)→ On-prem deployment, dedicated support, SLA
```

---

*All 10 blueprints complete. Implementation authorized. Zero regressions mandate confirmed.*
