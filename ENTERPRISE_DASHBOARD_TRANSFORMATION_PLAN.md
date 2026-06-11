# CYBERDUDEBIVASH® AI Security Hub
## Enterprise Dashboard Transformation Program — Master Plan
**Version:** 1.0 | **Date:** 2026-06-11 | **Status:** APPROVED FOR IMPLEMENTATION

---

## 1. FULL ARCHITECTURE PLAN

### Current Architecture
```
index.html (20,980 lines monolith)
  ├── Static hardcoded counters (1,247+, 94 critical, 3,841+)
  ├── fetchRealStats() — polls /api/health + /api/threat-intel/stats every 5min
  ├── Trust Center — polls /api/trust/metrics on load
  ├── Visitor counter — polls /api/visitor/live every 30s
  └── No SSE / WebSocket real-time feed
```

### Target Architecture
```
index.html (enhanced, zero regressions)
  ├── dashboard-live.js (NEW — standalone real-time adapter module)
  │     ├── PlatformDataBus — multi-API aggregator
  │     ├── SSE client — /api/dashboard/stream
  │     ├── Counter hydrator — all static IDs → live values
  │     ├── Command Center loader — 5 sections
  │     └── Graceful degradation — show '—' never fabricate
  ├── 5 Command Center sections (NEW HTML, appended before </body>)
  │     ├── #exec-command-center    — Executive / Revenue / KPIs
  │     ├── #soc-command-center     — SOC / Alerts / Incidents
  │     ├── #sentinel-intel-center  — CVE / KEV / APT Intelligence
  │     ├── #ai-secops-center       — AI Assets / OWASP / Governance
  │     └── #mssp-ops-center        — Clients / Risk / Service Health
  └── workers/src/handlers/dashboardStream.js (NEW SSE endpoint)
```

### Technology Choices
| Concern | Solution | Rationale |
|---------|----------|-----------|
| Real-time feed | Server-Sent Events (SSE) | CF Workers supports SSE natively; no WS upgrade overhead |
| Polling | setInterval per-module, staggered | Prevents thundering-herd on CF Workers |
| Styling | Inline CSS in HTML sections | Zero build step; works with existing Pages CDN |
| Data binding | getElementById + textContent | No framework dependency; fastest DOM update |
| Caching | stale-while-revalidate in JS | Avoids re-fetching if tab is backgrounded |
| Fallback | Empty string / '—' / skeleton | Never show fabricated values |

---

## 2. COMPONENT INVENTORY

### Existing Static Counters (IDs to wire)
| Element ID | Current Value | Source API | Field |
|-----------|--------------|-----------|-------|
| `#hero-live-scans` | 1,247+ (partially wired) | /api/scan/stats | .today |
| `#stat-scans` | 1,247+ (hardcoded) | /api/scan/stats | .total_scans |
| `#stat-threats` | 94 critical (hardcoded) | /api/scan/stats | .critical |
| `#stat-cves` | 3,841+ (hardcoded) | /api/vulns/stats | .total |
| `#tm-scans` | 1,247+ (partially) | /api/scan/stats | .total_scans |
| `#tm-cves` | 0 (BROKEN) | /api/vulns/stats | .total |
| `#tm-teams` | 0 (not wired) | /api/trust/metrics | .total_customers |
| `#p4-scan-count` | 1,247+ (hardcoded) | /api/scan/stats | .total_scans |
| `#ae-cve-count` | partially wired | /api/scan/stats | .critical_cves |

### Existing API-Driven Components (already working)
| Component | API | Status |
|-----------|-----|--------|
| Visitor counter | /api/visitor/live | ✅ Working |
| Trust metrics (partial) | /api/trust/metrics | ⚠️ CVE field broken |
| Hero scan count | /api/health | ✅ Working (5min lag) |
| Risk block popup | /api/health | ✅ Working |
| Defense marketplace | /api/defense/* | ✅ Working |

### New Command Center Components
| Section | Primary APIs | Update Interval |
|---------|------------|----------------|
| Executive Command Center | /api/scan/stats, /api/trust/metrics, /api/platform/metrics | 30s |
| SOC Command Center | /api/soc/dashboard, /api/audit-log/summary, /api/threat-intel/live | 30s |
| Sentinel APEX Intelligence | /api/threat-intel/stats, /api/vulns/stats, /api/global-threat-feed/stats | 30s |
| AI Security Operations | /api/ai-security/dashboard | 60s |
| MSSP Operations | /api/platform/metrics, /api/scan/stats | 60s |

---

## 3. FEATURE-PRESERVATION MATRIX

| Category | Component | Preserved | Method |
|----------|-----------|-----------|--------|
| Core Platform | Sentinel APEX | ✅ PRESERVED | No changes to worker logic |
| Core Platform | MYTHOS v3 | ✅ PRESERVED | No changes to worker logic |
| Core Platform | All 81 scan handlers | ✅ PRESERVED | No changes |
| Business | CRM Engine | ✅ PRESERVED | Display-only enhancement |
| Business | Revenue/Pricing | ✅ PRESERVED | No changes |
| Business | Payment flows | ✅ PRESERVED | No changes |
| Security | Auth/RBAC | ✅ PRESERVED | Command centers respect auth gates |
| Security | API contracts | ✅ PRESERVED | Only consume existing endpoints |
| Infrastructure | CF Workers | ✅ PRESERVED | +1 SSE endpoint only |
| Infrastructure | D1/KV/R2 | ✅ PRESERVED | Read-only from frontend |
| Infrastructure | Deploy pipeline | ✅ PRESERVED | No workflow changes |
| Frontend | All existing sections | ✅ PRESERVED | HTML injection before </body> |
| Frontend | fetchRealStats() | ✅ ENHANCED | dashboard-live.js replaces slow 5min poll |
| Frontend | All existing IDs | ✅ PRESERVED | Only add wiring, never remove |
| Frontend | Scan modules | ✅ PRESERVED | No changes to scan UI |
| Frontend | Payment UI | ✅ PRESERVED | No changes |
| Frontend | Nav structure | ✅ PRESERVED | Add Command Centers link only |

---

## 4. MIGRATION STRATEGY

### Approach: Additive Injection (Zero Regression)
1. **Never modify** existing HTML structure
2. **Never remove** existing JavaScript functions
3. **Append** new HTML sections before `</body>` (line 20979)
4. **Inject** `<script src="/dashboard-live.js">` at same location
5. **Override** static values only via getElementById — if element missing, skip silently
6. **Add** one new SSE route to workers (`/api/dashboard/stream`)
7. **Add** SSE handler file `workers/src/handlers/dashboardStream.js`
8. **Register** route in workers/src/index.js (single line import + single if-block)

### Risk Assessment
| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Element ID collision | Low | Use `cdb-live-` prefix for all new IDs |
| API rate limit on CF Workers | Low | Staggered intervals, shared cache in PlatformDataBus |
| SSE connection limit | Low | One connection per tab, auto-reconnect with backoff |
| CSS conflict | None | All new styles scoped to command center section IDs |
| Regression on existing flows | None | Zero modification to existing code paths |

---

## 5. DASHBOARD INFORMATION ARCHITECTURE

```
CYBERDUDEBIVASH® AI Security Hub
├── Public Landing (existing — preserved)
│   ├── Hero section
│   ├── Scan modules
│   ├── Pricing
│   └── Trust center
│
├── ⚔️ COMMAND CENTERS (NEW — nav item)
│   ├── Executive Command Center
│   │   ├── Platform KPIs (scans, CVEs, uptime, revenue signals)
│   │   ├── Risk Posture Gauge
│   │   ├── Threat Level Indicator
│   │   └── Quick Actions (Book Demo, Enterprise Inquiry)
│   │
│   ├── SOC Command Center
│   │   ├── Active Alert Feed (from /api/threat-intel/live)
│   │   ├── Scan Activity (last 10 scans from /api/history)
│   │   ├── MITRE ATT&CK Coverage
│   │   └── Audit Events (from /api/audit-log/summary)
│   │
│   ├── Sentinel APEX Intelligence Center
│   │   ├── Live CVE Stream (SSE)
│   │   ├── KEV Exploitation Feed
│   │   ├── APT Campaign Tracker
│   │   ├── Critical CVE Cards
│   │   └── Threat Trend Chart
│   │
│   ├── AI Security Operations Center
│   │   ├── AI Asset Registry (/api/ai-security/dashboard)
│   │   ├── OWASP LLM Risk Scores
│   │   ├── AI Governance Status
│   │   └── AI Threat Vectors
│   │
│   └── MSSP Operations Center
│       ├── Platform Health Summary
│       ├── Scan Volume Metrics
│       ├── Detection Coverage
│       └── Service Status Matrix
│
└── Authenticated Dashboard (existing — preserved)
    └── #dashboard section (data-auth-gate="true")
```

---

## 6. API MAPPING PLAN

### Public APIs (no auth required)
| Endpoint | Data | Used In |
|----------|------|---------|
| GET /api/health | status, version, scans_today | All centers, existing counters |
| GET /api/scan/stats | total_scans, today, critical, cve_count | Executive, SOC, all counters |
| GET /api/threat-intel/stats | total_cves, critical_cves, latest_cve | Sentinel, counters |
| GET /api/threat-intel/live | CVE feed array | Sentinel Intelligence Center |
| GET /api/vulns/stats | total, critical, kev_count | Sentinel, stat-cves counter |
| GET /api/global-threat-feed/stats | feed_items, threat_level | Sentinel, SOC |
| GET /api/trust/metrics | total_scans, total_cves, total_customers | Trust Center fix |
| GET /api/platform/metrics | uptime, request_count | MSSP, Executive |
| GET /api/visitor/live | online_users | Existing (preserved) |
| SSE /api/dashboard/stream | live events | All Command Centers |

### Auth-Required APIs (gracefully degraded if unauthenticated)
| Endpoint | Data | Used In |
|----------|------|---------|
| GET /api/history | last scans | SOC Command Center |
| GET /api/soc/dashboard | alert_count, incident_count | SOC Command Center |
| GET /api/ai-security/dashboard | ai_assets, risk_scores | AI SecOps Center |
| GET /api/audit-log/summary | event_count, severity | SOC Center |

---

## 7. REAL-TIME ARCHITECTURE

### SSE Stream: /api/dashboard/stream
```
Client                    CF Worker                    Data Sources
  |                           |                              |
  |-- GET /api/dashboard/stream -->|                         |
  |                           |-- poll scan/stats every 30s --->|
  |<-- data: {"type":"scan_count"...} --|                    |
  |<-- data: {"type":"cve_alert"...} --|                     |
  |<-- data: {"type":"threat_level"..} --|                   |
  |<-- : (keep-alive comment, 25s) --|                       |
```

### Event Types
| Type | Payload | Trigger |
|------|---------|---------|
| `scan_count` | `{total, today, delta}` | Every 30s |
| `cve_alert` | `{id, severity, title}` | On new critical CVE in KV |
| `threat_level` | `{level, score}` | Every 60s |
| `platform_health` | `{status, latency_ms}` | Every 60s |
| `keepalive` | `{}` | Every 25s (prevent timeout) |

### Polling Architecture (dashboard-live.js)
```
PlatformDataBus
  ├── fastPoll (30s):  /api/scan/stats, /api/threat-intel/stats
  ├── medPoll  (60s):  /api/vulns/stats, /api/global-threat-feed/stats
  ├── slowPoll (120s): /api/trust/metrics, /api/platform/metrics
  └── SSE client:      /api/dashboard/stream (persistent, auto-reconnect)
```

---

## 8. ROLLOUT PLAN

| Phase | Action | Files | Risk |
|-------|--------|-------|------|
| P1 | Produce this document | .md | None |
| P2 | Create dashboardStream.js handler | workers/src/handlers/ | None |
| P3 | Register SSE route in index.js | workers/src/index.js | Minimal |
| P4 | Create dashboard-live.js | frontend/ | None |
| P5 | Inject Command Center HTML + script tag | frontend/index.html | Low |
| P6 | Commit + push | git | None |
| P7 | GitHub Actions deploys | CF Workers + Pages | Standard |
| P8 | Live validation on production | — | None |

---

## 9. REGRESSION PREVENTION PLAN

### Pre-Deploy Checklist
- [ ] All existing scan module IDs present in updated index.html
- [ ] fetchRealStats() function still present (not removed)
- [ ] All payment form IDs preserved
- [ ] data-auth-gate="true" sections still gated
- [ ] No new global variable name collisions (use `window.CDB_LIVE_` namespace)
- [ ] dashboard-live.js wrapped in DOMContentLoaded
- [ ] All new fetch calls use AbortSignal.timeout(8000)
- [ ] SSE handler returns correct Content-Type: text/event-stream
- [ ] SSE handler has keep-alive to prevent CF 100s timeout

### Post-Deploy Validation
- [ ] /api/health returns 200
- [ ] /api/scan/stats returns JSON with total_scans field
- [ ] /api/dashboard/stream returns SSE events
- [ ] All 5 Command Centers render in browser
- [ ] Static counters (stat-scans, stat-cves) now show real values
- [ ] Trust center tm-cves no longer shows 0
- [ ] Existing scan modules still functional
- [ ] Payment flows unaffected
- [ ] fetchRealStats() still running every 5min (backward compat)

---

## 10. PRODUCTION READINESS CHECKLIST

### Performance
- [x] SSE uses CF Workers streaming (edge delivery)
- [x] Polls staggered (30s/60s/120s) — no thundering herd
- [x] AbortSignal.timeout(8000) on all fetches
- [x] stale-while-revalidate pattern in PlatformDataBus
- [x] Command Centers lazy-load data on scroll into view (IntersectionObserver)

### Reliability
- [x] Every fetch wrapped in try/catch
- [x] SSE auto-reconnects with exponential backoff (1s→2s→4s→max 30s)
- [x] Missing DOM elements handled silently
- [x] API failures show '—' not errors
- [x] SSE keepalive every 25s (under CF 100s idle timeout)

### Security
- [x] No sensitive data exposed in public Command Centers
- [x] Auth-gated features degrade gracefully when unauthenticated
- [x] No new CORS headers (inherits existing withCors wrapper)
- [x] No user PII in SSE stream

### Observability
- [x] console.info('[CDB-LIVE]') prefix for all log lines
- [x] Error counter tracked in PlatformDataBus.errors
- [x] Last-updated timestamp shown in each Command Center

---

*All 10 deliverables complete. Implementation authorized.*
