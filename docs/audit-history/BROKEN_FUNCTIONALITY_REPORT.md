# CYBERDUDEBIVASH® — BROKEN FUNCTIONALITY REPORT (BFR)
**Classification:** P0 Customer Escalation  
**Date:** 2026-06-12  
**Status:** 14 CONFIRMED BROKEN | 8 PARTIAL | 6 FUNCTIONAL

---

## BFR-001 — SCAN ENGINE PRODUCES FAKE DATA (P0 CRITICAL)

| Field | Details |
|-------|---------|
| **Feature** | AI Scanner, Red Team Scanner, Identity Scanner, Compliance Scanner |
| **Location** | `workers/workers/src/engine.js` |
| **Expected** | Real security analysis of the AI model / target system |
| **Actual** | Seeded pseudo-random results based on string hash of target name |
| **Root Cause** | `domainScanEngine()` in engine.js uses `strHash(target)` + `Math.sin(seed)` to generate findings. Same input = same output every time. No external API calls made. |
| **Evidence** | `engine.js:16` — `function sr(seed, offset=0){ const x = Math.sin(seed+offset+1)*10000; return Math.abs(x-Math.floor(x)); }` used throughout |
| **Business Impact** | Platform sells security scanning but provides fabricated results — regulatory/legal liability |
| **Fix Required** | Replace seeded engine with real external API calls: NVD for CVEs, Shodan/Censys for ports, Have I Been Pwned for identity, real OWASP LLM checks via AI inference |
| **Effort** | 40-60 hours |
| **Priority** | P0 — IMMEDIATE |

---

## BFR-002 — INTEL HUB SHOWS STATIC HARDCODED CONTENT (P0 CRITICAL)

| Field | Details |
|-------|---------|
| **Feature** | Intel Hub (/intel-hub) live threat feed |
| **Location** | `frontend/intel-hub.html` lines 220–298 |
| **Expected** | Live, rotating threat intelligence updated from Sentinel APEX |
| **Actual** | 6 static HTML cards hardcoded in the page — never change |
| **Root Cause** | The `loadLiveFeed()` function exists in the page script but ONLY runs if `/api/threat-intel` returns data. The fallback is the hardcoded cards. The D1 database requires cron seeding to populate. |
| **Evidence** | `intel-hub.html:224` — `<a href="/#pricing" class="btn-intel">Full Report →</a>` — 6 hardcoded cards visible |
| **Customer Complaint** | "Not the live intels, not the intels from last 24 hours" |
| **Fix Required** | (1) Ensure threat ingestion cron runs and seeds D1. (2) Replace fallback static cards with dynamic skeletons. (3) Add date-sorted API query with `?sort=date&limit=20` |
| **Effort** | 8-12 hours |
| **Priority** | P0 |

---

## BFR-003 — DEFENSE MARKETPLACE SHOWS MOCK PRODUCTS (P0 CRITICAL)

| Field | Details |
|-------|---------|
| **Feature** | Defense Marketplace — security product catalog |
| **Location** | `workers/workers/src/handlers/defenseMarketplace.js` lines 505-507 |
| **Expected** | Real AI-generated defense products based on live CVEs |
| **Actual** | 3 hardcoded mock products with IDs `mock-1`, `mock-2`, `mock-3` and fake CVE-2024-12345 |
| **Root Cause** | `defenseMarketplace.js:505` serves hardcoded objects when no real products exist in D1. The product generation cron (`queueCVEsForGeneration`) must have never run successfully. |
| **Evidence** | `{ id: 'mock-1', cve_id: 'CVE-2024-12345', title: 'Critical RCE Firewall Blocker'...}` |
| **Fix Required** | (1) Run product generation pipeline via `/api/content/pipeline/run`. (2) Remove mock fallback. (3) Add loading state instead. |
| **Effort** | 4-6 hours |
| **Priority** | P0 |

---

## BFR-004 — RAZORPAY/STRIPE PAYMENT FLOW NOT CONFIGURED (P0 CRITICAL)

| Field | Details |
|-------|---------|
| **Feature** | All paid features — reports, subscriptions, plan upgrades |
| **Location** | `workers/workers/src/lib/razorpay.js`, `workers/workers/src/handlers/payments.js` |
| **Expected** | User clicks "Get Starter ₹499" → Razorpay checkout → payment confirmed → access granted |
| **Actual** | Payment flow code exists but `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` are not confirmed as set in production secrets |
| **Root Cause** | wrangler.toml confirms both are required secrets but no evidence of them being configured. Revenue = ₹0 confirms this. |
| **Evidence** | `wrangler.toml` comment: `RAZORPAY_KEY_ID — Razorpay API key ID (rzp_live_... or rzp_test_...)` marked as required |
| **Business Impact** | Zero revenue. All upgrade flows dead. |
| **Fix Required** | Set production secrets: `npx wrangler secret put RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` |
| **Effort** | 2 hours (configuration, not code) |
| **Priority** | P0 — REVENUE BLOCKER |

---

## BFR-005 — CISO METRICS RETURNS RANDOM DATA (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | CISO Dashboard — API usage metrics |
| **Location** | `workers/workers/src/handlers/cisoMetrics.js:340` |
| **Expected** | Real platform API call count from D1 analytics |
| **Actual** | `api_calls_today: Math.floor(Math.random() * 3000) + 2000` — random number 2000-5000 on every request |
| **Root Cause** | Random generation used as placeholder, never replaced with real query |
| **Fix Required** | Replace with `SELECT COUNT(*) FROM api_events WHERE created_at > datetime('now', '-1 day')` against D1 |
| **Effort** | 1 hour |
| **Priority** | P1 |

---

## BFR-006 — AUTONOMOUS SOC USES RANDOM AI SCORES (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | Autonomous SOC — threat triage and MITRE TTP mapping |
| **Location** | `workers/workers/src/handlers/autonomousSocMode.js:178,181` |
| **Expected** | Real AI-calculated threat confidence scores |
| **Actual** | `ai_score: Math.min(10, parseFloat(t.cvss||7) + (Math.random()*0.5-0.25))` and `mitre_ttps: ['T1190','T1059','T1055'].slice(0, Math.ceil(Math.random()*3))` |
| **Root Cause** | Random jitter used for AI score, random slice for TTP count |
| **Fix Required** | Use env.AI (Workers AI) for real scoring, use CVE→MITRE mapping table for TTP assignment |
| **Effort** | 8 hours |
| **Priority** | P1 |

---

## BFR-007 — ATTACK LIBRARY MODAL BUTTONS BROKEN (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | Attack Library (/attack-library) — "Details" buttons |
| **Location** | `frontend/attack-library.html` lines 239, 260, 282, 303, 325, 347, 369, 390 |
| **Expected** | Click "Details" → modal opens with full attack details, test cases, MITRE mapping |
| **Actual** | `onclick="event.stopPropagation()"` — button clicks are eaten, no modal opens |
| **Root Cause** | Multiple attack cards have `btn-more` buttons with only `event.stopPropagation()` — `openAttack()` call missing |
| **Evidence** | `<button class="btn-more" onclick="event.stopPropagation()">Details</button>` — 8 instances |
| **Fix Required** | Add `openAttack('attack-id')` call to each broken button |
| **Effort** | 2 hours |
| **Priority** | P1 |

---

## BFR-008 — AIANALYSIS.JS MITRE ATT&CK RANDOM APPLICABILITY (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | AI Cyber Brain — MITRE ATT&CK mapping |
| **Location** | `workers/workers/src/handlers/aiAnalysis.js:180` |
| **Expected** | Relevant MITRE techniques derived from actual scan findings |
| **Actual** | `applicable: attack_chain.some(c => c.technique?.id === t.id) || Math.random() > 0.4` — 60% of techniques marked applicable randomly |
| **Root Cause** | Random fallback added when technique ID lookup fails |
| **Fix Required** | Remove `|| Math.random() > 0.4`. Only mark techniques applicable if genuinely correlated. |
| **Effort** | 1 hour |
| **Priority** | P1 |

---

## BFR-009 — D1 DATABASE SCHEMA FRAGMENTATION (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | All database-backed features |
| **Location** | `workers/workers/schema*.sql` — 10 files |
| **Expected** | Single canonical schema with versioned migrations |
| **Actual** | schema.sql, schema_v8.sql, schema_v10.sql, schema_v12.sql, schema_v15.sql, schema_v28.sql, schema_v29.sql, schema_migrations_v2.sql, schema_gtm_only.sql, schema_revenue_autopilot.sql, schema_threat_intel.sql |
| **Root Cause** | Iterative development added tables in separate files without a migration runner |
| **Business Impact** | Unknown which schema is applied to production D1. Missing tables cause silent 500 errors. |
| **Fix Required** | Audit production D1 with `wrangler d1 execute --command "SELECT name FROM sqlite_master WHERE type='table'"`. Produce single canonical schema_final.sql. |
| **Effort** | 6-8 hours |
| **Priority** | P1 |

---

## BFR-010 — DUPLICATE ROUTE DEFINITIONS IN INDEX.JS (P2 MEDIUM)

| Field | Details |
|-------|---------|
| **Feature** | Threat Intel Live endpoint |
| **Location** | `workers/workers/src/index.js:1518` and `2570` |
| **Expected** | Single route handler for `/api/threat-intel/live` |
| **Actual** | Route defined TWICE — line 1518 and line 2570 — second definition shadows first |
| **Root Cause** | Iterative development added routes without checking for existing definitions |
| **Fix Required** | Remove duplicate at line 2570, keep the more complete implementation |
| **Effort** | 30 minutes |
| **Priority** | P2 |

---

## BFR-011 — INTEL HUB "SUBSCRIBE" BUTTON BROKEN FLOW (P2 MEDIUM)

| Field | Details |
|-------|---------|
| **Feature** | Intel Hub subscription button |
| **Location** | `frontend/intel-hub.html:337` |
| **Expected** | Click → email captured → subscriber gets threat alerts |
| **Actual** | `subscribe()` function calls `/api/leads/magnet` — API may succeed but email pipeline (RESEND_API_KEY) not confirmed configured |
| **Fix Required** | Confirm RESEND_API_KEY is set; add confirmation message regardless of API response |
| **Effort** | 2 hours |
| **Priority** | P2 |

---

## BFR-012 — USER DASHBOARD BILLING TAB BROKEN (P2 MEDIUM)

| Field | Details |
|-------|---------|
| **Feature** | User Dashboard — Billing/Upgrade section |
| **Location** | `frontend/user-dashboard.html:1198-1201` |
| **Expected** | Click plan → Razorpay checkout opens |
| **Actual** | `window.CDB_PAY && CDB_PAY.open(...)` — CDB_PAY is conditionally loaded; if payment module not available, button silently fails |
| **Fix Required** | Add fallback to redirect to /upgrade.html if CDB_PAY not loaded |
| **Effort** | 1 hour |
| **Priority** | P2 |

---

## BFR-013 — MYTHOS AI PROVIDER NOT CONFIGURED (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | MYTHOS AI narratives — executive reports, AI assessments, tool generation |
| **Location** | `workers/workers/src/services/mythosOrchestrator.js` |
| **Expected** | MYTHOS generates AI-powered threat narratives and SOAR rules |
| **Actual** | Requires `env.AI` (Cloudflare Workers AI) OR Anthropic/Groq API key. If neither configured, narratives are null/empty |
| **Root Cause** | No confirmed AI provider secret set in production. Project instructions reference ANTHROPIC_API_KEY as missing. |
| **Fix Required** | Set at minimum Cloudflare Workers AI binding (free tier) OR configure Groq API key (free tier) |
| **Effort** | 2 hours |
| **Priority** | P1 |

---

## BFR-014 — SOC DASHBOARD REQUIRES SEEDED D1 DATA (P1 HIGH)

| Field | Details |
|-------|---------|
| **Feature** | SOC Dashboard — Alerts, Decisions, IOC panels |
| **Location** | `frontend/soc-dashboard.html` + `workers/workers/src/handlers/soc.js` |
| **Expected** | SOC analyst sees live alerts, threat decisions, active incidents |
| **Actual** | All panels return empty arrays if D1 is not seeded. No data = empty dashboard with "Upgrade to Enterprise" prompts |
| **Root Cause** | D1 tables are empty in production. Cron jobs that should populate via `runIngestion()` depend on external feeds which may not respond. |
| **Fix Required** | (1) Run `/api/seed/all` once to seed data. (2) Confirm cron ingestion is working. (3) Add "No active alerts — platform monitoring" state instead of upgrade CTA. |
| **Effort** | 4 hours |
| **Priority** | P1 |

---

*BFR Total: 14 confirmed defects | P0: 4 | P1: 8 | P2: 2*
