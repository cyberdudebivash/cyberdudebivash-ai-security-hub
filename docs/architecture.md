# CYBERDUDEBIVASH AI Security Hub — Architecture (v40)

> **Superseded content notice:** this file previously described the v3-era
> "deterministic engine" (string-hash scores, no database). That architecture
> was retired; the description survived unmaintained and was flagged NEEDS
> REMEDIATION in Phase IV (Global Release Decision #16). This rewrite states
> the architecture as verified on 2026-07-04 (source inspection + local
> cold-start run + same-day live evidence). The operator-facing view of the
> same topology lives in `PRODUCTION_OPERATIONS_MANUAL.md`.

## Topology

```
Customer browser / API client
    │
    ├─ Cloudflare Pages  — static frontend (76 pages + 1,626 CVE advisories, no build step)
    │
    └─ cyberdudebivash.in/api/* → Cloudflare Worker (single edge app)
           entry: workers/index.ts → src/index.js router (~770 routes, 158 handler files)
           │
           ├─ middleware: CORS · validation · security headers + X-Request-ID
           │              rate limiting (KV) · monetization/entitlements · auth (JWT/API-key/SSO)
           │
           ├─ D1  (SECURITY_HUB_DB, 216 tables)  — users, scan history/jobs, threat_intel
           │                                        (~1,600+ real CVEs), orgs, billing, system_errors
           ├─ KV  (SECURITY_HUB_KV)              — rate counters, caches, job status, report tokens
           ├─ R2  (SCAN_RESULTS)                 — scan artifacts
           ├─ Queues (scan-jobs + scan-jobs-dlq) — async scan pipeline (producer + consumer)
           └─ AI: Workers AI binding + external LLM mesh (Groq, DeepSeek, OpenRouter,
                  Together, Anthropic — disclosed in SUB_PROCESSOR_LIST.md)
```

## Key flows

**Async scan (primary customer flow):** `POST /api/scan/async/:module` → 202 + job → queue consumer runs the real engine (e.g. live DNS/TLS/DNSSEC resolution — `data_source: live_dns`) → result to R2/D1/KV → owner-scoped polling → report cache write (`scan:${owner}:${scan_id}`) enables `POST /api/report/generate`.

**AI grounding (anti-fabrication):** copilot and the MYTHOS analyst answer **from the platform's own `threat_intel` data**; unknown CVEs produce an explicit uncertainty statement, never invented facts. On LLM failure the narrative is `null` — no fabricated fallback. Regression-locked (`mythosAnalystGrounding`, `copilotCveGrounding`).

**Scheduled work — 5 cron slots** (Cloudflare cron cap on the current plan): hourly monitoring/anomaly probes (also seeds `operational_history`), 4×/day CVE feed refresh, 6-hourly MYTHOS run, daily content pipeline, daily revenue snapshot.

## Reliability & observability (verified)

- Global exception boundary in `fetch()`: structured 500 + `system_errors` record + deduped ops alert — no raw Cloudflare 1101 pages.
- One structured JSON access-log line per request (status, `dur_ms`, propagated `X-Request-ID`).
- Health: `/api/health` (per-component latency), `/api/uptime` (honest availability accounting), **plus an external probe outside the platform's failure domain** (`.github/workflows/external-uptime-probe.yml`, every 15 min).
- Graceful degradation: with the database unavailable, metric endpoints return structured 503s with null values — never fabricated numbers (verified in a cold local run).

## Delivery & recovery (verified)

- Deploys: push to `main` → Test & Quality Gate (vitest 1,267+ · Playwright E2E · axe · security headers · Lighthouse · bundle-size gate ≤2.5 MB gzip) → serialized deploy → multi-endpoint post-deploy smoke with version verification. 616+ production deploys, latest 30 consecutive successes at the time of writing.
- Data protection: nightly D1 export (integrity gate, SHA-256, 90-day artifact) + **weekly automated restore drill against the newest real artifact** (`d1-restore-drill.yml`) + migration workflow with pre-migration export.
- Runbooks: `INCIDENT_RESPONSE_RUNBOOK.md`, `DISASTER_RECOVERY_RUNBOOK.md`, `DEPLOY_RECOVERY_RUNBOOK.md`; risk ledger: `docs/OPERATIONAL_RISK_REGISTER.md`.

## Known architectural constraints (disclosed, tracked)

- KV counters are read-modify-write (bounded burst overshoot; fail-open on KV outage) — accepted risk R-14; the correct fix is Durable Objects if abuse levels ever justify it.
- D1 read latency floor (~240–330 ms observed) on D1-backed endpoints — open risk R-08.
- Worker bundle 1.32 MB gzip vs Cloudflare's 3 MB cap — CI gate at 2.5 MB (risk R-13).
- The `/api/*` route on the custom domain is dashboard-managed, not in wrangler.toml (least-privilege CI token) — documented manual step in DR runbook (R-17).

---
*CyberDudeBivash Pvt. Ltd. — https://cyberdudebivash.in*
