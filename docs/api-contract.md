# CYBERDUDEBIVASH AI Security Hub — API Contract (v40)

**Base URL:** `https://cyberdudebivash.in` (fallback origin: `https://cyberdudebivash-security-hub.iambivash-bn.workers.dev`)
**Interactive docs:** https://cyberdudebivash.in/api-docs · **Endpoint directory:** `GET /api`
**Superseded:** the previous v3.0 contract in this file described the retired deterministic-engine era (workers.dev base URL, 5 req/day FREE, ₹9,999 PRO) and no longer matched the platform — flagged NEEDS REMEDIATION in `docs/audit-history/PHASE4_GLOBAL_RELEASE_DECISION_2026-07.md` (#16) and replaced by this document.

Everything below is stated from verified behavior (regression suite + same-day live verification, 2026-07-04), not aspiration.

## Authentication

| Method | How | Notes |
|---|---|---|
| Session JWT | `Authorization: Bearer <token>` from `POST /api/auth/login` / `signup` | Refresh via `POST /api/auth/refresh` |
| API key | `x-api-key: <key>` | First key issued automatically at signup; manage via `/api/keys` |
| None | — | Anonymous IP-fallback: FREE-tier limits, public/preview surfaces only |

## Plans & limits (canonical tier table — enforced)

| Tier | Price (INR/mo) | API daily | Burst/min | API keys |
|---|---|---|---|---|
| FREE | 0 | 5 | 2 | 2 |
| STARTER | 999 | 20 | 5 | 2 |
| PRO | 1,499 | 500 | 20 | 5 |
| ENTERPRISE | 4,999 | unlimited | 60 | 20 |
| MSSP | 9,999 | unlimited | 120 | unlimited |

Live source of truth: `GET /api/auth/plans`. The **threat-intel feed product** has its own metered tiers — `GET /api/v1/intel/pricing.json` (FREE 100/day·10 rpm → MSSP unlimited·240 rpm). **Both the daily quota and the per-minute rate are enforced** (the per-minute window was advertised-only before 2026-07-04; a 429 for the minute window carries `Retry-After: 60`).

## Core customer endpoints (verified live)

| Endpoint | Purpose | Verified behavior |
|---|---|---|
| `POST /api/auth/signup` | Create account | 201 → access token + first API key, tier FREE |
| `POST /api/auth/login` / `GET /api/auth/me` | Session | 200 / real user row |
| `POST /api/scan/async/:module` | Queue a scan (domain, ai, redteam, identity, compliance) | 202 → `job_id`, `poll_url`, honest `estimated_eta` (~1–3 min by queue priority) |
| `GET /api/jobs/:id` · `/api/jobs/:id/result` | Poll job / fetch result | Owner-scoped (404 cross-tenant); results carry `data_source: live_dns` etc. |
| `GET /api/scan/history` | Per-user scan history | Scoped to the caller |
| `POST /api/report/generate` | Report from `scan_id` or inline `scan_result` | 201 → `download_url`. Optional `visibility:"private"` binds the report to your account: the download then requires auth as the owner (401/403 otherwise). Default links remain shareable capability URLs (unguessable token, 7-day expiry) |
| `GET /api/report/:token` | Download report | Styled HTML (print-to-PDF); 410 after expiry |
| `POST /api/copilot/chat` | Grounded AI copilot | Cites real CVE data; explicitly acknowledges unknowns — never fabricates |
| `GET /api/platform/metrics` | Live platform metrics (SSOT) | Honest structured 503 with null values when unavailable |
| `DELETE /api/auth/delete-account` | GDPR erasure | Purges api_keys / scan_history / scan_jobs (incl. queued) / mfa_secrets; login → 401 after |

## Threat-intel product endpoints

| Endpoint | Tier | Notes |
|---|---|---|
| `GET /api/v1/intel/latest.json` | public preview (edge-cached) / full detail with key | 25-item FREE preview is intentional |
| `GET /api/v1/intel/kev.json` | STARTER+ (full KEV) | |
| `GET /api/v1/intel/stix.json` | **PRO+** | STIX 2.1 bundle for SIEM/TIP ingestion |
| `GET /api/v1/intel/pricing.json` | public | Machine-readable pricing matrix |
| `GET/POST /api/intel/ioc · cve · actor · ttp · risk` | FREE (ioc,cve) / PRO+ (all) | Responses carry truthful `stix_available` + `stix_endpoint`; 429s include `retry_after` |
| `GET /api/cti/v2/stix/export` | entitlement-gated | Enterprise CTI export path |

## Standard response conventions

- Security headers on every response (HSTS preload, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`) plus **`X-Request-ID`** — quote it in support requests; it joins your call to the worker's structured logs.
- Rate headers on metered feeds: `X-RateLimit-Tier/-Limit/-Remaining`; 429 bodies distinguish `rate_per_min` (with `Retry-After: 60`) from daily quota.
- Errors are structured JSON: 400 validation (`{error, message, field}`), 401/403 auth, 404 `{error:"Not Found", path, method}`, 410 expired, 413 oversize, 429 quota, 500 `{code:"ERR_UNHANDLED", request_id}` via the global exception boundary — no raw HTML errors.

## Status & transparency endpoints

`GET /api/health` (per-component latency) · `GET /api/version` (deployed commit) · `GET /api/uptime` (availability with `degraded_pct` disclosed separately) · `GET /api/status`, `/api/incidents` · trust center: `/trust-center.html`, sub-processors disclosed in `SUB_PROCESSOR_LIST.md`.

---
*CyberDudeBivash Pvt. Ltd. · contact@cyberdudebivash.in · Operations: `PRODUCTION_OPERATIONS_MANUAL.md`*
