# Phase IV — Operations Readiness Report (incl. Performance Certification & Observability)

**Date:** 2026-07-04 · **Scope note:** this session's sandbox cannot reach production (egress policy-denied), so performance/observability certification combines: same-day live evidence from Phases II–III, CI/deploy telemetry via the GitHub API, a cold-start local runtime of the real worker, and source inspection. Each datum is labeled with its origin.

## 1. Performance certification

### 1.1 Live production (same-day, Phases II–III)
| Measure | Result | Assessment |
|---|---|---|
| Async scan end-to-end (free tier) | ~90s (queued → live_dns result) | Functional; slower than the advertised "<30s" ETA — UX-copy item, disclosed |
| Concurrent scan intake | 3 simultaneous → 3× 202, distinct jobs, all drained | Queue intake + consumer proven under modest concurrency |
| D1 read latency (health probes / ops history) | 241–247ms probe RTT; avg 331ms, max 1505ms | Elevated (R-08 open): every D1-backed endpoint carries this floor; investigate region placement + hot-query caching |
| API quota enforcement | Metered intel endpoints 429 at daily limit | Abuse protection holds at quota level; per-minute copy is a doc nuance |

### 1.2 Local cold runtime (this session; fresh clone → `npm ci` → `wrangler dev --local`; miniflare bindings — directional, not edge numbers)
| Probe | Result |
|---|---|
| `/api/health` — 100 requests @ 20-way concurrency | 100/100 HTTP 200 · p50 44ms · p95 124ms · p99 131ms |
| `/api/version` — 100 @ 20-way | 100/100 · p50 38ms · p99 53ms |
| `/api/platform/metrics` with empty DB — 50 @ 10-way | 50× structured 503, honest "Metrics temporarily unavailable", **all values null — no fabricated numbers under failure** |
| Malformed JSON / oversize (20KB) body / unknown route | 400 validation envelope / 400 / structured JSON 404 |
| Security headers | HSTS(preload) + nosniff + X-Frame-Options DENY + X-Request-ID on every response |

### 1.3 Not certified (no safe path this session)
- **Sustained high-volume stress** (hundreds of concurrent scans/AI requests) was **not** run: production is unreachable from this sandbox, and the same-day Phase III account-based probes were the last live datapoints. Local miniflare cannot represent edge/queue behavior at that scale. → Recommend a scheduled, rate-announced load exercise against production off-peak (runbook §7 of the Production Operations Manual).
- **WebSockets** — no customer-facing WS surface was claimed or found in the verified scope; nothing to certify.

## 2. Observability verification (source + CI evidence)

| Control | Status | Evidence |
|---|---|---|
| Structured access logs | ✅ | One JSON line per API request (`event:"request"`, status, dur_ms) with propagated `X-Request-ID` (R-02 closed) |
| Global exception boundary | ✅ | Exported `fetch()` try-boundary: structured 500 `ERR_UNHANDLED` + `system_errors` D1 record + deduped ops alert (30-min window); locked by `globalErrorBoundary.test.mjs` |
| Metrics & health | ✅ | `/api/health` per-component latency; `/api/platform/metrics` SSOT; cron fires a 9-component health probe seeding `operational_history` |
| Uptime accounting | ✅ (honest) | `/api/uptime` reports availability with `degraded_pct` separated (EH-01 closed) |
| Alerting | ✅ | `alertEngine` → Telegram (+email channel), severity-tagged, deduped |
| Tracing | ◐ | Request-ID correlation across client↔worker logs; no distributed tracing spans (acceptable at this scale — single worker hop) |
| Dashboards | ✅ | ops-dashboard + platform-health pages read live endpoints (Phase II data-integrity verified) |
| **External uptime probe** | ✗ **GAP (R-11)** | All monitoring runs inside the platform being monitored; a total Worker outage silences health recording. ~10-min fix via Cloudflare Healthchecks — top ops action |
| Incident response | ✅ documented | `INCIDENT_RESPONSE_RUNBOOK.md` severity ladder + playbooks |
| Rollback | ✅ documented + mechanized | Deploy serialization, post-deploy smoke with version-sync verification, `DEPLOY_RECOVERY_RUNBOOK.md`; `wrangler rollback`/redeploy paths in DR runbook |

## 3. Deployment & recovery reliability (CI telemetry, this session)

| Item | Evidence |
|---|---|
| Production deploys | **616 total; latest 30 consecutive successes** (run #616 = current prod commit `56ab74f`) |
| Gating | Deploy fires only after "Test & Quality Gate" success on main: vitest (1251) + Playwright E2E smoke + axe accessibility + security headers + Lighthouse (3-run median); gitleaks separate |
| Smoke discipline | 3-endpoint fallback chain, exponential backoff, JSON-structure + version + commit verification (zero-false-failure design) |
| Nightly D1 backup | 2/2 scheduled runs green (Jul 3, Jul 4); integrity gate + SHA-256 + 30-day artifact |
| Migrations | `db-migrate.yml`: typed-APPLY gate, pre-migration export artifact (90-day), post-check |
| Restore drill | Script proven offline both directions (`restoreDrill.test.mjs`, 6 tests); **never run against a real nightly artifact — R-06, owner action now unblocked** (first real artifacts exist) |

## 4. Operational excellence questions (program-mandated)

- **Can another engineering team maintain it?** Largely yes: living risk register with owners, engineering standards doc, 1251-test executable spec, runbooks. Friction: stale `docs/architecture.md`/`api-contract.md` (NEEDS REMEDIATION) and an 8,891-line router with 158 handler files — navigable but dense.
- **Can another SOC operate it?** For its own surface, yes (dashboards + runbooks + alerting). On-call, however, is a single Telegram operator (R-10).
- **Can another company deploy it?** Demonstrated this session: fresh clone → serving locally in 2 commands; CI deploy is fully declarative apart from the dashboard-managed route (R-17, documented).
- **Can another developer understand it?** Standards + tests + honest envelopes help; API-shape inconsistency (21% envelope adoption, 4-way timestamp naming) is the main comprehension tax — tracked debt, not hidden.

## 5. Open operational risks (carried, with owners — see `docs/OPERATIONAL_RISK_REGISTER.md`)

R-06 restore drill on real artifact (S1, owner) · R-08 D1 latency (S2, eng) · R-09 cron fan-out vs plan (S2, owner) · R-10 bus factor 1 (S2, business) · R-11 external probe (S2, owner) · R-12 30-day backup ceiling (S3) · R-13 bundle growth (S3) · EA-03 SLA definition reconciliation (product decision).

**Verdict: OPERATIONS PILOT-READY.** The pipeline, observability-in-band, backup, and recovery documentation meet or exceed small-vendor norms with evidence; the gaps that keep it from enterprise-grade ops are known, registered, owned, and mostly hours-not-months of work (external probe, real restore drill, escalation path).
