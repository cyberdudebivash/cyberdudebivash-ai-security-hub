# Production Operations Manual

> **Living document — the operator's entry point.** Detailed procedures live in the
> runbooks; this manual tells an operator (including one who has never seen the
> platform) what the system is, how to see its state, and which runbook to open.
> Established Phase IV (2026-07-04). Update when topology or procedures change.

## 1. What is running

| Layer | Technology | Name / binding |
|---|---|---|
| API | Cloudflare Worker (`workers/src/index.js`, entry `workers/index.ts`) | route `cyberdudebivash.in/api/*` (dashboard-managed — see risk R-17) + `cyberdudebivash-security-hub.iambivash-bn.workers.dev` |
| Frontend | Cloudflare Pages (static, no build step) | `cyberdudebivash-security-hub.pages.dev` → `cyberdudebivash.in` |
| Database | Cloudflare D1 (SQLite, 216 tables) | `SECURITY_HUB_DB` / `cyberdudebivash-security-hub` |
| Cache / counters / job status | Cloudflare KV | `SECURITY_HUB_KV` |
| Scan artifacts | Cloudflare R2 | `SCAN_RESULTS` |
| Async scans | Cloudflare Queues | producer+consumer `scan-jobs`, DLQ `scan-jobs-dlq` (DLQ is a crash safety net only — permanent failures are recorded to KV/D1, risk R-15) |
| AI inference | Workers AI binding + external LLM mesh (Groq, DeepSeek, OpenRouter, Together, Anthropic — see `SUB_PROCESSOR_LIST.md`) | copilot/MYTHOS fall back gracefully; `ai_narrative: null` on failure, never fabricated |
| Scheduled work | 5 cron slots (hourly monitoring · 4×/day CVE feed · 6h MYTHOS run · daily content 06:00 · daily revenue 23:00 UTC) | `workers/wrangler.toml` `[triggers]` |

## 2. How changes reach production

`push to main` → **Test & Quality Gate** (`test.yml`: vitest 1251 · Playwright E2E smoke · axe accessibility · security headers · Lighthouse 3-run median) → on success, **Deploy to Cloudflare** (`deploy.yml`: preflight → workers → frontend → post-deploy smoke with 3-endpoint fallback, exponential backoff, version+commit verification). Deploys are serialized (`concurrency: deploy-production`, never cancel-in-progress). `workflow_dispatch` inputs exist as documented emergency bypasses.

- **Verify what's live:** `GET https://cyberdudebivash.in/api/version` (returns deployed commit) — the post-deploy smoke does this automatically.
- **Rollback:** see `DEPLOY_RECOVERY_RUNBOOK.md`; fastest path is redeploy of the last green commit (deploy history: Actions → "Deploy to Cloudflare").

## 3. How to see system state

| Question | Where |
|---|---|
| Is it up? | `GET /api/health` (per-component status + latency) · `GET /api/uptime` (availability + `degraded_pct`, honest accounting) · `GET /api/status`, `/api/incidents` |
| Is it healthy long-term? | ops-dashboard / platform-health pages; `operational_history` (seeded by every cron firing via the 9-component probe) |
| What broke? | `system_errors` table (every unhandled exception, structured, with request path) · structured access logs: one JSON line per request (`event:"request"`, status, `dur_ms`, `X-Request-ID`) via `wrangler tail` |
| Am I being alerted? | Telegram admin chat (alertEngine; deduped 30-min window; severity-tagged) **plus the external uptime probe** (`external-uptime-probe.yml`, every 15 min from GitHub runners — outside the Worker's failure domain): on outage it files/refreshes a GitHub issue and fails the run (owner notification). Closes the monitoring half of risk R-11 |
| Correlate a customer report | Ask for their `X-Request-ID` (returned on every response) → grep tail/logs |

## 4. Data protection

- **Backups:** nightly 02:30 UTC full D1 export (`d1-backup.yml`) — integrity-gated, SHA-256 recorded, 90-day GitHub-artifact retention (>90-day compliance archive: residual of risk R-12).
- **Restore:** `DISASTER_RECOVERY_RUNBOOK.md` (per-store RPO/RTO, Time-Travel and export paths). **Mandatory pre-flight:** `node scripts/d1-restore-drill.mjs <dump>` — validates the artifact into a throwaway DB before touching production. The drill also runs **automatically every Monday 05:00 UTC against the newest real nightly artifact** (`d1-restore-drill.yml`); a failing drill run means current backups may not be restorable — treat as S1 (risk R-06).
- **Migrations:** only via `db-migrate.yml` (typed APPLY gate, automatic pre-migration export, post-check). Never `d1 execute` by hand against production.
- **KV/Queues are not backed up** by design (rebuildable; R-16).

## 5. Incidents

Open `INCIDENT_RESPONSE_RUNBOOK.md` (severity ladder, playbooks, customer-comms steps). Current escalation reality: **single operator** (risk R-10) — alerts land in one Telegram chat; there is no deputy. If you are a new operator taking over: read runbooks in this order — incident response → disaster recovery → deploy recovery.

## 6. Routine operations calendar

| Cadence | Task | Mechanism |
|---|---|---|
| Continuous | CVE feed refresh, monitoring probes, MYTHOS runs, content, revenue snapshot | The 5 cron slots (automatic) |
| Every 15 min | External uptime probe | Automatic (`external-uptime-probe.yml`); on outage: GitHub issue + failed-run notification |
| Nightly 02:30 UTC | D1 backup | Automatic; check the run went green after any schema change |
| After every deploy | Smoke verification | Automatic in `deploy.yml`; spot-check `/api/version` |
| Weekly Mon 05:00 UTC | DR restore drill vs newest real backup artifact | Automatic (`d1-restore-drill.yml`); failure = treat backups as untrusted (S1) |
| On demand (pre-release) | Enterprise release gate | Actions → "Enterprise Release Gate" (`workflow_dispatch`) → runs `scripts/enterprise-release-gate.mjs` end-to-end against production |
| Ongoing | Risk register review | `docs/OPERATIONAL_RISK_REGISTER.md` — living, with owners |

## 7. Load exercises (policy)

No sustained stress test has been run against production (see Phase IV Operations Readiness Report §1.3). If one is scheduled: off-peak, rate-announced, watch `/api/health` component latencies and queue drain; abort on sustained `degraded`. Free-plan Workers limits (subrequests/CPU, 5-cron cap, 3MB bundle) are the binding ceilings — confirm plan level first (risk R-09).

## 8. Secrets & access

GitHub Actions secrets: `CLOUDFLARE_API_TOKEN` (least-privilege: no Zone route edit — R-17), `CLOUDFLARE_ACCOUNT_ID`, Razorpay webhook secret via `wrangler secret`. LLM provider keys via `wrangler secret`. Rotation and scope rationale: `SECURITY_GAP_ANALYSIS.md`. gitleaks runs on every push.

## 9. Canonical references

`DEPLOY.md` · `DEPLOY_RECOVERY_RUNBOOK.md` · `DISASTER_RECOVERY_RUNBOOK.md` · `INCIDENT_RESPONSE_RUNBOOK.md` · `docs/OPERATIONAL_RISK_REGISTER.md` · `docs/ENGINEERING_STANDARDS.md` · `DOCUMENTATION_INDEX.md` (master map). Phase IV assessments: `docs/audit-history/PHASE4_*_2026-07.md`.
