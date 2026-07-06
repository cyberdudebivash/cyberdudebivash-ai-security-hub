# Operational Risk Register — Living Document

> Canonical register of operational risks for the production platform.
> Every entry carries evidence, impact, and current disposition. Update the
> disposition when a risk is closed or accepted; add new risks at the bottom.
> Point-in-time context: `docs/audit-history/ENTERPRISE_OPERATIONS_READINESS_2026-07.md`.

**Last reviewed:** 2026-07-04 (Phase IV remediation pass — see `docs/audit-history/PHASE4_REMEDIATION_REPORT_2026-07.md`)

## Phase IV remediation pass (2026-07-04) — dispositions changed

| ID | Change | Mechanism |
|----|--------|-----------|
| R-06 | **RESOLVED.** Weekly restore drill runs against the newest REAL nightly backup artifact in CI (`.github/workflows/d1-restore-drill.yml`: download artifact → `scripts/d1-restore-drill.mjs` → integrity + ≥50-table floor). First scheduled run went green 2026-07-06 08:56 UTC (run `28779799461`, all 7 steps, 26s) — closed per the condition set at the prior pass. |
| R-11 | **PARTLY RESOLVED.** External uptime probe now runs OUTSIDE the platform's failure domain (`.github/workflows/external-uptime-probe.yml`, every 15 min: /api/health on custom domain + workers.dev fallback, 3-attempt backoff; outage → auto-filed GitHub issue + failed run notification). A Cloudflare Healthcheck remains a recommended second vantage point (owner, ~10 min). |
| R-12 | **MITIGATED.** Backup artifact retention raised 30 → 90 days (GitHub Actions maximum). Residual: >90-day compliance archive still needs R2/external shipping if a customer contract requires it. |
| R-13 | **CLOSED.** CI bundle-size gate added to the Test & Quality Gate (`bundle-size` job: wrangler dry-run, fail > 2.5 MB gzip; measured 1.32 MB at introduction = 44% of Cloudflare's 3 MB cap). |
| (copy) | **CLOSED.** Scan-ETA honesty: homepage "<30s" claims and the API's `estimated_eta: '< 30s'` replaced with measured "~1–3 min" ranges; advertised-but-unenforced per-minute API limits now enforced in both metered paths. Locked by `honestCopy.test.mjs`, `intelRateLimitEnforcement.test.mjs`. |

| Sev | Likelihood | Meaning |
|---|---|---|
| S1 | — | Customer-visible outage / data loss / revenue loss |
| S2 | — | Degraded service, ops blind spot, or recovery slower than SLA |
| S3 | — | Hygiene / efficiency / future scaling constraint |

## Enterprise Acceptance pass (2026-07-02) — new entries

| ID | Risk | Sev | Evidence | Disposition |
|----|------|-----|----------|-------------|
| EA-01 | Trust Center reported 0 scans / 0 CVEs — `handleTrustMetrics` read never-written `platform_metrics` keys, and a cache-hit/miss envelope-shape mismatch made `/api/trust/center` metrics null (frontend fell back to a hardcoded baseline placeholder) | S1 (trust) | Live probe: trust=0 while platform/metrics=60, health=115; frontend reads `d.metrics.*` | **CLOSED** (commit `e141f1a`): source from hydrated blend, nested shape, cache `:v2`; `trustMetricsContract.test.mjs` |
| EA-02 | Subscription bypass — `/api/ai/simulate`, `/api/ai/forecast`, `/api/v1/forecast` advertised PRO+ but enforced nothing; anonymous FREE received full results | S1 (revenue) | Live: anon FREE → HTTP 200 full kill-chain; handler docstring says "(PRO+)" | **CLOSED** (commit `e141f1a`, per owner decision): gated via canonical `PLAN_FEATURES` → 402; `aiBrainEntitlementGate.test.mjs` |
| EA-03 | Uptime figure divergence: 95.8% (uptime API, degraded-inclusive) vs 100% (trust, availability) vs 99.9%/99.97% marketing SLA | S1 (trust/legal) | Live probes 2026-07-02 | **OPEN — product decision.** Reconcile before signing any uptime SLA. Supersedes/merges R-07 |
| EA-04 | Payment → entitlement grant not exercised end-to-end (live Razorpay capture → tier upgrade → feature unlock) | S1 (revenue) | Not exercised this pass; billing suites green in CI only | **PARTLY RESOLVED (2026-07-02):** full path now proven end-to-end through the real worker in `paymentEntitlementE2E.test.mjs` — HMAC-signed verify → `users.tier` write + `subscriptions` row → JWT minted with tier → previously-402 PRO endpoint returns 200; tampered signature grants nothing; STARTER does not over-grant. Remaining: one live Razorpay pilot transaction (needs a real card/UPI — owner action) |
| EA-05 | SSO/SAML + MFA advertised (ENTERPRISE) but not live-verified (no IdP/TOTP round-trip evidence) | S2 | Handlers/schema/tests present; no live proof | **PARTLY RESOLVED** — SSO (OIDC) verified wired: `/api/auth/sso/login|callback` live (400/302), `/api/admin/sso/config` owner-gated (live 403), issuer validated via `discoverOIDC` before save. MFA gate bug fixed (EH-02). Full code-path round-trips now proven in `mfaSsoRoundTrip.test.mjs`: MFA setup→computed-TOTP enable→backup codes→challenge login→replay/burn semantics, and SSO PKCE login→RS256 id_token verify (nonce/aud/iss)→user provisioning at org plan→platform JWT that authenticates. Remaining: one live round-trip against a customer's actual IdP at onboarding (needs their tenant) |

## Enterprise Trust & Auth hardening pass (2026-07-02) — new entries

| ID | Risk | Sev | Evidence | Disposition |
|----|------|-----|----------|-------------|
| EH-01 | Uptime metric conflated availability with latency: `uptime_pct = operational/total` counted every `degraded` (slow-but-up) sample as downtime → indefensible "95.8% uptime with 0 outage_events". Marketing showed a fabricated `99.97%` measured-uptime tile. | S1 (trust/legal) | Live `/api/uptime` 95.8% vs 0 outages; `frontend/index.html:5190` hardcoded 99.97% | **CLOSED**: uptime engine now reports availability (responded = operational+degraded), with `degraded_pct` disclosed separately; fabricated 99.97% relabeled to honest "99.9% Uptime SLA Target". Tests: `uptimeAvailability.test.mjs` (3) |
| EH-02 | **MFA anonymous-enrollment bug (security):** `/api/auth/mfa/setup|enable|disable` gated on `authCtx.authenticated`, which `resolveAuthV5` sets `true` for the anonymous IP-fallback tier (user_id=null). An unauthenticated caller minted a TOTP secret bound to a null user (`otpauth …:null`, shared KV key `mfa_setup:null`). | S1 (security) | Live: anon `POST /api/auth/mfa/setup` → 200 with `:null` secret | **CLOSED**: gate now requires a concrete `user_id`. Tests: `mfaAuthGate.test.mjs` (4) |
| EH-03 | **Systemic authz smell:** `authCtx.authenticated` is `true` for the anonymous IP-fallback tier, so all ~146 `if (!authCtx.authenticated)` gates fail to require login. Most are read paths that return empty for a null user (low impact); write/state paths (MFA) were exploitable. `/api/keys` etc. use stronger checks and correctly 401. | S2 | 146 call sites; MFA confirmed exploitable, now fixed | **CLOSED (2026-07-02, EH-04 pass):** canonical `isRealUser(authCtx)` added to `auth/middleware.js`; all 158 gate sites audited, 41 route gates in `index.js` + 40 handler/service files migrated. Deliberately preserved: anonymous scan funnel (`/api/scan/*` sync), public SIEM format info (GET), tier-only gates, invalid-key abuse signals. Also fixed en route: `/api/auth/status` reported `authenticated:true` to anonymous/garbage-key callers (key-validation UIs accepted invalid keys); four dead-admin gates (`authCtx.role`/tier `ADMIN` checks that never pass — `/api/mcp/revenue/*` 403'd everyone incl. admin, `revenueMetrics` was conversely open to all, `revenueIntelligence`/`commercializationEngine` admin routes dead) now use `isAdmin`. Tests: `authGateRealUser.test.mjs` (25). |

---

## Closed this pass (2026-07-02)

| ID | Risk | Sev | Evidence | Resolution |
|----|------|-----|----------|------------|
| R-01 | Uncaught handler exceptions returned Cloudflare 1101 HTML — no CORS, no JSON envelope, no error record, invisible to ops. 841 routes / 117 dynamic imports guarded by only 57 route-local try blocks; `resolveAuthV5` (D1-backed) called outside try on dozens of routes. | S1 | `workers/src/index.js` pre-change: no top-level try in `fetch()` | Global exception boundary in exported `fetch()`: structured 500 (`ERR_UNHANDLED`) + `system_errors` record + deduped ops alert. Locked by `test/globalErrorBoundary.test.mjs` |
| R-02 | Request correlation broken: caller `X-Request-ID` generated then dropped; every response minted a fresh random ID (`middleware/security.js:56`), so client logs could never be joined to worker logs. | S2 | `index.js:1320` (unused var), `security.js:56` | Guard stamps the propagated/minted ID on every response + emits one structured JSON access-log line per API request (`event:"request"` with status + dur_ms) |
| R-03 | No automated database backup existed. `INCIDENT_RESPONSE_RUNBOOK.md` referenced "the last automated backup" that did not exist; `docs/audit-history/DATABASE_GAP_ANALYSIS.md` item 8 open. | S1 | No backup workflow in `.github/workflows/` before this pass | `.github/workflows/d1-backup.yml`: nightly 02:30 UTC full `d1 export`, integrity gate, SHA-256, 30-day artifact retention |
| R-04 | Schema migrations were untracked laptop operations — no pre-migration backup, no audit trail, no rollback point. | S1 | wrangler.toml comments direct manual `d1 execute`; ~60 `schema_*.sql` files with no ledger | `.github/workflows/db-migrate.yml`: typed-APPLY gate, pre-migration export artifact (90-day), post-migration sanity check |
| R-05 | No disaster-recovery documentation: no RPO/RTO, no restore procedure, no store-by-store recovery map. | S1 | No DR runbook existed | `DISASTER_RECOVERY_RUNBOOK.md`: per-store RPO/RTO, restore paths (export, Time Travel, new-DB cutover), scenario playbooks, quarterly drill cadence |

---

## Open — action recommended

| ID | Risk | Sev | Evidence | Recommended action | Owner |
|----|------|-----|----------|--------------------|-------|
| R-06 | **Restore has never been drilled.** Backups now exist but restorability is unproven; the export contains non-idempotent `CREATE TABLE` sections (restore into non-empty DB can error). | S1 | `d1-backup.yml` new this pass; no drill record | **RESOLVED (2026-07-06):** shipped `scripts/d1-restore-drill.mjs` — offline drill that restores a dump into a throwaway SQLite DB, runs `PRAGMA integrity_check`, asserts table/row counts + SHA-256. Proven both directions (valid→pass, corrupt/truncated/tampered→fail) in `restoreDrill.test.mjs` (6) and wired into DR runbook §3.0 as the mandatory pre-restore pre-flight. First scheduled run against a REAL nightly artifact went green 2026-07-06 08:56 UTC (run `28779799461`: located latest backup → downloaded → restored → integrity-checked, all 7 steps passed in 26s). Closed |
| R-07 | **Uptime numbers disagree with marketing.** Live `/api/uptime` reports 95.8% (24h) / 95% (7d) with 0 outage events (degraded-latency samples counted as downtime), while public pages claim "99.9%/99.97% uptime". Enterprise buyers will check. | S2 | Live probe 2026-07-02: `avg_latency_ms` 331, `max` 1505, `downtime_minutes` 60/24h, `outage_events` 0 | Align definitions: publish "availability" (outage-based) separately from "latency SLO"; or fix degraded-as-downtime accounting in the uptime engine | Platform owner |
| R-08 | **D1 read latency elevated.** Health probes measure 241–247 ms D1 round trips; operational history avg 331 ms, max 1505 ms — above the 1000 ms degraded threshold at p-max. Every D1-backed endpoint carries this floor. | S2 | Live `/api/health` + `/api/uptime` probes 2026-07-02 | Investigate D1 region placement vs Worker execution colo; consider read caching for hot queries (edge cache / KV) on top-traffic endpoints | Platform eng |
| R-09 | **Hourly cron fan-out vs plan limits.** The hourly slot launches ~15 parallel pipelines (ingestion, radar, federation, SOC, GTM, revenue…). wrangler.toml notes the account is on the CF Free plan (5-cron cap); Free-plan subrequest/CPU ceilings can silently truncate pipelines. | S2 | `index.js` scheduled(); wrangler.toml cron comment | Confirm Workers Paid plan; if Free, stagger pipelines across slots or move heavy ingestion to Queue consumers | Platform owner |
| R-10 | **Single-operator on-call** (bus factor 1). All alerts route to one Telegram admin chat. | S2 | `EOP_v1_REPORT.md` §7; alerts config | Document a deputy + escalation path; even a non-technical "call the operator" secondary reduces MTTA risk | Business owner |
| R-11 | **No external uptime probe.** All monitoring runs inside the platform being monitored — a total Worker outage also silences health recording (cron-seeded `operational_history`). | S2 | EOP report §7 open item | Cloudflare Healthchecks (~10 min dashboard task) pointed at `/api/platform/health` | Platform owner |
| R-12 | **Backup archive ceiling: 30 days** (GitHub artifact retention). No long-term/compliance archive. | S3 | `d1-backup.yml` `retention-days: 30` | Add a step shipping the dump to R2 (or external storage) for 1-year archive when compliance requires | Platform eng |
| R-13 | **Bundle growth.** Worker bundle is 1.29 MB gzip (5.5 MB raw) — 43% of the Free-plan 3 MB cap; 216-table schema and 155 handlers keep growing. | S3 | Measured this pass via `wrangler deploy --dry-run` | Add a CI bundle-size threshold warning (e.g. fail >2.5 MB gzip); prune dead handlers on major versions | Platform eng |

---

## Accepted — documented by design

| ID | Risk | Sev | Rationale |
|----|------|-----|-----------|
| R-14 | KV rate-limit counters are read-modify-write (not atomic); concurrent bursts can overshoot limits by a bounded margin. | S3 | Cloudflare KV has no atomic increment. Correct fix is Durable Objects — a redesign not justified by current abuse levels. Fails open on KV outage (availability over enforcement) — intentional. |
| R-15 | Queue DLQ (`scan-jobs-dlq`) is effectively bypassed: consumer acks permanent failures at attempt ≥3 after recording failure state to KV/D1. | S3 | Explicit failure recording in `scan_jobs` is the operative dead-letter record; DLQ remains as a safety net for consumer crashes only. |
| R-16 | KV and Queues are not backed up. | S3 | Counters/caches/in-flight jobs are rebuildable; restoring stale counters would be worse than losing them (see DR runbook §2.4). |
| R-17 | Worker route `cyberdudebivash.in/api/*` is dashboard-managed, not in wrangler.toml. | S3 | CI token lacks Zone:Workers Routes:Edit by least-privilege choice; route re-creation is a documented manual step in DR runbook §3.6. |
| R-18 | Scan-job dedup window (1 h KV TTL) means a repeated scan of the same target returns the earlier job. | S3 | Intentional cost/abuse control; documented in `lib/queue.js`. |
