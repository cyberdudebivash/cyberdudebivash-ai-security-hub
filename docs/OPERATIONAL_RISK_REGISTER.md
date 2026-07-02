# Operational Risk Register — Living Document

> Canonical register of operational risks for the production platform.
> Every entry carries evidence, impact, and current disposition. Update the
> disposition when a risk is closed or accepted; add new risks at the bottom.
> Point-in-time context: `docs/audit-history/ENTERPRISE_OPERATIONS_READINESS_2026-07.md`.

**Last reviewed:** 2026-07-02 (Enterprise Operations Readiness pass)

| Sev | Likelihood | Meaning |
|---|---|---|
| S1 | — | Customer-visible outage / data loss / revenue loss |
| S2 | — | Degraded service, ops blind spot, or recovery slower than SLA |
| S3 | — | Hygiene / efficiency / future scaling constraint |

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
| R-06 | **Restore has never been drilled.** Backups now exist but restorability is unproven; the export contains non-idempotent `CREATE TABLE` sections (restore into non-empty DB can error). | S1 | `d1-backup.yml` new this pass; no drill record | Run the quarterly drill from DR runbook §5 once now: restore latest artifact into a scratch D1, assert ≥200 tables | Platform owner |
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
