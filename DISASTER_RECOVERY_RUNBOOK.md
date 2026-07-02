# CYBERDUDEBIVASH® — Disaster Recovery Runbook

**Version:** 1.0 | **Effective:** 2026-07-02 | **Owner:** bivash@cyberdudebivash.com
**Scope:** Production platform at `cyberdudebivash.in` (Cloudflare Workers + D1 + KV + R2 + Queues + Pages)

---

## 1. Data Stores & Recovery Objectives

| Store | Binding | Contents | Durability source | RPO (target) | RTO (target) |
|---|---|---|---|---|---|
| **D1** (`cyberdudebivash-security-hub`) | `SECURITY_HUB_DB` | Users, API keys, payments, scan history, threat intel, audit/ops data — **the system of record** | Nightly SQL export (GitHub artifact, 30d) + Cloudflare D1 Time Travel | ≤24 h via export; near-zero via Time Travel within its window | ≤4 h |
| **KV** (`SECURITY_HUB_KV`) | `SECURITY_HUB_KV` | Rate-limit counters, job status, caches, dedup locks, session-ish state | None — **treated as rebuildable cache** | N/A (loss = degraded, not data loss) | Self-heals; TTL'd keys repopulate |
| **R2** (`cyberdudebivash-scan-results`) | `SCAN_RESULTS` | Full scan result JSON payloads | Cloudflare R2 durability; metadata mirrored in D1 (`scan_jobs.r2_key`) | Provider-managed | ≤4 h |
| **Queues** (`scan-jobs`, `scan-jobs-dlq`) | `SCAN_QUEUE` | In-flight scan jobs | Transient by design; jobs are re-submittable | N/A | Self-heals |
| **Worker code** | — | Platform logic | Git (GitHub) + Cloudflare versioned deployments | 0 (git) | Minutes (rollback) |
| **Secrets** | — | JWT, Razorpay, provider keys, payment rails | Wrangler secret store only — **not in git by design** | Manual re-entry | ≤1 h with the secret manifest in `workers/wrangler.toml` comments |

**Design position:** D1 is the only store whose loss is a disaster. KV and Queues are rebuildable. R2 loss degrades historical report downloads but D1 retains scan metadata.

---

## 2. Backups — What Exists and Where

### 2.1 Nightly automated D1 export (primary backup)
- **Workflow:** `.github/workflows/d1-backup.yml`, runs 02:30 UTC nightly + on demand (`workflow_dispatch`).
- **Artifact:** `d1-backup-<UTC-stamp>` on the workflow run — gzipped full SQL dump, **30-day retention**, SHA-256 recorded in the run summary.
- **Integrity gate:** run fails loudly if the dump is empty, <10 KB, or has <10 `CREATE TABLE` statements — a failed nightly backup shows as a red run in Actions.

### 2.2 Cloudflare D1 Time Travel (secondary)
- D1 keeps automatic point-in-time restore history (30 days on paid plans; shorter on free — verify your plan's window in the Cloudflare dashboard before relying on it).
- Restore is **in-place** to a past timestamp — use for "bad migration 20 minutes ago", not for off-platform archival.

### 2.3 Pre-migration snapshots
- Every gated migration (`.github/workflows/db-migrate.yml`) takes a **full export first** and uploads it with **90-day retention** before touching the schema. A migration with a failed backup step aborts before applying anything.

### 2.4 What is deliberately NOT backed up
- **KV** — counters/caches/dedup keys; restoring stale counters would be worse than losing them.
- **Queues** — in-flight jobs; customers can re-run scans, and `scan_jobs` in D1 records what was queued.

---

## 3. Restore Procedures

### 3.0 Pre-flight — prove the artifact is restorable BEFORE touching any D1
Run the offline restore drill first. It restores the dump into a throwaway
SQLite database, runs `PRAGMA integrity_check`, and asserts table/row counts —
no Cloudflare access, no risk to production. A backup that fails this is not a
backup; do not proceed to 3.1 with it.
```bash
# 1. Fetch the artifact (GitHub → Actions → "Nightly D1 Backup" → latest green run
#    → Artifacts → download d1-backup-<stamp>.sql.gz). Note the SHA-256 printed
#    in that run's job summary.
# 2. Prove it restores (Node 22.5+ has the built-in engine; no install needed):
node scripts/d1-restore-drill.mjs d1-backup-<stamp>.sql.gz \
  --expect-sha256 <sha256-from-job-summary> --min-tables 200
#    → "RESTORE DRILL PASSED" + a RESTORE_DRILL_RESULT evidence line = artifact is good.
#    → any "RESTORE DRILL FAILED" = corrupt/tampered/truncated; use the previous
#      night's artifact or Time Travel (3.2) instead.
```

### 3.1 D1 — full restore from nightly export
```bash
# 1. Fetch the artifact (GitHub → Actions → "Nightly D1 Backup" → latest green run)
gunzip d1-backup-<stamp>.sql.gz

# 2. OPTION A — restore into the live database (DESTRUCTIVE — take a fresh export first!)
cd workers
npx wrangler d1 export cyberdudebivash-security-hub --remote --output /tmp/pre-restore-safety.sql
npx wrangler d1 execute cyberdudebivash-security-hub --remote --yes --file ../d1-backup-<stamp>.sql

# 3. OPTION B — restore into a NEW database and cut over (safer for total corruption)
npx wrangler d1 create cyberdudebivash-security-hub-restore
npx wrangler d1 execute cyberdudebivash-security-hub-restore --remote --yes --file ../d1-backup-<stamp>.sql
#    → update database_id in workers/wrangler.toml → deploy → verify → keep old DB for forensics

# 4. Verify
npx wrangler d1 execute cyberdudebivash-security-hub --remote \
  --command "SELECT COUNT(*) FROM users; SELECT COUNT(*) FROM threat_intel;"
curl -s https://cyberdudebivash.in/api/platform/health | head -c 400
```
> The exported dump contains `CREATE TABLE` statements without `IF NOT EXISTS` guards in some sections; restoring **into a non-empty database** can error on existing tables. For partial-loss scenarios prefer Time Travel (3.2); for full-loss restore into a fresh database (Option B).

### 3.2 D1 — Time Travel (point-in-time, e.g. bad migration/bulk delete)
```bash
cd workers
# Find the current bookmark / verify availability
npx wrangler d1 time-travel info cyberdudebivash-security-hub

# Restore to a timestamp BEFORE the incident (UTC, RFC3339)
npx wrangler d1 time-travel restore cyberdudebivash-security-hub \
  --timestamp "2026-07-02T02:00:00Z"
```
Then re-run any legitimate writes that occurred after that timestamp (payments: reconcile against Razorpay dashboard — it is the source of truth for money).

### 3.3 Worker code — rollback
```bash
cd workers
npx wrangler rollback            # reverts to the previous deployed version
# or: Cloudflare Dashboard → Workers → cyberdudebivash-security-hub → Deployments → Rollback
```
Verify: `curl -s https://cyberdudebivash.in/api/version` (check `commit`), then `/api/platform/health`.

### 3.4 Frontend (Pages) — rollback
Cloudflare Dashboard → Workers & Pages → `cyberdudebivash-security-hub` (Pages) → Deployments → ⋯ → **Rollback to this deployment**. The self-healing frontend force-reloads stale browsers off `version.json`.

### 3.5 Secrets — loss or compromise
Full manifest with generation commands lives in `workers/wrangler.toml` (comment block). Compromise procedure (rotate + revoke sessions) is in `INCIDENT_RESPONSE_RUNBOOK.md` → "SEV-1: Security Breach".

### 3.6 Configuration rollback
`wrangler.toml` is in git — `git revert` the change and redeploy. Dashboard-managed state that is **not** in git and must be re-checked after any account-level incident:
- Worker route `cyberdudebivash.in/api/*` (dashboard-managed by design — see wrangler.toml comment)
- Custom domains on Pages
- Queue + DLQ existence (`scan-jobs`, `scan-jobs-dlq`)
- Cron triggers (5 slots — redeployed from wrangler.toml on every deploy)

---

## 4. Scenario Playbooks

| Scenario | First move | Restore path | Data loss expectation |
|---|---|---|---|
| Bad deploy (500s spike) | `wrangler rollback` | 3.3 | None |
| Bad migration (schema broke handlers) | Stop writes if possible | Time Travel to pre-migration (3.2), or pre-migration artifact (3.1-A) | Writes since migration |
| Bulk data corruption/deletion | Identify timestamp | Time Travel (3.2) | Writes since timestamp |
| D1 database lost entirely | Create new DB | Nightly export → Option B (3.1) | ≤24 h (last nightly) |
| KV namespace lost | Recreate namespace, update ID in wrangler.toml, deploy | None needed — caches/counters rebuild | Rate-limit windows reset; job-status reads 404 briefly |
| R2 bucket lost | Recreate bucket | D1 `scan_jobs` still lists all scans; historical report payloads gone | Historical raw results |
| Cloudflare account lockout/compromise | Recover account with CF support; rotate `CLOUDFLARE_API_TOKEN` | Redeploy from git + restore D1 from GitHub artifact (off-platform copy) | ≤24 h |
| Razorpay webhook outage | Payments reconcile: Razorpay dashboard → replay webhooks | `manualPayments` flow continues independently | None (Razorpay is source of truth) |

---

## 5. DR Verification Cadence

| Check | How | Frequency |
|---|---|---|
| Nightly backup is green | GitHub Actions → "Nightly D1 Backup" — failure = red run | Automatic; review weekly |
| Backup restorability drill (offline) | `node scripts/d1-restore-drill.mjs <artifact.sql.gz> --expect-sha256 <sha> --min-tables 200` — restores into a throwaway SQLite DB, asserts integrity + table/row counts. No Cloudflare access needed. | Per first-of-month artifact; and before any real restore (§3.0) |
| Backup restorability drill (live scratch D1) | Restore latest artifact into a scratch D1 (`wrangler d1 create dr-drill-<date>`), assert table count ≥ 200, then delete | Quarterly |
| Rollback drill | `wrangler rollback` in a low-traffic window, verify `/api/version`, roll forward | Quarterly |
| Time Travel availability | `wrangler d1 time-travel info` — confirm bookmark window matches plan expectation | Monthly |
| Secret manifest accuracy | Diff `wrangler secret list` against the manifest in wrangler.toml | On every secret addition |

---

## 6. Known Limitations (accepted, documented)

1. **RPO for D1 is up to 24 h** via export (Time Travel narrows this within its window, same-account only). Tightening RPO further would need streamed replication (e.g., cron `d1 export` to R2 every N hours) — revisit when paying customers hold >24 h of unreplaceable data.
2. **GitHub artifact retention is 30 days** — there is no >30-day archive. For compliance-grade retention, add a step shipping the dump to R2 or external object storage.
3. **KV loss resets rate-limit counters** — brief over-serving of free-tier quota after a KV disaster is accepted.
4. **Dashboard-managed route** is a manual re-creation step after account-level disasters (documented above; not automatable with the current CI token permissions).
