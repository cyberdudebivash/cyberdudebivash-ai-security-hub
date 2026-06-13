# Disaster Recovery & Rollback Runbook
**CYBERDUDEBIVASH AI Security Hub™** — closes gap R7 (rollback/DR documented but un-rehearsed)

Owner: Platform SRE · Review cadence: quarterly · Last updated: June 2026

---

## 1. Architecture recovery map

| Tier | Service | State | Recovery primitive |
|---|---|---|---|
| Edge frontend | Cloudflare Pages (`frontend/`) | Stateless | Instant rollback to previous deployment |
| API | Cloudflare Worker (`workers/src/index.js`) | Stateless | `wrangler rollback` / redeploy prior version |
| Relational | D1 (`cyberdudebivash-security-hub`) | Stateful | Time-travel restore + migrations |
| Cache | KV namespace | Soft state | Rebuildable; no restore needed |
| Artifacts | R2 (`cyberdudebivash-scan-results`) | Stateful | Versioning / lifecycle; re-generatable |
| Async | Queues (producers/consumers) | In-flight | Drain + replay; dead-letter inspection |

---

## 2. Rollback procedures (rehearse each quarterly)

### 2.1 Frontend (Cloudflare Pages)
1. Cloudflare dashboard → Pages → `cyberdudebivash-security-hub` → Deployments.
2. Select the last-known-good deployment → **Rollback to this deployment**.
3. Verify: `curl -s https://cyberdudebivash.in/version.json` shows the prior build id.
4. Smoke: load homepage, confirm no error banner, run a test scan.
- **CLI alternative:** `wrangler pages deployment list` → redeploy the good commit.

### 2.2 Worker API
1. `cd workers && npx wrangler deployments list`
2. `npx wrangler rollback [DEPLOYMENT_ID]` (or `git revert` + `npx wrangler deploy`).
3. Verify: `curl -s https://cyberdudebivash.in/api/health` returns `status: ok` and the expected version.

### 2.3 D1 database
- **Point-in-time:** `wrangler d1 time-travel restore cyberdudebivash-security-hub --timestamp <ISO>`
- **Forward-fix:** apply a corrective migration; never hand-edit production rows.
- Always `wrangler d1 export` a snapshot **before** any schema migration.

---

## 3. Incident response (severity-driven)

| Severity | Definition | First action | Target |
|---|---|---|---|
| P0 | Full outage / data loss | Rollback frontend+Worker to last-good; status page | < 15 min to mitigate |
| P1 | Core flow broken (scan/checkout/auth) | Roll back the offending tier; feature-flag off | < 30 min |
| P2 | Significant feature degraded | Hotfix forward or flag off | < 4 h |
| P3 | Minor | Normal backlog | next release |

**Decision rule:** mitigate first (rollback), diagnose second. Never debug forward on a P0/P1 while users are impacted.

---

## 4. DR drill checklist (run quarterly, record evidence)

- [ ] Frontend rollback executed and verified (screenshot version.json before/after)
- [ ] Worker `wrangler rollback` executed against a staging version and verified
- [ ] D1 time-travel restore tested on a non-prod copy
- [ ] Queue backlog drain + dead-letter replay tested
- [ ] Smoke test (`hardening/smoke.spec.mjs`) green post-rollback
- [ ] Mean-time-to-recover recorded; gaps logged

---

## 5. Pre-deploy safety gates (already in `deploy.yml` — keep enforced)

- Preflight validates critical files + secrets before any deploy.
- Smoke test: 5 attempts × exponential backoff per endpoint; hard-fail only on all-unreachable.
- Version gate: deployed version compared to `PLATFORM_VERSION`.
- Concurrency: `deploy-production` group serializes deploys (no partial/overlapping).

> Add the `Test & Quality Gate` workflow (`hardening/test.yml`) as a required status check so no deploy proceeds on a failing unit/Lighthouse/E2E gate.
