# Production Hardening Kit
**CYBERDUDEBIVASH AI Security Hub™** — closes the open certification gaps (R1–R7)

This folder contains review-ready, low-regression artifacts that address every gap from the Production Readiness Certification. Each is **additive** (new files / new CI jobs) — nothing overwrites working production code, so regression risk is minimal. Apply in the order below.

---

## Gap → fix map

| Gap | Severity | Fix in this kit | Action to apply | Regression risk |
|---|---|---|---|---|
| **R1** Fixes not deployed | P1 | (prior session) `frontend/index.html` + `cdb-mobile-responsive.css` + `threatHunting.fixed.js` | `git add … && git commit && git push`; apply Defender-safe handler; `wrangler deploy` | Low (additive/CSS @media-scoped) |
| **R2** CSP `unsafe-inline` | P2 | `_headers.csp-hardening.txt` (report-only rollout) | Add Report-Only line; collect reports; then enforce | None (report-only blocks nothing) |
| **R3** Perf unvalidated | P2 | `lighthouserc.json` + `test.yml` lighthouse job | Copy to repo root; CI runs it | Low |
| **R4** No test suite | P2 | `handlers.unit.test.mjs`, `vitest.config.mjs`, `smoke.spec.mjs`, `test.yml` | Copy into `workers/test/`, `tests/e2e/`, `.github/workflows/` | Low (additive) |
| **R5** Funnel uninstrumented | P2 | `cdb-analytics.js` | Copy to `frontend/assets/`; add `<script defer>`; call `CDBAnalytics.track()` at checkpoints | Low (no-op until fired) |
| **R6** Stale duplicate | P3 | (manual) remove `workers/frontend/index.html` | `git rm workers/frontend/index.html` after confirming it is unused | Low |
| **R7** Rollback un-rehearsed | P3 | `DR_ROLLBACK_RUNBOOK.md` | Adopt; run the quarterly drill checklist | None (doc) |

---

## Apply steps (copy commands — run from repo root on your machine)

```bash
# R4 — tests + CI
mkdir -p workers/test tests/e2e
cp hardening/handlers.unit.test.mjs workers/test/
cp hardening/vitest.config.mjs       workers/
cp hardening/smoke.spec.mjs          tests/e2e/
cp hardening/test.yml                .github/workflows/
cp hardening/lighthouserc.json       ./           # R3

# add to workers/package.json: "scripts": { "test": "vitest run" }, devDep "vitest": "^2.0.0"
cd workers && npm i -D vitest && npx vitest run    # verify green locally
cd ..

# R5 — funnel instrumentation
cp hardening/cdb-analytics.js frontend/assets/
# then add to <head> of pages: <script src="/assets/cdb-analytics.js" defer></script>
# and call CDBAnalytics.track('scan_started') etc. at each funnel checkpoint

# R2 — CSP (safe, report-only first) : follow _headers.csp-hardening.txt

# R7 — adopt DR_ROLLBACK_RUNBOOK.md ; schedule the quarterly drill
```

---

## Funnel instrumentation checkpoints (R5)

Wire `CDBAnalytics.track(event)` at these points so the revenue funnel becomes measurable:

| Checkpoint | Event | Where |
|---|---|---|
| Scan button click | `scan_started` | scan CTA handler |
| Scan result rendered | `scan_completed` | after results paint |
| Report paywall shown | `report_viewed` | report card render |
| Unlock CTA tapped | `unlock_clicked` | unlock button |
| Razorpay opened | `checkout_started` | checkout init |
| Payment success | `purchase_completed` | payment webhook/return |
| Subscription active | `subscription_started` | post-subscribe |
| Tier limit reached | `tier_limit_hit` | limit guard |
| Consult booked | `consult_booked` | booking confirm |

A `page_view` (device-segmented) fires automatically on load.

---

## What this kit does NOT do (still requires your runtime action)

- **Deploy** to production (R1) — that is your push; the board keeps that gate under human control.
- **Run** the live Lighthouse / pen-test / load drill — the configs are here; execution happens in your CI / a connected browser.

Once these run green with evidence, the certification upgrades from **GO WITH CONDITIONS** toward **GO (unconditional)** on real measurements.
