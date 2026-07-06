# KPI Dashboard — Living Document

> **The only scoreboard.** Per `docs/ENGINEERING_STANDARDS.md` §12, product
> progress is measured by these outcome metrics — never by feature, commit,
> or test counts. Per §10 (Verifiable-Statement Rule) every value below is
> evidence-backed or written as **UNKNOWN**; per §11 (Production Truth Law)
> production observation outranks every other source. Reviewed weekly by
> CORB; updated whenever new evidence lands.
>
> **Baseline date:** 2026-07-04 · **Production build:** `c4cdbb9`

| KPI | Current value | Evidence / source | Cadence |
|-----|---------------|-------------------|---------|
| Customer onboarding success rate | 100% simulated (100/100 orgs; every live RC/GA/CEAP journey since) · **no real customers yet** | Phase VIII harness; CEAP sweep step 2 | Per CEAP sweep (6 h) |
| Time to first value (TTFV) | **~7 s** live cold scan (first request → scan result); 0.4 s warm-cache lab | Post-GA lifecycle pass; CEAP sweep timings | Per CEAP sweep |
| Production incident rate | 2 lifetime (IR-1, IR-2), **0 since GA** | Incident Review Register (`OPERATIONAL_EXCELLENCE_REPORT.md` §4) | Per incident |
| Mean time to detect (MTTD) | Historically customer/audit-first (unbounded); **bounded ≤ 6 h** for journey regressions by the CEAP sweep; **bounded ≤ 15 min** for Workers runtime-error spikes by `error-rate-alert.yml` (CI-1); **bounded ≤ 24 h** for schema drift (the RC-B1 class) by the new `d1-schema-drift.yml` (CI-2) — both CI-1 and CI-2 are code shipped + unit-tested this cycle (12 + 19 tests, full suite 1,433/1,433 green), **first live-production runs are still-open evidence** for both; deliberately-returned 5xx from caught application errors remain outside the error-rate signal (stated limitation, not silently assumed away) | `ceap-assurance.yml` + `error-rate-alert.yml` + `d1-schema-drift.yml` schedules | Weekly (CORB) |
| Mean time to recover (MTTR) | **Same-day** for both lifetime incidents (found → root-caused → fixed → locked → deployed → live-verified within hours) | IR-1/IR-2 records; deploy timestamps | Per incident |
| Customer satisfaction (CSAT) | **UNKNOWN — no real customers** | — | When real customers exist |
| Renewal rate | **UNKNOWN — no real customers** | — | When real customers exist |
| Expansion rate | **UNKNOWN — no real customers** | — | When real customers exist |
| Support resolution time | **UNKNOWN — no real tickets**; playbook diagnostics verified accurate against production | Support-doc accuracy audit (OER §3) | Per ops cycle |
| Regression rate | **0** — no RESOLVED objection or locked defect has re-observed behavior | Objection Register recurrence check; 1,433-test suite green | Per CEAP sweep + suite |
| Documentation accuracy | Audited against live production; 2 imprecisions found and corrected in the last audit (429 headers, key-usage semantics); 0 known open drifts | OER §3 audit table | Per ops cycle |
| AI confidence calibration | **UNKNOWN** — confidence is reported (e.g. 94) and grounding/honesty are regression-locked, but no calibration eval harness exists (backlog E-4) | `mythosAnalystGrounding`, live analyze probes | When eval harness ships |
| Deployment success rate | **100% recent window** — 9 consecutive green gated deploys (#618–#626), incl. 5 same-day releases through test→deploy→smoke | GitHub Actions deploy.yml history | Per deploy |
| Recovery drill success rate | **100% (1/1)** — first scheduled run (2026-07-06 08:56 UTC) restored the latest real nightly backup artifact and passed integrity + table-count checks in 26s; restore script regression-tested both directions | `d1-restore-drill.yml` run #1 (`28779799461`, all 7 steps green); `restoreDrill.test.mjs` | Weekly (scheduled) |
| Release blocker aging | 5 open blockers (GA-O1…O5), **all owner-action, all aged 0 days** (opened 2026-07-04); 0 open code-level blockers | GA Blocker Board (`GENERAL_AVAILABILITY_REPORT.md` §5) | Weekly (CORB) |

## Reading this dashboard

- **Green story:** reliability, recovery speed, deployment discipline, truth
  discipline (regressions, docs) are all measured and healthy.
- **Honest story:** every customer-outcome KPI (CSAT, renewal, expansion,
  support) is UNKNOWN for one reason — **zero real customers**. The single
  action that converts the most UNKNOWNs to measurements remains GA-O1: one
  real payment through the already-verified live order flow.
- **Update protocol:** values change only with named evidence. An UNKNOWN is
  never replaced by an estimate.
