# Enterprise Capability Registry — Schema

**Status:** Living register. This is a CEAP instrument
(`docs/ENGINEERING_STANDARDS.md` §10, §12) — not a new phase or framework.
Per the Standing Engineering Directive (§13), the governance architecture is
closed: no new phases, no new frameworks. This registry is the missing
machine-readable evidence store that CEAP's existing instruments (the
`ceap-sweep.mjs` synthetic sweep, the per-cycle documentation-accuracy audit)
should read from and write to, joining the other living registers already
indexed in `DOCUMENTATION_INDEX.md` (Customer Objection Register,
Operational Risk Register).

## 0. Why this exists (read before editing anything here)

A forensic pass found this repository already has 30+ prior narrative
"certification/readiness" markdown documents (`docs/audit-history/*.md` plus
several root-level reports). None are machine-readable, none require
file:line evidence consistently, and none are checked by CI. The result:
`GENERAL_AVAILABILITY_REPORT.md` — the document `DOCUMENTATION_INDEX.md`
names as the **current** GA decision — certifies Organizations and Auth as
"GA APPROVED, live-verified," and both are false. Organizations has **zero**
frontend UI; the login entry point is a dead-end modal. That error was
written 2026-06-12 and rode unchallenged through four subsequent audits,
because `GENERAL_AVAILABILITY_REPORT.md` itself states prior evidence "is not
re-litigated."

Root cause, confirmed by direct inspection: `scripts/ceap-sweep.mjs` verifies
Organizations by calling `POST /api/orgs`, `GET /api/orgs/{id}/dashboard`, and
`GET /api/orgs/{id}/scans` **directly via `fetch`**. That is real, valid
backend verification — and it was generalized into a whole-capability GA
claim, even though no frontend page calls any of those endpoints. **The one
job of this registry's schema is to make "the API works" and "a customer can
use this" structurally different, separately-tracked facts, so that specific
mistake cannot happen again.** See `verification.method` below — it is the
load-bearing field in this schema.

This registry also does not compete with `KPI_DASHBOARD.md`, which
`docs/ENGINEERING_STANDARDS.md` §12 designates as the only *outcome*
scoreboard (onboarding time, MTTD/MTTR, CSAT). This registry tracks
*structural completeness and parity* (does the UI exist, is it wired, is it
reachable) — an engineering inventory that feeds CORB's weekly review and the
CIP backlog, not a rival measurement of customer outcomes.

## 1. File layout

```
docs/capability-registry/
  SCHEMA.md                    — this file
  domains/*.json                — one file per domain, array of capability entries
  exceptions.json               — accepted/deliberate gaps (mirrors workers/schema_drift_accepted.json's pattern)
  PRODUCTION_READINESS_REPORT.md  — GENERATED from domains/*.json by scripts/registry/generate-report.mjs. Never hand-edit.

scripts/registry/
  extract-handlers.mjs   — enumerates handler files + exported function names (the stable evidence unit)
  extract-routes.mjs     — best-effort route extraction from workers/src/index.js (if-chain + object-literal tables)
  cross-reference.mjs    — greps frontend/*.html and workers/test/**/*.mjs for evidence per handler
  validate.mjs           — schema + evidence-resolution + staleness checks (CI entry point)
  generate-report.mjs    — renders PRODUCTION_READINESS_REPORT.md from domains/*.json
```

No new npm dependency was introduced for any of this — plain Node.js ESM,
JSON instead of YAML, matching the existing zero-dependency convention in
`scripts/d1-schema-diff.mjs` and friends (Node 18+, no `package.json` at
repo root).

## 2. Capability entry schema

One JSON object per customer-recognizable capability (not one per raw HTTP
route — see §3 for why). Required shape:

```jsonc
{
  "id": "CAP-ORG-001",                 // stable, never reused even if the capability is removed
  "domain": "organizations",           // a tag, not a person — this is a single-operator business
  "name": "Organization Management",
  "description": "Create/list/manage organizations, invite members, assign roles.",

  "backend": {
    "handlers": ["workers/src/handlers/orgManagement.js"],
    "entry_points": ["handleCreateOrg", "handleListOrgs", "handleGetOrg", "..."],
    // entry_points (exported function names) is the STABLE evidence unit —
    // reliable regardless of routing idiom (if-chain / object-literal table /
    // prefix dispatcher). routes_sampled below is best-effort, not exhaustive.
    "routes_sampled": [
      { "path": "/api/orgs", "method": "POST", "evidence": "workers/src/index.js:3543" }
    ],
    "routes_fully_enumerated": true,
    // MUST be false for any handler reached via a prefix/startsWith dispatcher
    // (e.g. sentinelApexMarketplace.js) — an honesty flag, not a silent gap.
    "status": "exists"  // exists | partial | missing | broken | deprecated | duplicate
  },

  "frontend": {
    "surface_type": "none",  // dedicated_page | embedded_widget | modal | none
    "pages": [],
    "status": "missing",     // exists | partial | missing | broken
    "evidence": "grep for /api/orgs across frontend/*.html (excluding cve/,blog/) returns 0 matches (verified 2026-07-08)"
  },

  "navigation": {
    "discoverable": false,  // boolean | "unknown" — see note below
    "evidence": "no nav entry links to any org page"
  },

  "auth_enforced": true,   // boolean | "unknown"
  "rbac": { "enforced": true, "permissions": ["org:create", "org:manage"] },  // enforced: boolean | "unknown"
  "subscription_gated": false,  // boolean | "unknown"

  "feature_flag": {
    "present": false,
    "mechanism": "none"  // "ops/flags" | "admin-route" | "none" — two parallel flag systems exist in this repo, name which one applies
  },

  "test_coverage": {
    "has_tests": true,
    "evidence": "workers/test/orgRbacIsolation.test.mjs imports handleInviteMember/handleUpdateMemberRole/handleRemoveMember from handlers/orgManagement.js"
    // Evidence must be an import-statement match, not a filename-similarity guess
    // (filename matching is a weak signal in this repo: 14/169; import matching is strong: 100/169).
  },

  "docs": [
    { "path": "docs/SAAS_PRODUCTIZATION_MISSION_BRIEF.md", "tag": "canonical" }
    // tag canonical | audit-history — never cite an audit-history doc as current-state evidence
  ],

  "customer_journey_complete": false,

  "operational_status": "NOT READY",
  // Reuses GENERAL_AVAILABILITY_REPORT.md / docs/ENGINEERING_STANDARDS.md §9's
  // fixed vocabulary verbatim — do not invent a 6th value:
  //   GA APPROVED | GA APPROVED WITH DOCUMENTED LIMITATIONS | PILOT ONLY | NOT READY | BLOCKED

  "priority": "P2",
  // P1 broken customer journey · P2 backend exists, frontend missing ·
  // P3 backend+frontend exist, navigation missing · P4 RBAC missing ·
  // P5 subscription gating missing · P6 no tests · P7 documentation missing

  "verification": {
    "method": "static",
    // static        — code/grep-level evidence (this pass covers ~all capabilities)
    // dynamic_api   — a live fetch/curl-style check (e.g. scripts/ceap-sweep.mjs).
    //                 Real evidence the API works. NEVER sufficient alone to claim
    //                 customer_journey_complete or a frontend/navigation status.
    // dynamic_browser — an actual Playwright click-through of the real page.
    //                 The only method that can support customer_journey_complete: true.
    "last_verified": "2026-07-08",
    "evidence": "workers/src/handlers/orgManagement.js read directly; frontend/*.html grepped for /api/orgs (0 hits)"
  },

  "contradicts_doc": [
    {
      "file": "GENERAL_AVAILABILITY_REPORT.md",
      "line": 79,
      "claim": "Organizations: GA APPROVED — Full admin loop live-verified this phase",
      "correction": "Backend-only. dynamic_api verification (ceap-sweep.mjs) confirmed the API; no dynamic_browser verification was ever performed, and none was possible — zero frontend pages call /api/orgs*."
    }
  ],

  "notes": "Free-text. Use for anything the structured fields can't express."
}
```

### 2.1 The `"unknown"` value

`subscription_gated`, `navigation.discoverable`, `auth_enforced`, and
`rbac.enforced` each additionally accept the literal string `"unknown"`
instead of a boolean. Use it when a genuine, good-faith check was made but
did not reach a confident answer (e.g. "checking every one of a 27-function
handler's individual auth gates was out of scope for this pass") — never as
a default or a way to avoid checking. `"unknown"` still fails the
`operational_status: "GA APPROVED"` mechanical rule (§5.5) exactly like
`false` does, so it can never be used to smuggle an ungated capability past
that check. Prefer resolving to a real `true`/`false` whenever the evidence
supports it; reach for `"unknown"` only when it doesn't.

## 3. Why capability-level, not route-level

This repo has ~700 raw backend routes (a ~700-entry sequential if-chain in
`workers/src/index.js`, **plus** at least one separate object-literal
dispatch table, **plus** ~35 prefix/`startsWith` dispatcher handlers whose
internal actions aren't visible to any `index.js`-level scan at all) across
169 handler files. A customer does not recognize 700 rows; they recognize
~60-100 capabilities ("Organization Management", "Coupon Redemption", "MSSP
White-Label Config"). Routes are evidence *underneath* a capability, not
capabilities themselves. Some capabilities (coupons, dark-web scanning) have
real backend support with **no dedicated frontend page at all** — captured
via `frontend.surface_type`, not by forcing a fake page entry.

## 4. `exceptions.json`

Mirrors the pattern already established by `workers/schema_drift_accepted.json`:
a deliberate, evidence-backed exception (e.g. a page that is intentionally
admin-only and therefore correctly unreachable from customer-facing nav) gets
one entry with a reason and a reference, so the validator can distinguish
"accepted by design" from "undetected drift." Adding an entry here changes
nothing about the product — it only changes what CI treats as expected.

## 5. Validation (`scripts/registry/validate.mjs`)

Run via `node scripts/registry/validate.mjs`. Checks:
1. Every `domains/*.json` file parses and every entry matches this schema
   (required fields present, enums valid).
2. Every `file:line`-shaped evidence string resolves to a real file (existence
   check; line-range sanity where a line number is given).
3. Every entry's `verification.last_verified` is flagged if older than 90 days
   (staleness warning, not a hard failure — see §6).
4. No entry claims `customer_journey_complete: true` unless
   `verification.method` is `dynamic_browser`.
5. No entry claims `operational_status: "GA APPROVED"` unless
   `frontend.status` is `exists` (or `surface_type` is `embedded_widget`/`modal`
   with `frontend.status: exists`) **and** `navigation.discoverable: true`
   **and** `customer_journey_complete: true` — i.e., the exact conflation that
   produced the false Organizations/Auth claims is now a mechanical check, not
   a matter of trusting prose.

Wired into `.github/workflows/ci.yml` as an advisory job (`registry-validate`)
initially — matching how `security-scan` was launched advisory-first before
`dependency-audit` graduated to required. Graduating `registry-validate` to a
required, deploy-blocking job is a natural follow-up once it's proven stable
across a few real cycles, not a day-one guarantee.

## 6. Staleness, not silence

Unlike the 30 prior audit documents (none of which were ever revisited), this
registry's `last_verified` field is checked by `validate.mjs` on every CI run
that touches `workers/src/handlers/**`, `frontend/*.html`, or
`workers/test/**`. A capability whose backend/frontend files changed since
its `last_verified` date is flagged for re-review — drift is caught the same
day it's introduced, not rediscovered four audits later.
