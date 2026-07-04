# Customer Objection Register — Living Document

> **Phase VIII instrument (permanent).** Every time a simulated or real customer
> expresses an objection — "I don't understand this", "why is this useful",
> "why should I trust this", "this is too complicated", "we already have
> another solution", "your pricing isn't clear", "onboarding is difficult",
> "this report doesn't answer my question" — it is recorded here with persona,
> business impact, classification, corrective action, and **evidence the
> objection was resolved**. An objection is closed only when the
> customer-observable behavior that caused it is fixed and re-verified over the
> same channel a customer would use. See `docs/ENGINEERING_STANDARDS.md` §8.
>
> **Edition:** 3 · **Date:** 2026-07-04 · **Build:** `bf12e10` (live production) + Phase X GA fixes
> **Method (Ed. 1, Phase VIII):** 100 simulated organizations across 10
> enterprise archetypes, exercised over HTTP only (no implementation knowledge)
> against a lab runtime of the deployed build.
> **Method (Ed. 2, Phase IX RC):** paying-customer journeys executed against
> **live production** (`https://cyberdudebivash.in`) with throwaway accounts and
> full cleanup — public workflows only, no admin overrides, no DB manipulation.
> Objections are recorded only when a customer action actually produced them —
> none are hypothetical.

## Status legend

`RESOLVED` — fixed + regression-locked + re-verified over the customer channel ·
`OPEN (owner)` — requires an organizational action no commit can close ·
`ACCEPTED` — an intended product boundary, mitigated and disclosed, not a defect.

---

## OBJ-01 — "I just ran a scan, but the report says it doesn't exist." · RESOLVED

| Field | Detail |
|-------|--------|
| **Objection** | Customer runs a domain scan, receives a `scan_id`, immediately clicks *Generate Report*, and gets `422 — Could not resolve scan result` with a hint saying "use a scan_id from a scan run within the last 7 days" — for a scan run **seconds** ago. |
| **Persona** | SOC analyst / security engineer — any of the 100 orgs that scanned a domain another customer had already scanned (example.com, github.com, common infrastructure). |
| **Business impact** | Breaks the core scan → report → executive-reporting workflow. Appears **only at multi-customer scale** (once a domain is cached), so it would have surfaced in production, not in single-user testing. Destroys trust ("the product can't find the scan it just gave me") and blocks weekly/monthly reporting — a primary reason customers buy. |
| **Classification** | **Product** (defect). |
| **Root cause** | The domain-scan response cache is shared across tenants and keyed by domain, so a cache hit returned the *original* scan's id in the response body, while the report cache and `X-Scan-ID` header used a fresh per-request id. The id the customer received was never the key the report was stored under. |
| **Corrective action** | `workers/src/handlers/domain.js` — on a cache hit, stamp the fresh per-request `scanId` onto the returned payload (`scan_id` + `scan_metadata.scan_id`) so the id the customer receives equals the report-cache key, the history row, and the response header; report-cache write is now awaited to remove a secondary race. |
| **Resolution evidence** | Re-run over HTTP as the customer: scan example.com (`X-Cache: HIT`) → body `scan_id` equals `X-Scan-ID` → `POST /api/report/generate` returns **201**. Regression-locked by `workers/test/phase8CachedScanReportId.test.mjs` (4 tests incl. cross-tenant non-leak). Clean 100-org re-run: **90/90 reports generated, 0 report errors** (down from a reproducing 422 rate). |

---

## OBJ-02 — "Your pricing isn't clear — how many free scans do I actually get?" · RESOLVED

| Field | Detail |
|-------|--------|
| **Objection** | A prospect comparing plans finds the FREE daily scan allowance stated as **5/day** on `GET /api`, **3/day** on the public plans page (`/api/subscription/plans`), and **50/month** on the signed-in account page (`/api/user/plan`). Worse, the `/api` docs listed **STARTER `scan_limit: 10`** — making the paid tier look *worse* than FREE's 50 — and FREE `key_limit: 2` when only 1 is issued. |
| **Persona** | Enterprise procurement / technical evaluator / developer reading the API docs before buying. |
| **Business impact** | Pricing that contradicts itself across three official surfaces reads as an unreliable vendor at exactly the evaluation moment. The STARTER-looks-worse-than-FREE error actively suppresses upgrades. |
| **Classification** | **Product (data integrity)** + **Sales (pricing clarity)**. |
| **Root cause** | The `/api` docs `tiers` block and the plans page were hardcoded copies that had drifted from the single enforced source of truth, `TIER_LIMITS` (`auth/apiKeys.js`). |
| **Corrective action** | The `/api` `tiers` block is now **derived** from `TIER_LIMITS` via `apiTierDoc()` (`workers/src/index.js`) so it can never drift again; the plans page FREE row states the enforced **5/day** (`workers/src/handlers/subscription.js`). |
| **Resolution evidence** | Re-verified over HTTP: `/api` FREEMIUM `key_limit=1`, STARTER `scan_limit=600` (> FREE 50); plans page FREE `scans=5/day`. Regression-locked by `workers/test/phase8EntitlementTruth.test.mjs` — every advertised tier row is asserted equal to `TIER_LIMITS`. |

---

## OBJ-03 — "My plan says I don't get reports or AI, but I can use them — which is true?" · RESOLVED

| Field | Detail |
|-------|--------|
| **Objection** | The signed-in FREE customer's plan page (`/api/user/plan`) advertised `ai_analyze: false` and `reports: false`, yet the same customer successfully ran `/api/ai/analyze` (200) and generated a downloadable report (201). The product contradicted its own entitlement display. |
| **Persona** | Platform administrator / CISO reviewing what their plan includes. |
| **Business impact** | Two harms: (1) the free tier was **under-sold** — prospects were told they get no AI and no reports when they actually do, weakening the free-to-paid funnel; (2) a product that says "you can't" while letting you erodes trust ("what else is mislabeled?"). |
| **Classification** | **Product (entitlement display)** + **Sales (positioning)**. |
| **Root cause** | `PLAN_FEATURES.FREE` (`auth/apiKeys.js`) advertised capabilities as false that the product intentionally ships to FREE: report generation (Phase VII-certified, 7-day retention) and AI threat-correlation (`/api/ai/analyze` is intentionally *not* PRO-gated, locked by `test/aiBrainEntitlementGate`). |
| **Corrective action** | `PLAN_FEATURES.FREE` now reflects reality: `ai_analyze: true`, `reports: true`. Genuinely paid capabilities stay false and enforced: `ai_simulate`/`ai_forecast` (PRO, 402-gated) and `api_access` (the premium `/api/v1` surface, 403 for FREE keys). |
| **Resolution evidence** | Re-verified over HTTP for a fresh FREE user: `features.ai_analyze=true`, `features.reports=true`, `features.api_access=false`; `/api/ai/simulate` and `/api/ai/forecast` still 402. Regression-locked by `phase8EntitlementTruth.test.mjs` (advertised == enforced, and the real PRO gates still hold via `hasAccess`). Clean 100-org re-run captured **0 entitlement objections** (down from 7 in the 10-org pre-fix pass). |

---

## OBJ-04 — "Following your deploy docs, my fresh environment's auth surface 500s." · RESOLVED

| Field | Detail |
|-------|--------|
| **Objection** | An implementation engineer standing up a staging / DR / self-host environment from the repo followed the documented steps and got a deployment whose entire `/api/auth/*` surface returned 500 — because required secrets were undocumented and no `schema*.sql` file could bootstrap an empty database (core-table foreign keys referenced `users_v44_backup`, a migration artifact created by no schema file). |
| **Persona** | Implementation / DevSecOps engineer; also every DR drill and self-hosted evaluation. |
| **Business impact** | A first-touch deployment that fails on the whole auth surface ends a self-hosted evaluation immediately and undermines DR confidence. |
| **Classification** | **Documentation** + **Product (reproducibility)**. |
| **Corrective action** | Phase VII added the required-secrets table + failure modes to `DEPLOY.md`. Phase VIII closes the remaining half: `scripts/lab-bootstrap-d1.mjs` replays the historical migrations with heal semantics and emits a single canonical **`workers/schema_bootstrap.sql`** — a from-empty schema with no phantom-table references. |
| **Resolution evidence** | `schema_bootstrap.sql` replays on a **truly empty** database to **228 tables with 0 failures**; contains all auth-critical tables (`users`, `api_keys`, `refresh_tokens`, `scan_jobs`, `scan_history`, `payments`, `organizations`, `report_access`); **0** references to `users_v44_backup`. This was the "canonical bootstrap export queued" item from Phase VII J8 — now delivered and verified. |

---

## OBJ-05 — "Why should I trust your uptime and compliance claims?" · OPEN (owner)

| Field | Detail |
|-------|--------|
| **Objection** | A Fortune 500 security/procurement reviewer asks for third-party attestation (SOC 2 / ISO 27001), independently measured SLA, and a support organization larger than one person before approving for regulated data. |
| **Persona** | Fortune 500 CISO / procurement / compliance officer. |
| **Business impact** | Blocks regulated-segment (bank, healthcare, government) production adoption; caps deals at non-regulated / pilot scope. |
| **Classification** | **Sales / organizational** — no commit can close it. |
| **Corrective action taken** | Removed implied certifications (honest "Ready/Aligned/Mapped" phrasing, Phase VI); external uptime probe outside the platform's failure domain; weekly restore drill; erasure receipts; security-questionnaire pack; transparent Trust Center. |
| **Resolution evidence** | Partial — the *trust-through-transparency* posture is in place and verifiable. The attestations themselves (SOC 2 Type II, a measured external SLA, a support deputy) remain **owner-action GA gates**, unchanged and openly disclosed rather than papered over. **Remains OPEN.** |

---

## OBJ-06 — "Heavy usage keeps getting throttled." · ACCEPTED (intended boundary, disclosed)

| Field | Detail |
|-------|--------|
| **Objection** | Under sustained load (simulated MSSP and Fortune-500 SOC patterns), FREE-tier requests are throttled once they exceed 2/min burst or 5/day — by Month 1 of the six-month simulation, most FREE scans in the heavy archetypes returned 429. |
| **Persona** | MSSP operations / high-volume SOC on the FREE tier. |
| **Business impact** | The FREE tier cannot sustain production SOC volume — **by design**; this is the upgrade signal. The risk is not the limit but whether the customer *understands* it when they hit it. |
| **Classification** | **Product boundary** (not a defect), provided the throttle response is honest and actionable. |
| **Corrective action / mitigation** | Verified the 429 response quality: it names the tier, the specific reason (`daily_limit_reached` / `burst_exceeded`), `retry_after`, `Retry-After` + `X-RateLimit-*` headers, an `upgrade_url`, and per-tier `upgrade_benefits` (PRO/ENTERPRISE). |
| **Resolution evidence** | Graceful degradation confirmed at scale (throttle escalation across the six-month waves is clean 429s, not errors or 500s). Documented as a tier boundary in the operations report. No code change required; **ACCEPTED**. |

---

## OBJ-07 — "I created my organization and its security dashboard just crashes." · RESOLVED

| Field | Detail |
|-------|--------|
| **Objection** | A brand-new enterprise customer signs up on **live production**, creates an organization (201), then opens the org security dashboard — `GET /api/orgs/{id}/dashboard` returns **500 ERR_UNHANDLED**. The org-wide scan history (`GET /api/orgs/{id}/scans`) also returns **500**. The flagship multi-tenant surface fails on first touch. |
| **Persona** | Platform administrator / SOC manager on day one of an enterprise evaluation — the exact moment a deployment decision is formed. |
| **Business impact** | A hard 500 on the organization dashboard immediately after org creation ends an enterprise evaluation. It is the highest-visibility failure a paying customer can encounter: the feature they are paying for (multi-user org security posture) does not open. |
| **Classification** | **Product** (defect) — found **in live production** by the Phase IX RC program (`request_id 49ad647b…` dashboard, `e2164bfc…` scans, build `b81bce0`). |
| **Root cause** | Both handlers queried `scan_history.created_at`; the canonical (and only) time column is `scanned_at` (base schema, all indexes, and the working `/api/history` all use `scanned_at`). Production has the correct schema, so SQLite threw `no such column` → unhandled 500. The Phase VIII lab **masked** the bug because a bootstrap heal-pass had added a stray `created_at` column — which is precisely why the RC mandate requires production-first validation. |
| **Corrective action** | `workers/src/handlers/orgManagement.js` — all `scan_history` queries in `handleOrgDashboard` and `handleOrgScans` use the canonical `scanned_at`; every dashboard aggregate is additionally wrapped so a single failing query degrades that panel to an empty state instead of hard-500ing the customer's dashboard. |
| **Resolution evidence** | Regression-locked by `workers/test/phase9OrgDashboardSchema.test.mjs` (5 tests) which runs the **real handlers against a production-faithful schema** — `scan_history` with `scanned_at` and deliberately **no** `created_at` — so the pre-fix code fails the suite and any regression back to `created_at` is caught before deploy. Includes a degradation test (missing aggregate table → 200 with empty panel, not 500) and a 403 non-member control. Production re-verification of the exact failing journey (signup → org create → dashboard 200 → scans 200 → account delete) executed at the Phase IX release gate — see `PHASE_IX_RELEASE_CANDIDATE_REPORT.md`, Release Verification Addendum. |

---

## OBJ-08 — "I forgot my password and there is no way to get my account back." · RESOLVED (code) / email delivery = owner evidence

| Field | Detail |
|-------|--------|
| **Objection** | A customer who forgets their password has **no recovery path at all**: every standard reset endpoint returned 404 in live production, and the login UI offered no "Forgot password?" affordance. The account — with its organization, scan history, API keys, and any paid subscription — is permanently lost unless single-operator support manually intervenes (and no admin reset tool existed either). |
| **Persona** | Any customer; discovered by the Phase X GA Board. Highest impact on a platform admin whose organization is anchored to their account. |
| **Business impact** | Guaranteed churn event on first occurrence; for a security vendor, "we can't recover your account" is also a credibility failure. GA-blocking for customer operations and support readiness. |
| **Classification** | **Product** (missing capability) + **Support** (no fallback procedure). |
| **Root cause** | Credential recovery was never built — signup/login/change-password existed, but no unauthenticated reset flow, no token infrastructure, no UI affordance. |
| **Corrective action** | Phase X built the full flow: `POST /api/auth/forgot-password` (enumeration-safe generic response, per-email rate limit 3/hour, 32-byte token stored **hashed** in KV with a 30-minute TTL — no schema migration) → email with a single-use link (Resend primary, MailChannels fallback, honest failure reporting) → `POST /api/auth/reset-password` (strength-validated, consume-token-before-write single use, revokes **all** prior sessions) → "Forgot password?" + reset views added to the login UI (`frontend/user-dashboard.html`). |
| **Resolution evidence** | Locked by `workers/test/phase10PasswordReset.test.mjs` (6 tests: token hashed at rest, byte-identical response for unknown emails, single-use, weak-password rejection, session revocation, rate limit). Production endpoint verification at the Phase X release gate — see `GENERAL_AVAILABILITY_REPORT.md`. **Open owner evidence:** one real inbox round-trip (requires `RESEND_API_KEY` configured in production); until then email *delivery* is unverified — the flow, tokens, and UI are. |

---

## Positive signals (objections a customer did *not* raise)

Recorded for balance — capabilities that survived the same adversarial customer scrutiny without producing an objection:

- **Tenant isolation** — a second tenant's token reading/updating another org's dashboard and record returned **403** on every attempt (control: owner access 200). No "I can see another customer's data" objection.
- **AI honesty** — asked about a CVE absent from the intel DB, the analyst refused to fabricate a severity. No "your AI made something up" objection (Phase VII J6, held in Phase VIII).
- **Offboarding** — account deletion returns a per-category erasure receipt; credentials die immediately. No "I couldn't get my data deleted" objection.
- **Onboarding speed** — time-to-first-value p50 **406 ms** / p95 778 ms across 100 orgs (signup → org → key → scan → report → AI). No "onboarding is slow" objection.

Phase IX RC (verified against **live production**, build `b81bce0`):

- **Failure honesty** — wrong password → 401, bad API key → 401, paid AI gate → 402 with the required plan named, login after account deletion → 401. Clean, truthful negative paths.
- **Measurement honesty** — an unmeasurable domain returns `grade: null`, `risk: UNKNOWN` in production rather than a fabricated verdict (Phase VII posture holds live).
- **Input validation** — malformed signup input returns a clean 400 with a clear message, not a 500.
- **SSO surface** — `/api/auth/sso/login` (400 asking for the org slug), `/api/auth/sso/callback` (302), `/api/auth/enterprise/sso` (setup guidance) all respond correctly in production; what remains is live-IdP round-trip evidence, an owner action.

Phase X GA Board (verified against **live production**, build `bf12e10`):

- **API key rotation** — rotate returns the replacement once (201); the old key is dead immediately and the new key authenticates via the documented `x-api-key` header. Per-key daily/monthly usage reporting returns clean structured data.
- **User provisioning lifecycle** — invite (201) → member accesses org dashboard (200) → RBAC denial for over-privilege (analyst inviting → 403) → role change by owner (200) → removal (200) → removed member locked out (403). The full enterprise admin loop works with no engineering intervention.
- **AI consistency** — `/api/ai/analyze` rejects malformed input with a clean 400 naming the required fields; a real scan yields `confidence_score`, `exploit_probability`, a phased attack chain, and MITRE mappings grounded in the customer's own scan findings.

## OBJ-09 — "When I Google your platform, nothing rich shows up — other companies get full listings." · RESOLVED (code) / indexing & knowledge panel = owner + time

| Field | Detail |
|-------|--------|
| **Objection** | Searching "cyberdudebivash ai security hub" shows the owner's Google Business Profile card but no rich organic result for the platform itself; competitors' searches show full knowledge panels. (Owner-reported with screenshots, 2026-07-05.) |
| **Persona** | Every prospect at the **Discovery** stage — the first trust stage in the GA certification. |
| **Business impact** | Weak discovery caps the entire funnel: a platform that can't be found can't be evaluated, bought, or recommended. |
| **Classification** | **Product (SEO/structured data)** + **Sales/owner (search-engine assets)** + **inherent time factor** (knowledge panels require corroboration + crawl cycles). |
| **Root cause (audited production-first)** | The basics existed (title/description/OG/Twitter/canonical/sitemap/robots/Search Console verification, a production-grade 1200×630 og-image). Three real defects: (1) **fabricated `AggregateRating` markup** — "4.8 from 312 reviews" on the homepage and "5 from 1" on the marketplace with zero real customers — a Google review-spam policy violation that risks suppression of **all** rich results; (2) Organization JSON-LD lacked the registered legal entity (`CYBERDUDEBIVASH PRIVATE LIMITED`) and full registered address, weakening knowledge-graph reconciliation with the GBP; (3) unverifiable preview copy ("Trusted by security teams globally", hardcoded "1,625+" counts that drift from the live product). |
| **Corrective action** | Removed all review/rating markup until real reviews exist; Organization now carries `legalName`, `brand` (the platform), and the full registered address (29, Korai - Sukinda - Ramchandrapur Rd, JAJPUR ROAD, Ragadi, Jajpur, Odisha 755019, IN); preview copy made verifiable; homepage sitemap `lastmod` refreshed. Locked by `workers/test/seoStructuredDataTruth.test.mjs` (5 tests: JSON-LD validity, no rating markup, legal entity + address, canonical/og-image contract incl. file existence, no unverifiable preview claims). |
| **Owner actions (no code can close)** | In Search Console (already verified): submit/refresh `sitemap.xml` and request indexing of the homepage. Complete the Google Business Profile: link `https://cyberdudebivash.in` as the website, add phone, photos, and the exact legal name so Google can merge the entities. Register the site in Bing Webmaster Tools (imports from Search Console in one click). Knowledge panels additionally require third-party corroboration (LinkedIn company page, GitHub org profile, press/directory listings matching the same name/address) and **crawl time — typically days to weeks**; no tag can force it. |
| **Verification status** | Code fixes verified at the release gate (live JSON-LD parses, no rating markup served, legal entity present). Rich-result appearance itself is **owner + time**; re-check via Google's Rich Results Test after deploy and again after re-indexing. |

---

## Trend (post-GA operations cycle, build `34cd6c5`)

Lifetime: **9 objections — 7 RESOLVED (regression-locked), 1 ACCEPTED
boundary (OBJ-06), 1 OPEN owner (OBJ-05)**. OBJ-09 (discovery) is the first
**owner-reported real-world** objection — exactly the Voice-of-Customer
intake CEAP was built for. The first full post-GA lifecycle
pass (onboarding → scan → report → AI → org → upgrade-to-payment-gate → key
rotation → recovery → offboarding, all live) surfaced **zero new
objections** — the first cycle with no new product defect. All open friction
is now organizational (owner actions GA-O1…O5), none code-closable.
Recurrence check: no RESOLVED objection has re-observed behavior.

## Update protocol

New objections append with the next OBJ-NN id. A `RESOLVED` entry may not be
edited to hide a regression — if the behavior returns, open a new objection that
references the old one. `OPEN (owner)` items are reviewed every phase and only
the owner's real-world action (a signed attestation, a hired deputy, a measured
SLA) closes them.
