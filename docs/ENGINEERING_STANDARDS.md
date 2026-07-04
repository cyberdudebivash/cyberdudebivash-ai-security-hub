# Engineering Standards — API Contracts, Severity, Status, Timestamps

**Status:** Living document. Established Phase 3 of the Enterprise Production
Readiness Program, based on real evidence gathered in Phases 1–2 (see
`docs/audit-history/` if present, or the engagement's PR history on
`main` around commits `a1244ce`…`b87d8b6`).

This is the canonical reference for *new* code. It does not retroactively
rewrite existing endpoints — see "Migration status" below for why, and what
that means for you if you're touching a legacy handler.

---

## 1. Why this document exists

Phase 1 of this program found ~31 confirmed production defects across the
platform's dashboards. Every one of them reduced to the same root cause:
**a real backend endpoint, computing correct data, whose response shape the
frontend was never updated to match.** No build step catches this — the
field lookup just silently returns `undefined`, and the UI renders a stale
default forever, with no error.

Phase 2 quantified how widespread the underlying inconsistency is:

| Finding | Evidence |
|---|---|
| Only ~21% of classifiable API routes use the shared response envelope | 99 of 470 routes traced to source, programmatically |
| 71% return flat, unwrapped JSON | 332 of 470 |
| 8% mix both styles *in the same handler file* — the highest-risk pattern | 39 of 470 |
| Timestamp field name varies 4+ ways for the same concept | `generated_at` (109×), `timestamp` (106×), `ts` (47×), `last_updated` (19×) |
| Status casing varies for the same state | `active`/`ACTIVE` (72×), `operational`/`OPERATIONAL` (22×), `error`/`ERROR` (12×) |
| Severity casing is already consistent | 238/239 literals use canonical uppercase |

The `/api/health` → `status === 'operational'` mismatch (endpoint has never
returned that value; only `'ok'|'degraded'|'error'|'stale'`) shipped to
production and caused a customer-visible dashboard bug fixed this
engagement — this is not a hypothetical risk.

## 2. The canonical response envelope

Defined in `workers/src/lib/response.js` (pre-existing, well-designed —
Phase 3 did not need to build this):

```js
import { ok, fail, paginated, notFound, badRequest, unauthorized, forbidden } from '../lib/response.js';

// Success:
return ok(request, { alerts, total });
// → { success: true, data: { alerts, total }, error: null, timestamp: "..." }

// Failure:
return fail(request, 'title is required', 400, 'MISSING_TITLE');
// → { success: false, data: null, error: "title is required", code: "MISSING_TITLE", timestamp: "..." }

// Paginated list:
return paginated(request, items, total, page, limit);
```

**Every new endpoint must use these helpers.** Do not hand-roll
`Response.json({...})` for a new route.

Frontend consumers must unwrap accordingly:
```js
const raw = await res.json();
const data = raw.success && raw.data ? raw.data : raw; // tolerate both during migration
```

## 3. Canonical severity, status, and timestamps

New in Phase 3: `workers/src/lib/contracts.js`. This did not exist before —
severity/status enums were being redefined independently in dozens of files
(e.g. the exact map `{CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}` appeared standalone
in multiple handlers).

```js
import { SEVERITY, normalizeSeverity, STATUS, normalizeStatus, nowISO } from '../lib/contracts.js';

// Severity — 5 canonical uppercase values: CRITICAL, HIGH, MEDIUM, LOW, INFO
normalizeSeverity('high')   // → 'HIGH'
normalizeSeverity('urgent') // → null (never guesses)

// Status — anchored to what /api/health already returns in production:
// 'ok' | 'degraded' | 'error' | 'stale'
normalizeStatus('operational') // → 'ok'  (documented alias, not a new meaning)
normalizeStatus('ACTIVE')      // → 'ok'
normalizeStatus('purple')      // → null

// Timestamps — two distinct concepts, don't conflate them:
nowISO()              // when THIS response was produced → use as `timestamp`
// vs. a real computed-at value you already have → use as `generated_at`
// (the underlying dataset may be older than the response if served from cache)
```

Add new aliases to `STATUS_ALIASES` in `lib/contracts.js` as new drift is
discovered — do not let a handler start returning an unmapped value.

## 4. Migration status — what's actually done vs. what remains

**Adopted this phase** (proof-of-concept, not a mass migration):
- `workers/src/handlers/cisoMetrics.js` → `handleCreateIncident` now uses
  `normalizeSeverity()` instead of a locally-redefined 4-value array.

**Not migrated, and why:**
Rewriting the other ~600 handlers to use `lib/response.js` and
`lib/contracts.js` uniformly is real, valuable work — but doing it as a
blind mechanical sweep in one sitting, without individually verifying every
one of their (largely untracked) frontend consumers first, would very
likely **reintroduce the exact contract-drift bug class this program exists
to eliminate.** That migration should be scoped, reviewed, and executed
incrementally — new/touched endpoints adopt the standard; a dedicated
future initiative handles the rest with proper consumer verification per
endpoint, the same rigor Phase 1 used for the 31 defects it fixed.

**When you touch a handler for any reason:** migrate it to
`lib/response.js` + `lib/contracts.js` as part of that change, and update
its confirmed frontend consumer(s) in the same commit. Do not migrate a
handler's response shape without also checking who reads it.

## 5. Contract regression tests

`workers/test/phase2ContractDrift.test.mjs` and `workers/test/contracts.test.mjs`
lock in the real shape of every endpoint a confirmed frontend fix depends
on. When you fix a field-mismatch bug, add a test here — the pattern is:
assert the real field exists, and assert the specific wrong field name a
consumer used to read does *not* exist, so the same bug can never silently
ship twice.

## 6. Known, accepted findings (not defects)

- **Error responses expose `err.message` to the client** in ~235 call
  sites, including the shared `withErrorBoundary()` wrapper itself. Sampled
  for secret/credential/connection-string leakage — none found. This
  appears to be a deliberate platform convention (specific, actionable
  error text for API integrators) rather than an oversight, and is not
  being changed without a product decision to do otherwise.
- **`X-Request-ID` is already generated and returned on effectively every
  response** via `withSecurityHeaders()` (963 call sites in
  `workers/src/index.js`). The gap: `console.error(...)` calls do not
  consistently include that same ID, so a client-reported failure can't
  yet be correlated to a specific server log line. Real, scoped
  improvement opportunity for a future observability pass — not fixed this
  phase (touches hundreds of logging call sites).
- **One dead function** confirmed via static analysis of `index.js`:
  `detectAnomaly()` is defined but never called from any route. Zero
  production impact; left in place rather than deleted speculatively.

## 7. The Product Council gate (permanent, Phase VI)

Adopted 2026-07-04 as a permanent owner-directed rule, marking the
transition from a bug-fixing mindset to a Product Council mindset. Every
proposed feature, architectural change, or marketing claim must answer
four questions **before** implementation:

1. **Does it solve a verified customer problem?** Verified means evidence:
   a support issue, a usage signal, a live-production observation, a
   procurement blocker — not an assumption about what customers might want.
2. **Can we implement and maintain it reliably?** Including the ongoing
   maintenance cost, not just the initial build.
3. **Can we demonstrate its value with evidence?** If the value can't be
   measured or shown, it can't be claimed — the same honesty standard the
   platform applies to its security intelligence applies to its roadmap.
4. **Will it make the platform stronger six months from now?** Work that
   only looks good this week fails this question.

If the answer to any of the four is "no" or "we don't know yet", the work
is **reconsidered or deferred** — recorded (in the Production Health
Scorecard's action queue or the risk register) rather than silently
dropped, but not built.

This gate sits *in front of* the existing release-governance reviews (code,
architecture, security, performance, customer impact, regression,
deployment, rollback, evidence). Passing tests has never been sufficient
for release; from Phase VI on, having an idea is no longer sufficient for
implementation.

How this interacts with the rest of this document: sections 1–6 govern
*how* code is written once approved. Section 7 governs *whether* it gets
written at all.

## 8. The Customer Adoption Rule (permanent, Phase VIII)

Adopted 2026-07-04 as a permanent owner-directed rule for all future phases,
marking the transition from *engineering completeness* to *customer adoption*
as the definition of done. It is the standard by which every capability is
judged "successful":

> **No capability is successful because it works technically. It is successful
> only when a representative customer can discover it, understand it, configure
> it, use it effectively, and achieve meaningful business value with an
> acceptable operational experience.**

Concretely, a capability is not "done" until all six hold, each with evidence:

1. **Discover** — a real customer can find it without being told it exists
   (navigation, docs, `/api` self-description, onboarding guide).
2. **Understand** — its purpose and value are clear without reading source.
3. **Configure** — a customer can set it up with the documented steps, and the
   documented steps actually work on a clean environment.
4. **Use effectively** — the primary workflow completes end-to-end under
   production-like conditions, including the second and hundredth use, not just
   the first.
5. **Business value** — it solves a named business problem and the customer can
   see the result (a report, a verdict, a saved hour) — not just a 200 response.
6. **Acceptable operations** — failure modes are honest and recoverable, limits
   are disclosed before they bite, and support has a path when it breaks.

The enforcement instrument for this rule is the **Customer Objection Register**
(`CUSTOMER_OBJECTION_REGISTER.md`): every time a simulated or real customer says
"I don't understand this", "why is this useful", "why should I trust this",
"this is too complicated", "your pricing isn't clear", "onboarding is hard", or
"this doesn't answer my question", it is recorded with persona, business impact,
classification (product / documentation / onboarding / sales), corrective
action, and evidence of resolution. An objection is not closed until the
customer-observable behavior that caused it is fixed and re-verified over the
same channel a customer would use.

Sections 7 and 8 are complementary: §7 decides whether a capability should
exist; §8 decides whether an existing capability is actually succeeding with
customers. A feature can pass §7 and still fail §8 — that failure is a defect,
tracked and fixed, exactly like a functional bug.

## 9. The Permanent Release Lifecycle (adopted at GA, Phase X)

Phase-numbered validation programs (VIII, IX, X…) end with the GA decision.
From GA forward, all work moves through one permanent lifecycle — the same one
mature software organizations run:

1. **Development** — build on a feature branch; §1–6 conventions apply.
2. **Engineering Verification** — full suite green; every customer-facing
   change carries a regression lock; schema-touching changes are tested
   against a **production-faithful schema** (the RC-B1 lesson: a healed lab
   schema masked a production-only 500).
3. **Customer Verification** — exercise the change over the channel a
   customer actually uses (HTTP against the running build), production-first
   where safe: reproduce through the customer experience, *then* inspect
   the implementation.
4. **Release Candidate** — the gated pipeline (test gate → deploy →
   post-deploy smoke) is the only path to production; no manual deploys,
   no admin overrides.
5. **GA Decision** — every capability holds exactly one evidence-backed
   status from the fixed vocabulary (GA APPROVED / GA APPROVED WITH
   DOCUMENTED LIMITATIONS / PILOT ONLY / NOT READY / BLOCKED). Never
   "100% complete", "bug free", or "guaranteed".
6. **Post-GA Customer Operations** — the default posture is operating, not
   building: watch production, answer objections, keep every customer-facing
   claim equal to verified platform behavior.
7. **Continuous Improvement** — real-world evidence (objections, incidents,
   usage) drives the backlog; fixes re-enter at step 1.

Standing instruments: the **Customer Objection Register** (voice-of-customer
intake, §8), the **GA Blocker Board** (`GENERAL_AVAILABILITY_REPORT.md` §5 —
only genuine customer-impacting blockers, each with owner and required
evidence), and the **Production Health Scorecard** (state + trends, updated
every cycle). The optimization target is **customer confidence**: when
engineering convenience conflicts with customer trust, customer trust wins;
when internal assumptions conflict with externally verifiable evidence, the
evidence wins.

## 10. The Verifiable-Statement Rule (permanent, CEAP)

**Every customer-facing statement — in the product, documentation, support
guidance, pricing, marketing, or AI responses — must be continuously
verifiable against observed production behavior. If production evidence
changes, the statement is updated or withdrawn.**

Operating consequences:

1. **Documentation drift is a production-quality defect**, triaged like any
   other: reproduce over the customer channel, correct the statement or the
   behavior (whichever is wrong), and record the resolution in the Customer
   Objection Register or the Operational Excellence Report.
2. **Statements ship with their evidence.** A claim enters a customer-facing
   surface only with a named verification behind it (a live probe, a
   regression lock, a pipeline run). "It should work that way" is not
   evidence. Where evidence cannot yet exist (e.g. renewal behavior before
   the first real customer), the surface says so plainly instead of implying
   the evidence.
3. **Certifications are revisable in one direction only — toward the
   evidence.** When new production evidence contradicts an earlier
   certification, the certification is updated transparently with the reason
   (never silently edited to hide the regression; see the Objection
   Register's update protocol).
4. **The enforcement instruments** are the CEAP synthetic sweep
   (`scripts/ceap-sweep.mjs`, scheduled by `.github/workflows/ceap-assurance.yml`
   every 6 hours against live production), the documentation-accuracy audit
   in each operations cycle, and the living registers indexed in
   `DOCUMENTATION_INDEX.md`.

This rule is the standing form of the mandate that has governed every cycle
since the Release Candidate program: the platform succeeds only while a
customer can independently verify that it behaves as advertised.

## 11. The Production Truth Law (supreme rule)

**The production environment is the ultimate source of truth.**

Tests establish confidence. Customer simulations establish probability.
Documentation establishes expectations. **Only observed production behaviour
establishes reality.**

Whenever implementation, documentation, monitoring, customer expectation, or
operational assumptions disagree with verified production behaviour,
production behaviour becomes the starting point for investigation. Every
discrepancy must either:

- be **corrected**,
- be **documented**, or
- be **explicitly accepted** as a known limitation.

Nothing else is permitted. Where this law conflicts with any other section
of this document, this law wins. (Precedent: IR-1 was invisible to a green
1,300-test suite because the lab schema disagreed with production — the
suite established confidence, production established reality.)

## 12. The Governance Operating System (permanent — no more phases)

Phase-numbered programs are retired. The product operates under four
standing programs plus one council. New work is an iteration through this
system, never a new phase.

### CEAP — Continuous Enterprise Assurance (implemented)
Owns production truth, customer verification, regression prevention,
documentation verification, and evidence collection. Instruments: the
6-hourly synthetic sweep (`scripts/ceap-sweep.mjs` via `ceap-assurance.yml`),
the per-cycle documentation-accuracy audit, and the living registers. A
sweep FAIL is a production incident.

### CIP — Continuous Improvement Program
Every improvement **starts** here: product evolution, customer objections,
roadmap, UX, performance, technical debt. Intake instruments: the Customer
Objection Register (voice of customer) and the Continuous Improvement
Backlog (`OPERATIONAL_EXCELLENCE_REPORT.md` §7), prioritized **only** by
observed customer impact — engineering convenience is never sufficient
justification. The objective given to any engineering agent is not "find
bugs" but **"continuously reduce operational risk."**

### CORB — Continuous Operational Review Board (weekly)
Reviews incidents and near misses, deployments, customer feedback, support
metrics, reliability, AI quality, cost, and performance — against the KPI
Dashboard (`KPI_DASHBOARD.md`). Produces **action items only** (into the CIP
backlog with owners); it does not produce reports.

### CAB — Change Advisory Board (every production change)
No production deployment bypasses CAB. Every release to `main` must answer,
in its commit/PR record, the six CAB questions:
**Why? · Risk? · Rollback? · Customer impact? · Evidence? · Success
criteria?** The gated pipeline (test → deploy → smoke) is CAB's mechanical
arm; the six answers are its record. A change that cannot answer all six is
not ready to ship.

### Product Council (monthly — extends §7)
Perspectives at the table: CEO, CTO, CISO, Customer Success, Support, Sales,
Engineering, AI, DevOps. Every feature proposal must answer: does a customer
actually need this · does it increase customer trust · does it increase ARR ·
does it reduce churn · does it reduce support burden · does it reduce
operational complexity · does it strengthen the platform? **If not — don't
build it.** (The §7 four-question gate remains the per-change fast path; the
Council is the monthly portfolio view.)

**Measurement:** progress is tracked exclusively by the outcome metrics in
`KPI_DASHBOARD.md` — never by feature counts, commit counts, or test counts.

## 13. Standing Engineering Directive (owner-issued, 2026-07-04 — final)

Issued by the owner as the permanent measurement rule binding every program
in §12. The governance architecture is hereby **declared complete**: no new
phases, no new frameworks — every future feature, customer request,
deployment, incident, and business decision flows through CEAP + CIP + CORB
+ CAB + Product Council.

**Effective immediately, the engineering organization is not measured by
commits, deployments, features, or tests. Engineering success is measured
only by customer outcomes.**

Every engineering cycle must improve at least one measurable customer
outcome — e.g. reduced onboarding time, operational risk, support effort,
deployment complexity, or customer confusion; improved AI trust, platform
reliability, customer confidence, documentation accuracy, operational
visibility, or business value. A change that improves no measurable
customer outcome does not receive implementation priority.

Precedence rules (absolute):

1. **Customer evidence outranks engineering intuition.**
2. **Production evidence outranks internal assumptions** (§11).
3. **Operational simplicity outranks unnecessary complexity.**
4. **Long-term maintainability outranks short-term convenience.**

The platform evolves through disciplined iteration, never periodic
reinvention. The KPI Dashboard (`KPI_DASHBOARD.md`) is the management tool;
its UNKNOWN values are filled by generating real customer evidence, never by
estimation. The organization's present priorities are business initiatives,
not prompts: first paying customer; CEAP against real (not simulated)
customer activity; real Voice of Customer into the Product Council; closure
of the owner-controlled blockers (GA-O1…O5) as business work.
