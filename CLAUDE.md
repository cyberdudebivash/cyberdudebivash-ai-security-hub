# Engineering governance

This repo has accumulated 50+ prior audit/certification documents under
`docs/audit-history/`, several with self-certified "COMPLETE"/"VERIFIED"
claims that don't hold up against the actual code (e.g. an invoice-generation
claim was checked and found false — see PR #230). The policies below exist to
prevent adding to that pile and to keep production changes safe. They apply
to all engineering work in this repository, not just one task.

## 1. Production fix policy

Every task starts with: repository audit → root cause analysis → production
impact assessment → customer impact assessment → evidence collection. Do not
modify code before tracing the complete execution path.

**Auto-fix immediately**, without waiting for a separate approval round, when
an issue is clearly incorrect, objectively verifiable, self-contained,
backward-compatible, and production-safe — e.g. broken null references, wrong
API routing, incorrect imports, confirmed-dead/unreachable code, typos
affecting production, wrong feature flags, small authorization mistakes,
logging issues, minor UI defects, missing validations, a race condition with
a well-defined fix, or a safe DB constraint addition (after verification).

**Do not auto-implement** architectural changes: major refactors, payment /
subscription / billing / database / auth / API redesigns, multi-service
extraction, breaking schema changes, or customer-facing commercial changes.
For these: document the finding, explain the impact, recommend a plan, and
wait for explicit approval before implementing.

**One production problem per PR.** Don't mix unrelated fixes into the same
change. Workflow per problem: Audit → Root Cause → Design → Implement → Test
→ CI → Review → Merge → Deploy → Production Verification — then move to the
next one.

**Production safety overrides speed and elegance.** Prefer lower deployment
risk, smaller blast radius, easier rollback, and higher customer safety over
a change that's simply cleaner or shorter.

**Every fix must be provable**: root cause, repository evidence, files
changed, tests executed, remaining risks, rollback plan, deployment
checklist, production verification checklist.

**Scope discipline**: if unrelated issues surface mid-implementation, record
and prioritize them — don't fold them into the current PR.

**Optimize for**: customer experience, production stability, revenue
integrity, commercial consistency, security, compliance, and
maintainability — not line-count reduction or architectural purity for its
own sake.

## 2. How to treat existing audit/certification documents

Everything under `docs/audit-history/` (and any future audit doc) is
**reference material, not evidence** — historical context, design intent,
feature inventory, prior engineering observations. It is never proof that
something is implemented.

**The repository is the source of truth**: production code, routing, DB
schema, API implementation, authorization logic, automated tests, CI/CD and
deployment config, and observed runtime behavior all outrank documentation.
Where a document conflicts with the implementation, trust the
implementation and record the discrepancy.

**Use existing documents as an audit checklist** — they're useful for the
feature/claim inventory they contain — but don't skip verification just
because something is already written down, and don't re-run an entire
investigation from scratch when a prior finding can be quickly confirmed
against current code instead.

**Validate every "COMPLETE / VERIFIED / IMPLEMENTED / PRODUCTION READY /
CERTIFIED / DEPLOYED / ENTERPRISE READY" claim** against the current repo.
Classify each as one of: Verified, Partially Verified, Outdated, Superseded,
Not Verified, or Contradicted by current implementation.

**Preserve historical documents** even when they contain inaccuracies —
don't delete them. Instead, record a **Documentation Drift** finding:
document name, affected feature, current implementation status, customer
impact (if any), and recommended action (update / archive / replace).

## 3. Audit/report deliverable format

Structure audit output as a risk-prioritized evidence report, not a rigid
template filled in regardless of content:

- **Executive summary first**: overall readiness, highest-risk findings,
  customer/revenue/security/compliance impact, recommended next actions, and
  a GO / Conditional GO / NO-GO call where applicable. Should be readable in
  a few minutes by a non-engineer.
- **Findings ordered by business risk**, not by file/directory location.
  Each finding: severity, root cause, repository evidence, customer impact,
  business impact, files involved, recommended remediation, estimated
  complexity, and (if implementation is proposed) rollback considerations
  and testing requirements.
- Include a requested section only where it has real, evidence-backed
  content — if a section has nothing significant, say so plainly instead of
  padding it.
- **Tag every claim's confidence level explicitly**: Verified / Partially
  Verified / Not Verified / Proposed / Assumed. Never blend a verified fact
  with a recommendation in the same sentence without distinguishing them.
- **Living document**: update an existing audit doc if it's still
  substantially current rather than creating a new one; mark superseded
  findings; cross-reference earlier audits instead of duplicating their
  investigation.
