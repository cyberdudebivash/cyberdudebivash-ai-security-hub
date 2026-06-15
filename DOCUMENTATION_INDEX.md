# Documentation Index — Single Source of Truth

> Authoritative map of repository documentation. When two documents overlap,
> the one named here is canonical; the others are historical records kept for
> audit trail only and must not be updated. Add new docs to the right category
> instead of creating another root-level report.

## Canonical documents by domain

| Domain | Canonical document | Notes |
|--------|--------------------|-------|
| Product overview | `README.md` | Platform modules, architecture, endpoints |
| Architecture | `README.md` → Architecture section | Worker (JS) is the deployed surface; Python `generated_app` is the container stack |
| Deployment | `DEPLOY.md` | Cloudflare Workers/Pages deploy. Runbooks: `DEPLOY_RECOVERY_RUNBOOK.md` |
| Operations / Incident response | `DEPLOY_RECOVERY_RUNBOOK.md` | Recovery + rollback procedures |
| Security posture | `SECURITY_GAP_ANALYSIS.md` | Current gaps + controls |
| Artifact / binary policy | `ARTIFACT_RETENTION_POLICY.md` | What may be committed |
| Production stabilization | `PRODUCTION_STABILIZATION_REPORT.md` | This pass: defects, fixes, validation, verdict |
| Regression safety net | `tests/test_p0_p1_regression.py` + `workers/test/*` | Executable documentation of invariants |

## Historical / point-in-time records (do not update)

The numerous `*_AUDIT*.md`, `*_REPORT.md`, `*_CERTIFICATION*.md`,
`*_GAP_*.md`, `*_PLAN.md`, `*_BLUEPRINTS.md`, and `GODMODE_*/MYTHOS_*` files at
the repository root are dated snapshots from prior reviews. They are retained
for audit history. For current state, use the canonical documents above.

## Rules

1. One canonical doc per domain (table above). New material updates it.
2. Point-in-time reports are immutable; supersede, don't edit.
3. No duplicate documentation across directories (e.g. `workers/*.md` copies of
   root docs are deprecated — see `PRODUCTION_STABILIZATION_REPORT.md`,
   Technical Debt → Duplication).
4. Operational procedures live in runbooks, not in audit reports.
