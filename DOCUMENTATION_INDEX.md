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
| Incident response | `INCIDENT_RESPONSE_RUNBOOK.md` | Severity ladder, detection sources, SEV playbooks |
| Disaster recovery | `DISASTER_RECOVERY_RUNBOOK.md` | Backups (nightly `d1-backup.yml`), restore, rollback, RPO/RTO, drills |
| Emergency recovery (legacy) | `DEPLOY_RECOVERY_RUNBOOK.md` | 2026-06-12 recovery execution record |
| Operational risk | `docs/OPERATIONAL_RISK_REGISTER.md` | Living register: accepted risks + open items with owners |
| Security posture | `SECURITY_GAP_ANALYSIS.md` | Current gaps + controls |
| Artifact / binary policy | `ARTIFACT_RETENTION_POLICY.md` | What may be committed |
| Production stabilization | `PRODUCTION_STABILIZATION_REPORT.md` | This pass: defects, fixes, validation, verdict |
| Enterprise ops readiness | `docs/audit-history/ENTERPRISE_OPERATIONS_READINESS_2026-07.md` | 2026-07-02 ten-workstream assessment + GO/NO-GO |
| Regression safety net | `tests/test_p0_p1_regression.py` + `workers/test/*` | Executable documentation of invariants |

## Historical / point-in-time records (do not update)

The numerous `*_AUDIT*.md`, `*_REPORT.md`, `*_CERTIFICATION*.md`,
`*_GAP_*.md`, `*_PLAN.md`, `*_BLUEPRINTS.md`, and `GODMODE_*/MYTHOS_*` files
are dated snapshots from prior reviews, archived under
[`docs/audit-history/`](docs/audit-history/). They are retained for audit
history only — none of them describe current behavior. For current state,
use the canonical documents above.

## Rules

1. One canonical doc per domain (table above). New material updates it.
2. Point-in-time reports are immutable; supersede, don't edit. New ones land
   in `docs/audit-history/`, not the repository root.
3. No duplicate documentation across directories. `workers/README.md` and
   `workers/docs/` were exact duplicates of the root copies and have been
   removed; `workers/AUDIT_REPORT.md` (and the root copy) turned out to be a
   Microsoft Word `.docx` binary mislabeled with a `.md` extension and have
   been deleted per `ARTIFACT_RETENTION_POLICY.md`.
4. Operational procedures live in runbooks, not in audit reports.
