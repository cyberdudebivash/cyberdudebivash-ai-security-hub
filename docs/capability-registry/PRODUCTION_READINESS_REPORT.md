# Enterprise Production Readiness Report

> **GENERATED FILE — do not hand-edit.** Produced by
> `scripts/registry/generate-report.mjs` from
> `docs/capability-registry/domains/*.json`. Every number below is computed
> from those entries. To change a number here, correct the underlying
> registry entry (with real evidence) and re-run the generator — never edit
> this file directly. This is the CEAP instrument described in
> `docs/ENGINEERING_STANDARDS.md` §10/§12; it does not replace
> `KPI_DASHBOARD.md` (the outcome scoreboard) — this report measures
> structural completeness and parity, not customer outcomes.

Generated: 2026-07-08T12:58:05.670Z
Capabilities catalogued: 11

## Overall Completion

| Dimension | % |
|---|---|
| Backend | 81.8% |
| Frontend | 45.5% |
| Parity (backend **and** frontend both exist) | 45.5% |
| Customer Journeys complete (dynamic_browser-verified) | 0% |

## Gaps by Priority

| Severity | Priority | Count | Meaning |
|---|---|---|---|
| Critical | P1 | 1 | Broken customer journey |
| High | P2 | 4 | Backend exists, frontend missing |
| Medium | P3 | 0 | Backend+frontend exist, navigation missing |
| Medium | P4 | 1 | RBAC not enforced |
| Low | P5 | 0 | Subscription gating missing |
| Low | P6 | 0 | No test coverage |
| Low | P7 | 5 | Documentation missing |

**Rollup:** Critical 1 · High 4 · Medium 1 · Low 5

## Structural Findings

| Metric | Count | Definition |
|---|---|---|
| Hidden features | 4 | Backend exists, but not discoverable via navigation |
| Backend-only features | 2 | Backend exists, zero frontend surface |
| Duplicate systems | 0 | Backend marked `duplicate` (two implementations of one capability) |
| Broken journeys | 1 | Priority P1 |

## Production Readiness Verdict: **NOT READY**

Computed, not asserted: NOT READY if any broken journey (P1) exists or
parity is below 80%; GA APPROVED WITH DOCUMENTED LIMITATIONS if parity is
below 95% or any P2 (backend-only) gaps remain; GA APPROVED otherwise. Uses
the fixed vocabulary from `docs/ENGINEERING_STANDARDS.md` §9 — never "100%
complete", "bug free", or "guaranteed".

## Capabilities by Domain

### commercial-billing (3 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-BILL-001 | Coupon Redemption at Checkout | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-BILL-002 | Coupon Administration | ✓ | ✗ | ✗ | NOT READY | P2 |
| CAP-BILL-003 | Subscription Plans & Billing Portal | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |

### customer-portal (4 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-PORTAL-001 | Profile & Security Settings | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-PORTAL-002 | Scan History & Reports | ✓ | ✓ | ✓ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-PORTAL-003 | Session Management (Active Sessions / Per-Session Revoke) | ◐ | ✗ | ✗ | NOT READY | P2 |
| CAP-PORTAL-004 | Support Ticket System | ✗ | ✗ | ✗ | NOT READY | P2 |

### identity (1 capability)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-IDN-001 | Login / Sign-in Entry Point | ✓ | ✗ | ✗ | NOT READY | P1 |

### organizations (1 capability)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-ORG-001 | Organization Management | ✓ | ✗ | ✗ | NOT READY | P2 |

### rbac (2 capabilities)

| ID | Capability | Backend | Frontend | Nav | Status | Priority |
|---|---|---|---|---|---|---|
| CAP-RBAC-001 | Platform Staff Role Management | ✓ | ✓ | ✗ | GA APPROVED WITH DOCUMENTED LIMITATIONS | P7 |
| CAP-RBAC-002 | Role/Plan-Based Frontend Feature Gating | ◐ | ✗ | ✓ | NOT READY | P4 |

---
*Regenerate with `node scripts/registry/generate-report.mjs` after any
change to `docs/capability-registry/domains/*.json`.*
