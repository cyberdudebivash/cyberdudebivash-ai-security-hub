/**
 * CYBERDUDEBIVASH AI Security Hub — Canonical Business Metrics Layer
 * ═══════════════════════════════════════════════════════════════════════════
 * ONE definition · ONE computation · ONE authoritative source per business fact.
 *
 * This module is the single source of truth for the SQL predicates that define
 * customer-visible threat-intelligence business facts. Every consumer (dashboard
 * API, executive report, export, filter, background job) MUST import the predicate
 * from here instead of inlining its own — that is how the platform guarantees the
 * SAME number for the SAME fact on every surface.
 *
 * Governance note (why these definitions and not the alternatives):
 *
 *  ┌────────────────┬──────────────────────────────┬───────────────────────────┐
 *  │ Business fact  │ CANONICAL predicate           │ Rejected alternatives      │
 *  ├────────────────┼──────────────────────────────┼───────────────────────────┤
 *  │ KEV / actively │ exploit_status = 'confirmed'  │ is_kev = 1   (column exists │
 *  │ exploited      │                               │  but ingestion NEVER writes │
 *  │                │                               │  it → always 0);            │
 *  │                │                               │ in_kev = 1   (column does   │
 *  │                │                               │  not exist → query errors,  │
 *  │                │                               │  silently returns 0).       │
 *  ├────────────────┼──────────────────────────────┼───────────────────────────┤
 *  │ Critical       │ severity = 'CRITICAL'         │ cvss_score >= 9 (a distinct │
 *  │ severity       │                               │  "CVSS-critical" fact —     │
 *  │                │                               │  exposed separately, never  │
 *  │                │                               │  as the headline "critical")│
 *  ├────────────────┼──────────────────────────────┼───────────────────────────┤
 *  │ Ransomware     │ known_ransomware = 1          │ —                          │
 *  └────────────────┴──────────────────────────────┴───────────────────────────┘
 *
 * The `is_kev`-derived alias below lets queries that historically SELECTed or
 * ORDERed BY `is_kev` keep working while now reflecting the TRUE canonical KEV
 * status instead of the unpopulated column's constant 0.
 */

// ─── Canonical predicates (bare SQL, embeddable in any WHERE/CASE) ────────────
export const KEV_PREDICATE        = "exploit_status = 'confirmed'";
export const CRITICAL_PREDICATE   = "severity = 'CRITICAL'";
export const HIGH_PREDICATE       = "severity = 'HIGH'";
export const RANSOMWARE_PREDICATE = "known_ransomware = 1";
export const CVSS_CRITICAL_PREDICATE = "cvss_score >= 9"; // distinct fact — NOT "critical severity"

// ─── Derived column aliases (for SELECT / ORDER BY that referenced is_kev) ────
// Use in place of the raw `is_kev` column so downstream code sees the canonical
// KEV flag, not the unpopulated column's constant 0.
export const KEV_FLAG_ALIAS = `CASE WHEN ${KEV_PREDICATE} THEN 1 ELSE 0 END AS is_kev`;
export const KEV_ORDER      = `CASE WHEN ${KEV_PREDICATE} THEN 1 ELSE 0 END`;

// ─── Canonical COUNT helpers over the threat_intel catalog ────────────────────
// One authoritative query per fact. Returns a number (0 on any failure — never throws).
async function countWhere(db, predicate) {
  if (!db) return 0;
  try {
    const row = await db.prepare(
      `SELECT COALESCE(COUNT(*),0) AS v FROM threat_intel WHERE ${predicate}`
    ).first('v');
    return Number(row ?? 0);
  } catch { return 0; }
}

export const kevCount        = (db) => countWhere(db, KEV_PREDICATE);
export const criticalCount   = (db) => countWhere(db, CRITICAL_PREDICATE);
export const highCount       = (db) => countWhere(db, HIGH_PREDICATE);
export const ransomwareCount = (db) => countWhere(db, RANSOMWARE_PREDICATE);

// Canonical KEV definition as a human string for docs/telemetry.
export const KEV_DEFINITION = "Known Exploited Vulnerability = threat_intel row with exploit_status='confirmed' (CISA KEV + confirmed-exploited feeds).";
