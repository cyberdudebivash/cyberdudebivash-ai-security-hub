/**
 * CYBERDUDEBIVASH AI Security Hub — Intelligence Severity Governance Gate v30.0
 *
 * P0 SPEC: Any threat/vuln entry where:
 *   • active_exploitation = true   OR
 *   • cisa_kev_status    = true    OR
 *   • cvss_score         >= 9.0
 * MUST be classified as HIGH or CRITICAL.  Any attempt to downgrade below HIGH
 * is intercepted, corrected, and the violation is logged as a P0 exception.
 *
 * Integration:
 *   import { enforceGovernanceGate, validateIngestPayload } from './severityGovernanceGate.js';
 *
 *   In threatIngestion.js:
 *     const { entry, violation } = enforceGovernanceGate(rawEntry);
 *     if (violation) await logP0Violation(env, violation);
 *     // use entry — severity is now guaranteed correct
 *
 *   In handleManualIngest (threatIntel.js):
 *     const { valid, errors } = validateIngestPayload(body);
 *     if (!valid) return Response.json({ error: 'Ingestion gate rejected', errors }, { status: 422 });
 */

// ─── Severity ordering ────────────────────────────────────────────────────────
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const MINIMUM_RANK_TRIGGERED = 3;   // HIGH = 3

// ─── P0 Violation logger (fire-and-forget into D1) ───────────────────────────
export async function logP0Violation(env, violation) {
  const db = env.SECURITY_HUB_DB || env.DB;
  if (!db) return;
  try {
    await db.prepare(
      `INSERT OR IGNORE INTO p0_exceptions
         (id, entry_id, trigger_reason, original_severity, corrected_severity,
          cvss_score, active_exploitation, cisa_kev, logged_at)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).bind(
      `p0-${Date.now()}-${Math.random().toString(36).slice(2,8)}`,
      violation.entry_id   || 'unknown',
      violation.reason     || 'policy_enforcement',
      violation.original   || 'UNKNOWN',
      violation.corrected  || 'HIGH',
      violation.cvss       ?? null,
      violation.active     ? 1 : 0,
      violation.kev        ? 1 : 0,
      new Date().toISOString(),
    ).run();
  } catch {}

  // Also write to KV for real-time observability dashboard reads
  const kv = env.SECURITY_HUB_KV;
  if (kv) {
    try {
      const dayKey = `p0:violations:${new Date().toISOString().slice(0,10)}`;
      const cur    = parseInt(await kv.get(dayKey).catch(() => '0') || '0', 10);
      await kv.put(dayKey, String(cur + 1), { expirationTtl: 86400 * 3 });
    } catch {}
  }
}

// ─── Enforcement core ─────────────────────────────────────────────────────────
/**
 * Receives a raw threat/vuln entry and ensures severity is never below HIGH
 * when the entry meets any KEV/active-exploitation/CVSS-9 trigger.
 *
 * @param {object} entry   — raw threat intel object pre-write
 * @returns {{ entry: object, violation: object|null }}
 */
export function enforceGovernanceGate(entry) {
  if (!entry || typeof entry !== 'object') {
    return { entry: null, violation: null, dropped: true, reason: 'null_entry' };
  }

  const cvss   = parseFloat(entry.cvss_score ?? entry.cvss ?? 0);
  const active = !!(entry.active_exploitation || entry.actively_exploited);
  const kev    = !!(entry.cisa_kev || entry.cisa_kev_status || entry.kev);

  // Determine whether governance floor applies
  const triggered = active || kev || cvss >= 9.0;
  if (!triggered) return { entry, violation: null };

  const rawSev     = (entry.severity || 'MEDIUM').toUpperCase();
  const currentRank = SEVERITY_RANK[rawSev] ?? 2;

  if (currentRank >= MINIMUM_RANK_TRIGGERED) {
    // Already HIGH or CRITICAL — compliant
    return { entry, violation: null };
  }

  // Violation: entry is triggered but classified below HIGH — correct it
  const corrected = cvss >= 9.0 ? 'CRITICAL' : 'HIGH';

  const violation = {
    entry_id: entry.id || entry.cve_id || 'unknown',
    reason:   active ? 'active_exploitation_flag' : kev ? 'cisa_kev_flag' : 'cvss_9_threshold',
    original: rawSev,
    corrected,
    cvss,
    active,
    kev,
    timestamp: new Date().toISOString(),
  };

  const fixedEntry = {
    ...entry,
    severity:       corrected,
    severity_locked: true,           // downstream must not re-classify below HIGH
    _governance_corrected: true,
  };

  return { entry: fixedEntry, violation };
}

// ─── Batch enforcement (for ingestion pipeline arrays) ───────────────────────
/**
 * @param {object[]} entries   — array of raw threat entries
 * @param {object}   env       — Cloudflare env (for violation logging)
 * @returns {Promise<{ entries: object[], violations: object[], dropped: number }>}
 */
export async function enforceGovernanceBatch(entries, env) {
  const cleaned    = [];
  const violations = [];
  let   dropped    = 0;

  for (const raw of (entries || [])) {
    const { entry, violation, dropped: d } = enforceGovernanceGate(raw);
    if (d) { dropped++; continue; }
    cleaned.push(entry);
    if (violation) {
      violations.push(violation);
      logP0Violation(env, violation).catch(() => {});   // fire-and-forget
    }
  }

  return { entries: cleaned, violations, dropped };
}

// ─── Schema validator for manual ingest endpoint ─────────────────────────────
/**
 * Validates a manually-submitted threat payload before it touches D1.
 * Returns { valid: true } or { valid: false, errors: string[] }.
 */
export function validateIngestPayload(body) {
  const errors = [];

  if (!body || typeof body !== 'object')  { return { valid: false, errors: ['body must be a JSON object'] }; }

  if (!body.id || typeof body.id !== 'string' || body.id.length < 3) {
    errors.push('id: required string, minimum length 3');
  }
  if (!body.title || typeof body.title !== 'string' || body.title.length < 5) {
    errors.push('title: required string, minimum length 5');
  }

  const cvss = parseFloat(body.cvss_score ?? body.cvss ?? -1);
  if (body.cvss_score !== undefined && (isNaN(cvss) || cvss < 0 || cvss > 10)) {
    errors.push('cvss_score: must be a number between 0 and 10');
  }

  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  if (body.severity && !validSeverities.includes((body.severity || '').toUpperCase())) {
    errors.push(`severity: must be one of ${validSeverities.join(', ')}`);
  }

  // Governance pre-check: flag potential violations before we even accept the write
  const active  = !!(body.active_exploitation || body.actively_exploited);
  const kev     = !!(body.cisa_kev || body.kev);
  const cvss9   = cvss >= 9.0;
  const rawSev  = (body.severity || 'MEDIUM').toUpperCase();
  const rank    = SEVERITY_RANK[rawSev] ?? 2;

  if ((active || kev || cvss9) && rank < MINIMUM_RANK_TRIGGERED) {
    errors.push(
      `severity_governance: entry triggers KEV/active-exploitation/CVSS-9 policy ` +
      `but severity is "${rawSev}". Minimum required: HIGH.`
    );
  }

  // Reject deep-path injection attempts in id/title fields
  const SAFE_ID_RE = /^[a-zA-Z0-9\-_:.]{1,80}$/;
  if (body.id && !SAFE_ID_RE.test(body.id)) {
    errors.push('id: contains disallowed characters — alphanumeric, hyphens, underscores, colons, dots only');
  }

  return errors.length ? { valid: false, errors } : { valid: true };
}
