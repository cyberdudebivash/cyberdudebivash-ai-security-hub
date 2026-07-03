/**
 * CYBERDUDEBIVASH AI Security Hub — Canonical Contract Constants v1.0
 *
 * Enterprise Engineering Platform Standardization Program, Phase 3.
 *
 * Phase 2's audit found severity/status values redefined independently
 * across dozens of handler files (e.g. the exact map
 * `{CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}` appears standalone in multiple
 * files) and confirmed real drift in status casing (`active`/`ACTIVE`,
 * `operational`/`OPERATIONAL`) that has already caused shipped bugs
 * (frontend checking `status === 'operational'` against an endpoint that
 * has only ever returned `'ok'`).
 *
 * This module is the single source of truth going forward. It does not
 * retroactively touch the ~600 existing call sites that inline their own
 * literals — that is real, separate migration work (see docs/API_STANDARDS.md)
 * — but every new handler should import from here instead of redefining
 * its own map.
 *
 * STATUS is anchored to what /api/health — the platform's most-consumed
 * endpoint — already returns in production (workers/src/index.js), not an
 * invented vocabulary: 'ok' | 'degraded' | 'error' | 'stale'.
 */

// ─── Severity ──────────────────────────────────────────────────────────────
export const SEVERITY = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH:     'HIGH',
  MEDIUM:   'MEDIUM',
  LOW:      'LOW',
  INFO:     'INFO',
});

export const SEVERITY_ORDER = [SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW, SEVERITY.INFO];

// Sort weight — the exact map duplicated standalone across multiple handler
// files (e.g. lib/aiBrain.js:522). Higher = more severe.
export const SEVERITY_WEIGHT = Object.freeze({
  [SEVERITY.CRITICAL]: 4,
  [SEVERITY.HIGH]:      3,
  [SEVERITY.MEDIUM]:    2,
  [SEVERITY.LOW]:       1,
  [SEVERITY.INFO]:      0,
});

/** Case-insensitive normalize to a canonical SEVERITY value, or null if unrecognized. */
export function normalizeSeverity(input) {
  if (!input || typeof input !== 'string') return null;
  const upper = input.trim().toUpperCase();
  return SEVERITY[upper] || null;
}

export function isValidSeverity(input) {
  return normalizeSeverity(input) !== null;
}

// ─── Status ────────────────────────────────────────────────────────────────
// Anchored to the real values /api/health already returns — see module docblock.
export const STATUS = Object.freeze({
  OK:       'ok',
  DEGRADED: 'degraded',
  ERROR:    'error',
  STALE:    'stale',
});

// Legacy/inconsistent values found in production this engagement, mapped to
// their canonical equivalent. Extend this list as new drift is discovered —
// do not silently start returning a new unmapped value from a handler.
const STATUS_ALIASES = Object.freeze({
  operational: STATUS.OK,
  active:      STATUS.OK,
  healthy:     STATUS.OK,
  online:      STATUS.OK,
  up:          STATUS.OK,
  running:     STATUS.OK,
  enabled:     STATUS.OK,
  available:   STATUS.OK,
  degraded:    STATUS.DEGRADED,
  warning:     STATUS.DEGRADED,
  error:       STATUS.ERROR,
  down:        STATUS.ERROR,
  offline:     STATUS.ERROR,
  failed:      STATUS.ERROR,
  disabled:    STATUS.ERROR,
  stale:       STATUS.STALE,
  cached:      STATUS.STALE,
});

/** Case-insensitive normalize to a canonical STATUS value, or null if unrecognized. */
export function normalizeStatus(input) {
  if (!input || typeof input !== 'string') return null;
  const lower = input.trim().toLowerCase();
  if (Object.values(STATUS).includes(lower)) return lower;
  return STATUS_ALIASES[lower] || null;
}

export function isValidStatus(input) {
  return normalizeStatus(input) !== null;
}

// ─── Timestamps ────────────────────────────────────────────────────────────
// Two distinct concepts were being conflated under 4+ different field names
// (generated_at/timestamp/ts/last_updated) in Phase 2's audit:
//   - "timestamp": when THIS HTTP response was produced (matches the shared
//     ok()/fail() envelope in lib/response.js, and /api/health).
//   - "generated_at": when the underlying DATASET was computed/aggregated,
//     which may be older than the response itself if served from cache.
// Use nowISO() for the former; pass a real computed-at time for the latter.
export function nowISO() {
  return new Date().toISOString();
}

/** Attach a canonical `timestamp` field without clobbering one the caller already set. */
export function withTimestamp(obj = {}) {
  return { timestamp: nowISO(), ...obj };
}

// ─── Freshness Contract ────────────────────────────────────────────────────
// Enterprise Real-Time Intelligence Assurance Program.
//
// Premium "LIVE" intelligence widgets (Sentinel APEX, AI Threat Intel, MYTHOS
// GOD MODE, etc.) previously carried only a "LIVE" badge with no supporting
// evidence — a customer had no way to tell ingestion-stale from cache-stale
// from UI-stale, and support had no way to diagnose which layer failed
// without reading logs. This contract is the single shape every freshness-
// bearing endpoint attaches under a `freshness` key, so the frontend can
// render one shared widget (see frontend renderFreshnessContract()) instead
// of every panel inventing its own ad hoc "Updated Xm ago" text.
//
// PIPELINE_STATUS is deliberately a small enum, not a boolean, because
// "the API responded" and "the underlying feed is current" are different
// facts — a cached-but-stale response should read DELAYED, not HEALTHY.
export const PIPELINE_STATUS = Object.freeze({
  HEALTHY: 'HEALTHY',   // ingested within its expected interval
  DELAYED: 'DELAYED',   // reachable, but older than expected interval
  OFFLINE: 'OFFLINE',   // ingestion has not run at all recently, or errored
  UNKNOWN: 'UNKNOWN',   // no freshness data available for this source yet
});

/**
 * Build a Freshness Contract for one intelligence source.
 *
 * @param {object} p
 * @param {string} p.source              Human-readable origin, e.g. "Sentinel APEX / CISA KEV".
 * @param {string|null} p.latestRecordAt ISO timestamp of the NEWEST underlying record (not the
 *                                       response time) — null if genuinely no data exists yet.
 * @param {number} p.expectedIntervalSec Expected max gap between ingestions, in seconds
 *                                       (e.g. 3600 for hourly, 21600 for every 6h).
 * @param {number} p.recordsDisplayed    Count actually returned in this response.
 * @param {number|null} p.recordsAvailable Total count available server-side, if known.
 * @param {number} p.autoRefreshSec      How often the FRONTEND re-polls this widget.
 * @returns {object} Freshness Contract — safe to serialize directly into an API response.
 */
export function buildFreshnessContract({
  source,
  latestRecordAt = null,
  expectedIntervalSec = 3600,
  recordsDisplayed = 0,
  recordsAvailable = null,
  autoRefreshSec = 300,
} = {}) {
  const now = Date.now();
  let ageSec = null;
  let pipelineStatus = PIPELINE_STATUS.UNKNOWN;

  if (latestRecordAt) {
    const t = new Date(latestRecordAt).getTime();
    if (!Number.isNaN(t)) {
      ageSec = Math.max(0, Math.round((now - t) / 1000));
      // 2x grace window absorbs normal cron jitter without false-alarming.
      pipelineStatus = ageSec <= expectedIntervalSec * 2 ? PIPELINE_STATUS.HEALTHY
        : ageSec <= expectedIntervalSec * 6 ? PIPELINE_STATUS.DELAYED
        : PIPELINE_STATUS.OFFLINE;
    }
  }

  return {
    source,
    latest_record_at:      latestRecordAt,
    latest_record_age_sec: ageSec,
    pipeline_status:       pipelineStatus,
    records_displayed:     recordsDisplayed,
    records_available:     recordsAvailable,
    expected_interval_sec: expectedIntervalSec,
    auto_refresh_sec:      autoRefreshSec,
    generated_at:          nowISO(),
  };
}
