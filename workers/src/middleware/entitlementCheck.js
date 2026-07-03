/**
 * SENTINEL APEX™ Entitlement Enforcement Middleware
 * Checks customer_entitlements table (schema v39) before granting feature access.
 * Used by intelAPIHandlers.js, STIX export, SIEM webhooks, and any premium feature gate.
 *
 * ARCHITECTURE:
 *   1. Check customer_entitlements table (post-purchase grants from provisioningEngine.js)
 *   2. Fall back to tier-based lookup (legacy JWT tier from resolveAuthV5)
 *   3. FREE users: ioc + cve only (100 req/day)
 *      PRO users: all 5 endpoints (1000 req/day)
 *      TEAM+ users: + STIX, SIEM, multi-seat (10,000 req/day)
 *      ENTERPRISE: unlimited
 */

// ─── Feature Constants ────────────────────────────────────────────────────────
export const FEATURES = {
  API_ACCESS: 'api_access',
  THREAT_FEED_FULL: 'threat_feed_full',
  STIX_21_EXPORT: 'stix_21_export',
  SIEM_WEBHOOK: 'siem_webhook',
  KILL_CHAIN_MAPPING: 'kill_chain_mapping',
  MULTI_SEAT: 'multi_seat',
  DASHBOARD_PRO: 'dashboard_pro',
  DASHBOARD_EXECUTIVE: 'dashboard_executive',
  BOARD_REPORTS: 'board_reports',
  AI_PREDICTIONS: 'ai_predictions',
  ACTOR_ATTRIBUTION: 'actor_attribution',
  REPORT_DOWNLOAD: 'report_download',
  PDF_REPORTS: 'pdf_reports',
  DEDICATED_ENDPOINT: 'dedicated_endpoint',
  ANALYST_BRIEFINGS: 'analyst_briefings',
  CUSTOM_INTEGRATIONS: 'custom_integrations',
  WHITE_LABEL: 'white_label',
  SLA_GUARANTEE: 'sla_guarantee',
};

// Tier → implicit features (used when no entitlements row exists — backward compat)
const TIER_IMPLICIT_FEATURES = {
  FREE:       [FEATURES.API_ACCESS],
  STARTER:    [FEATURES.API_ACCESS, FEATURES.THREAT_FEED_FULL, FEATURES.DASHBOARD_PRO],
  PRO:        [FEATURES.API_ACCESS, FEATURES.THREAT_FEED_FULL, FEATURES.DASHBOARD_PRO, FEATURES.AI_PREDICTIONS, FEATURES.ACTOR_ATTRIBUTION, FEATURES.REPORT_DOWNLOAD, FEATURES.PDF_REPORTS, FEATURES.STIX_21_EXPORT],
  TEAM:       [FEATURES.API_ACCESS, FEATURES.THREAT_FEED_FULL, FEATURES.DASHBOARD_PRO, FEATURES.AI_PREDICTIONS, FEATURES.ACTOR_ATTRIBUTION, FEATURES.REPORT_DOWNLOAD, FEATURES.PDF_REPORTS, FEATURES.STIX_21_EXPORT, FEATURES.SIEM_WEBHOOK, FEATURES.KILL_CHAIN_MAPPING, FEATURES.MULTI_SEAT],
  ENTERPRISE: Object.values(FEATURES),
  MSSP:       Object.values(FEATURES),
};

// ─── Core Entitlement Check ───────────────────────────────────────────────────

/**
 * Check if a user has a specific feature entitlement.
 * @param {D1Database} db
 * @param {string} userId
 * @param {string} feature - one of FEATURES.*
 * @param {string} tier - fallback tier from authCtx
 * @returns {Promise<{granted: boolean, source: 'entitlement'|'tier'|'none', expires_at: string|null}>}
 */
export async function checkEntitlement(db, userId, feature, tier = 'FREE') {
  // 1. Check customer_entitlements table (purchased/provisioned grants)
  if (userId && db) {
    try {
      const row = await db.prepare(
        `SELECT feature, granted, expires_at, source_ref FROM customer_entitlements
         WHERE user_id = ? AND feature = ? AND granted = 1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         LIMIT 1`
      ).bind(userId, feature).first();

      if (row?.granted) {
        return { granted: true, source: 'entitlement', expires_at: row.expires_at || null };
      }
    } catch {
      // D1 errors shouldn't block access — fall through to tier check
    }
  }

  // 2. Tier-based implicit access (backward compatibility + unauthenticated users)
  const normTier = (tier || 'FREE').toUpperCase();
  const tierFeatures = TIER_IMPLICIT_FEATURES[normTier] || TIER_IMPLICIT_FEATURES.FREE;
  if (tierFeatures.includes(feature)) {
    return { granted: true, source: 'tier', expires_at: null };
  }

  return { granted: false, source: 'none', expires_at: null };
}

/**
 * Check if a user has any of the listed features.
 * Returns true if ANY feature is granted.
 */
export async function checkAnyEntitlement(db, userId, features, tier = 'FREE') {
  for (const feature of features) {
    const result = await checkEntitlement(db, userId, feature, tier);
    if (result.granted) return result;
  }
  return { granted: false, source: 'none', expires_at: null };
}

/**
 * Check if a user has ALL of the listed features.
 */
export async function checkAllEntitlements(db, userId, features, tier = 'FREE') {
  for (const feature of features) {
    const result = await checkEntitlement(db, userId, feature, tier);
    if (!result.granted) return { granted: false, missing_feature: feature, source: 'none', expires_at: null };
  }
  return { granted: true, source: 'all', expires_at: null };
}

/**
 * Get full entitlement list for a user (both explicit grants + tier-implicit).
 */
export async function getUserEntitlements(db, userId, tier = 'FREE') {
  const explicit = new Map();

  if (userId && db) {
    try {
      const { results } = await db.prepare(
        `SELECT feature, granted, expires_at, source_ref FROM customer_entitlements
         WHERE user_id = ? AND granted = 1
           AND (expires_at IS NULL OR expires_at > datetime('now'))`
      ).bind(userId).all();

      for (const row of results || []) {
        explicit.set(row.feature, { source: 'entitlement', expires_at: row.expires_at });
      }
    } catch {}
  }

  // Merge tier-implicit
  const normTier = (tier || 'FREE').toUpperCase();
  const tierFeatures = TIER_IMPLICIT_FEATURES[normTier] || TIER_IMPLICIT_FEATURES.FREE;
  for (const f of tierFeatures) {
    if (!explicit.has(f)) explicit.set(f, { source: 'tier', expires_at: null });
  }

  return Object.fromEntries(
    Array.from(explicit.entries()).map(([k, v]) => [k, { granted: true, ...v }])
  );
}

// ─── Upgrade Prompt Payloads ──────────────────────────────────────────────────

export function buildUpgradePayload(feature, currentTier = 'FREE') {
  // Prices + tiers MUST match the customer-facing billing source of truth
  // (handlers/monetizationV2.js PLANS, served by /api/billing/plans):
  //   PRO ₹2,999/mo ($36) · ENTERPRISE ₹24,999/mo ($299).
  // Two prior defects fixed here:
  //  1) every upgrade CTA misquoted the price (PRO ₹3,999, ENTERPRISE ₹39,999)
  //     — the customer saw one price in the gate and was charged another.
  //  2) SIEM_WEBHOOK / KILL_CHAIN_MAPPING required tier 'TEAM' — a tier that is
  //     NOT purchasable (billing sells FREE/PRO/ENTERPRISE only). The features
  //     are granted at ENTERPRISE (TIER_IMPLICIT_FEATURES.ENTERPRISE = all), so
  //     the CTA now correctly directs the customer to ENTERPRISE.
  const PRO   = { required_tier: 'PRO',        price_usd: '$36/mo',  price_inr: '₹2,999/mo' };
  const ENT   = { required_tier: 'ENTERPRISE', price_usd: '$299/mo', price_inr: '₹24,999/mo' };
  const UPGRADE_MAP = {
    [FEATURES.THREAT_FEED_FULL]:   PRO,
    [FEATURES.STIX_21_EXPORT]:     PRO,
    [FEATURES.SIEM_WEBHOOK]:       ENT,
    [FEATURES.KILL_CHAIN_MAPPING]: ENT,
    [FEATURES.ACTOR_ATTRIBUTION]:  PRO,
    [FEATURES.AI_PREDICTIONS]:     PRO,
    [FEATURES.BOARD_REPORTS]:      ENT,
    [FEATURES.ANALYST_BRIEFINGS]:  ENT,
    [FEATURES.WHITE_LABEL]:        ENT,
    [FEATURES.DEDICATED_ENDPOINT]: ENT,
    [FEATURES.REPORT_DOWNLOAD]:    PRO,
    [FEATURES.DASHBOARD_PRO]:      PRO,
  };

  const upg = UPGRADE_MAP[feature] || PRO;

  return {
    error: 'feature_locked',
    feature,
    current_tier: currentTier,
    required_tier: upg.required_tier,
    // Structured price (matches /api/billing/plans) so the frontend renders the
    // exact figure the customer will be charged, not a parsed CTA string.
    price_usd: upg.price_usd,
    price_inr: upg.price_inr,
    upgrade_url: 'https://intel.cyberdudebivash.com/pricing.html',
    cta: `Upgrade to ${upg.required_tier} — ${upg.price_usd} / ${upg.price_inr}`,
    trial_available: currentTier === 'FREE',
    trial_url: 'https://intel.cyberdudebivash.com/pricing.html#trial',
  };
}

// ─── Middleware Helper ─────────────────────────────────────────────────────────

/**
 * Gate an entire handler behind a single feature check.
 * Usage:
 *   const gate = await featureGate(env.DB, authCtx, FEATURES.STIX_21_EXPORT);
 *   if (gate) return gate; // returns 403 JSON response if not entitled
 *   // proceed with handler...
 */
export async function featureGate(db, authCtx, feature) {
  const userId = authCtx?.userId || authCtx?.id;
  const tier   = authCtx?.tier || 'FREE';

  const result = await checkEntitlement(db, userId, feature, tier);
  if (result.granted) return null; // pass-through

  return Response.json(buildUpgradePayload(feature, tier), { status: 403 });
}

/**
 * Log an entitlement check for audit trail.
 */
export async function logEntitlementCheck(db, userId, feature, granted, context = '') {
  try {
    await db.prepare(
      `INSERT INTO provisioning_log (id, event_type, user_id, details, created_at)
       VALUES (?, 'entitlement_check', ?, ?, datetime('now'))`
    ).bind(
      `ent_${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
      userId,
      JSON.stringify({ feature, granted, context })
    ).run();
  } catch {} // Non-blocking
}
