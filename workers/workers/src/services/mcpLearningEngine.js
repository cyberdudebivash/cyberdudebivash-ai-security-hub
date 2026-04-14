/**
 * ═══════════════════════════════════════════════════════════════════════════
 * CYBERDUDEBIVASH AI Security Hub — MCP Self-Learning Engine v17.0
 *
 * ARCHITECTURE: Lightweight, KV + D1 based. No external ML dependencies.
 * All writes are fire-and-forget. All reads are parallelised with Promise.all.
 * Target: < 30ms added latency on MCP Control path.
 *
 * PHASES IMPLEMENTED:
 *   Phase 1  — Feedback ingestion + validation
 *   Phase 2  — Item scoring model (click_rate, purchase_rate, ignore_rate)
 *   Phase 3  — Adaptive recommendation re-ranking
 *   Phase 4  — User preference profile management
 *   Phase 5  — Contextual conversion learning
 *   Phase 6  — Dynamic pricing signal generation (visual only, no price changes)
 *   Phase 7  — A/B experiment engine (CTA, bundle, urgency variants)
 *   Phase 9  — Performance safety + fallsafe wrappers
 *
 * SCORING FORMULA:
 *   mcp_score = clamp(
 *     (purchase_rate * 60) + (click_rate * 25) - (ignore_rate * 15) + base(50),
 *     0, 100
 *   )
 *
 * KV KEY SCHEMA:
 *   mcp:score:{item_id}           → {score, click_rate, purchase_rate, ignore_rate, total, ts}
 *   mcp:profile:{user_id}         → user profile object
 *   mcp:ctx:{context}:{item_id}   → context conversion rate
 *   mcp:ab:{experiment_id}        → {A: {...}, B: {...}} variants
 *   mcp:ab:winner:{experiment_id} → 'A' | 'B'
 *   mcp:pricing:{item_id}:{tier}  → pricing signal object
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const SCORE_WEIGHTS = { purchase: 60, click: 25, ignore: -15, dismiss: -8 };
const SCORE_BASE    = 50;  // neutral start for new items
const KV_SCORE_TTL  = 7 * 24 * 3600;   // 7 days
const KV_PROFILE_TTL= 30 * 24 * 3600;  // 30 days
const KV_CTX_TTL    = 14 * 24 * 3600;  // 14 days
const KV_AB_TTL     = 30 * 24 * 3600;  // 30 days
const MIN_EVENTS_FOR_LEARNING = 3;      // don't re-rank until N events observed

// A/B experiment definitions — extend this array to add new experiments
const AB_EXPERIMENTS = [
  {
    id:        'cta_urgency_v1',
    type:      'cta',
    item_type: 'bundle',
    variants: {
      A: { cta_suffix: '— Limited Offer', urgency_tag: '⚡ Expires in 24h' },
      B: { cta_suffix: '— Best Value',    urgency_tag: '🔥 Top choice this week' },
    },
  },
  {
    id:        'discount_signal_v1',
    type:      'pricing',
    item_type: 'training',
    variants: {
      A: { show_discount: false, discount_pct: 0,   label: null },
      B: { show_discount: true,  discount_pct: 15,  label: '15% OFF for new users' },
    },
  },
  {
    id:        'bundle_urgency_v1',
    type:      'urgency',
    item_type: 'bundle',
    variants: {
      A: { viewing_now_label: '%N people viewing right now',  countdown: true  },
      B: { viewing_now_label: '%N experts recommend this bundle', countdown: false },
    },
  },
];

// ─── Safe helpers ─────────────────────────────────────────────────────────────
function safeParseJSON(str, fallback = null) {
  try { return JSON.parse(str); } catch { return fallback; }
}

function clamp(v, min, max) {
  return Math.min(max, Math.max(min, isNaN(v) ? min : v));
}

export function computeScore(stats) {
  const { click_rate = 0, purchase_rate = 0, ignore_rate = 0 } = stats;
  const raw = SCORE_BASE
    + (purchase_rate * SCORE_WEIGHTS.purchase)
    + (click_rate    * SCORE_WEIGHTS.click)
    + (ignore_rate   * SCORE_WEIGHTS.ignore);
  return Math.round(clamp(raw, 0, 100) * 10) / 10;
}

// SHA-256-lite for IP hashing (Cloudflare Workers compatible)
async function hashIP(ip) {
  if (!ip || ip === 'anon') return 'anon';
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip + 'cdb_salt_v17'));
    return Array.from(new Uint8Array(buf)).slice(0, 8).map(b => b.toString(16).padStart(2,'0')).join('');
  } catch { return 'anon'; }
}

// ─── PHASE 1: Validate feedback input ─────────────────────────────────────────
const VALID_ACTIONS  = new Set(['click','purchase','ignore','dismiss','share']);
const VALID_CONTEXTS = new Set(['scan_result','dashboard','exit_intent','post_payment','marketplace','training_page']);
const VALID_TYPES    = new Set(['tool','training','bundle','upsell','enterprise']);

export function validateFeedback(body) {
  const errors = [];
  if (!VALID_ACTIONS.has(body.action))              errors.push(`Invalid action: ${body.action}`);
  if (!VALID_TYPES.has(body.recommendation_type))   errors.push(`Invalid recommendation_type: ${body.recommendation_type}`);
  if (!body.item_id || typeof body.item_id !== 'string' || body.item_id.length > 80) errors.push('item_id required (max 80 chars)');
  if (body.context && !VALID_CONTEXTS.has(body.context)) errors.push(`Invalid context: ${body.context}`);
  return errors;
}

// ─── PHASE 1: Store feedback event in D1 + update KV score ───────────────────
/**
 * Persists a feedback event. Fire-and-forget safe — never throws to caller.
 */
export async function storeFeedback(env, feedbackData, authCtx = {}) {
  if (!env?.DB) return false;

  const {
    action, context = 'scan_result', recommendation_type,
    item_id, item_name = '', module = '', risk_level = '',
    tier = 'FREE', ab_variant = null, revenue_inr = 0,
  } = feedbackData;

  const success    = action === 'purchase' ? 1 : 0;
  const user_id    = authCtx?.userId || authCtx?.user_id || null;
  const ip_hash    = await hashIP(authCtx?.ip || 'anon');
  const session_id = feedbackData.session_id || null;

  // 1. Insert raw event (fire-and-forget)
  env.DB.prepare(`
    INSERT INTO mcp_feedback
      (id, user_id, session_id, ip_hash, action, context, recommendation_type,
       item_id, item_name, module, risk_level, tier, ab_variant, success, revenue_inr)
    VALUES
      (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    user_id, session_id, ip_hash, action, context, recommendation_type,
    item_id, item_name, module, risk_level, tier, ab_variant, success, revenue_inr || 0
  ).run().catch(e => console.warn('[MCPLearning] D1 feedback insert error:', e.message));

  // 2. Update item score in KV (async, non-blocking)
  updateItemScoreKV(env, item_id, recommendation_type, item_name, action, revenue_inr || 0).catch(() => {});

  // 3. Update context stats (async)
  updateContextStats(env, context, recommendation_type, item_id, action).catch(() => {});

  // 4. Update A/B tracking (if variant provided)
  if (ab_variant) {
    updateABResult(env, feedbackData.experiment_id || 'unknown', ab_variant, item_id, action, revenue_inr || 0).catch(() => {});
  }

  // 5. Update user profile (async, if user_id known)
  if (user_id) {
    updateUserProfile(env, user_id, { action, recommendation_type, item_id, module, success }).catch(() => {});
  }

  return true;
}

// ─── PHASE 2: KV-based item score updater ─────────────────────────────────────
/**
 * Reads current score from KV, applies new event, writes back.
 * KV key: mcp:score:{item_id}
 * This is the core learning signal — runs on every feedback event.
 */
async function updateItemScoreKV(env, item_id, rec_type, item_name, action, revenue_inr) {
  if (!env?.SECURITY_HUB_KV) return;

  const kvKey  = `mcp:score:${item_id}`;
  const raw    = await env.SECURITY_HUB_KV.get(kvKey, 'json').catch(() => null);

  const stats  = raw || {
    item_id, rec_type, item_name,
    total_shown:    0, total_clicks: 0, total_purchases: 0,
    total_ignores:  0, total_dismisses: 0, total_revenue:  0,
    click_rate:     0, purchase_rate:   0, ignore_rate:    0,
    mcp_score:      SCORE_BASE,
    event_count:    0,
  };

  // Increment counters
  stats.event_count++;
  stats.item_name = item_name || stats.item_name;
  stats.rec_type  = rec_type  || stats.rec_type;

  switch (action) {
    case 'click':     stats.total_clicks++;    break;
    case 'purchase':  stats.total_purchases++; stats.total_revenue += revenue_inr; break;
    case 'ignore':    stats.total_ignores++;   break;
    case 'dismiss':   stats.total_dismisses++; break;
  }

  // Infer shown count: any event = 1 impression (shown)
  // purchases and clicks also count as shown (they saw it)
  stats.total_shown = stats.total_clicks + stats.total_purchases
    + stats.total_ignores + stats.total_dismisses;

  if (stats.total_shown > 0) {
    stats.click_rate    = stats.total_clicks    / stats.total_shown;
    stats.purchase_rate = stats.total_purchases / stats.total_shown;
    stats.ignore_rate   = stats.total_ignores   / stats.total_shown;
  }

  stats.mcp_score  = computeScore(stats);
  stats.updated_at = new Date().toISOString();

  // Write back to KV (7 day TTL)
  await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(stats), { expirationTtl: KV_SCORE_TTL });

  // Also sync to D1 for persistence + analytics (upsert)
  if (env?.DB) {
    env.DB.prepare(`
      INSERT INTO mcp_item_scores
        (item_id, item_name, recommendation_type, total_shown, total_clicks,
         total_purchases, total_ignores, total_dismisses, total_revenue_inr,
         click_rate, purchase_rate, ignore_rate, mcp_score, last_updated)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'))
      ON CONFLICT(item_id) DO UPDATE SET
        item_name        = excluded.item_name,
        total_shown      = excluded.total_shown,
        total_clicks     = excluded.total_clicks,
        total_purchases  = excluded.total_purchases,
        total_ignores    = excluded.total_ignores,
        total_dismisses  = excluded.total_dismisses,
        total_revenue_inr= excluded.total_revenue_inr,
        click_rate       = excluded.click_rate,
        purchase_rate    = excluded.purchase_rate,
        ignore_rate      = excluded.ignore_rate,
        mcp_score        = excluded.mcp_score,
        last_updated     = datetime('now')
    `).bind(
      stats.item_id, stats.item_name || '', rec_type,
      stats.total_shown, stats.total_clicks, stats.total_purchases,
      stats.total_ignores, stats.total_dismisses, stats.total_revenue,
      stats.click_rate, stats.purchase_rate, stats.ignore_rate, stats.mcp_score,
    ).run().catch(() => {});
  }
}

// ─── PHASE 5: Context performance tracker ─────────────────────────────────────
async function updateContextStats(env, context, rec_type, item_id, action) {
  if (!env?.SECURITY_HUB_KV) return;

  const kvKey = `mcp:ctx:${context}:${rec_type}:${item_id}`;
  const raw   = await env.SECURITY_HUB_KV.get(kvKey, 'json').catch(() => null);
  const stats = raw || { context, rec_type, item_id, shown: 0, conversions: 0, rate: 0 };

  stats.shown++;
  if (action === 'purchase') stats.conversions++;
  stats.rate       = stats.conversions / stats.shown;
  stats.updated_at = new Date().toISOString();

  await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(stats), { expirationTtl: KV_CTX_TTL });
}

// ─── PHASE 7: A/B result tracker ──────────────────────────────────────────────
async function updateABResult(env, experiment_id, variant, item_id, action, revenue_inr) {
  if (!env?.SECURITY_HUB_KV) return;

  const kvKey = `mcp:ab:${experiment_id}`;
  const raw   = await env.SECURITY_HUB_KV.get(kvKey, 'json').catch(() => null);
  const data  = raw || { A: { impressions:0, clicks:0, purchases:0, revenue:0 }, B: { impressions:0, clicks:0, purchases:0, revenue:0 } };

  const v = data[variant] || { impressions:0, clicks:0, purchases:0, revenue:0 };
  v.impressions++;
  if (action === 'click')    v.clicks++;
  if (action === 'purchase') { v.purchases++; v.revenue += revenue_inr; }
  v.click_rate    = v.clicks    / v.impressions;
  v.purchase_rate = v.purchases / v.impressions;
  data[variant]   = v;

  // Determine winner if enough data (min 20 impressions per variant)
  if (data.A.impressions >= 20 && data.B.impressions >= 20 && !data.winner) {
    data.winner = data.A.purchase_rate >= data.B.purchase_rate ? 'A' : 'B';
    // Store winner separately for fast lookup
    env.SECURITY_HUB_KV.put(`mcp:ab:winner:${experiment_id}`, data.winner, { expirationTtl: KV_AB_TTL }).catch(() => {});
  }

  await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(data), { expirationTtl: KV_AB_TTL });
}

// ─── PHASE 4: User profile updater ────────────────────────────────────────────
async function updateUserProfile(env, user_id, event) {
  if (!env?.SECURITY_HUB_KV || !user_id) return;

  const kvKey = `mcp:profile:${user_id}`;
  const raw   = await env.SECURITY_HUB_KV.get(kvKey, 'json').catch(() => null);
  const profile = raw || {
    user_id,
    preferred_tools:    [],
    preferred_training: [],
    preferred_bundles:  [],
    risk_pattern:       'unknown',
    conversion_behavior:'unknown',
    top_module:         null,
    avg_risk_score:     0,
    total_interactions: 0,
    total_purchases:    0,
    purchase_types:     {},
  };

  profile.total_interactions++;

  if (event.action === 'purchase') {
    profile.total_purchases++;
    profile.purchase_types[event.recommendation_type] =
      (profile.purchase_types[event.recommendation_type] || 0) + 1;

    // Add to preferred list (top 5)
    if (event.recommendation_type === 'tool') {
      profile.preferred_tools = [...new Set([event.item_id, ...profile.preferred_tools])].slice(0, 5);
    } else if (event.recommendation_type === 'training') {
      profile.preferred_training = [...new Set([event.item_id, ...profile.preferred_training])].slice(0, 5);
    } else if (event.recommendation_type === 'bundle') {
      profile.preferred_bundles = [...new Set([event.item_id, ...profile.preferred_bundles])].slice(0, 3);
    }
  }

  if (event.module) profile.top_module = event.module;

  // Infer conversion behavior
  const purchaseRatio = profile.total_interactions > 0 ? profile.total_purchases / profile.total_interactions : 0;
  if (profile.total_purchases >= 3)           profile.conversion_behavior = 'quick_buyer';
  else if (purchaseRatio > 0.2)               profile.conversion_behavior = 'quick_buyer';
  else if (profile.total_interactions > 10 && profile.total_purchases === 0) profile.conversion_behavior = 'researcher';
  else if (profile.total_purchases >= 1)      profile.conversion_behavior = 'paid_user';
  else                                        profile.conversion_behavior = 'browser';

  profile.updated_at = new Date().toISOString();

  await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(profile), { expirationTtl: KV_PROFILE_TTL });
}

// ─── PHASE 3: Adaptive recommendation re-ranker ───────────────────────────────
/**
 * Re-ranks a list of items using their KV scores.
 * Items with no score data keep their base ranking.
 * Only re-ranks when >= MIN_EVENTS_FOR_LEARNING events observed.
 *
 * @param {Array} items - Array of {id, ...} objects
 * @param {string} itemKey - field name for the item id (e.g. 'id', 'tool')
 * @param {object} env - Cloudflare env (KV access)
 * @returns {Array} sorted items by score DESC
 */
export async function reRankItems(items, itemKey = 'id', env) {
  if (!items?.length || !env?.SECURITY_HUB_KV) return items;

  try {
    // Parallel KV reads for all item scores
    const scorePromises = items.map(item => {
      const id = item[itemKey] || item.id || item.tool || '';
      return env.SECURITY_HUB_KV.get(`mcp:score:${id}`, 'json').catch(() => null);
    });

    const scores = await Promise.all(scorePromises);

    // Attach scores to items
    const scored = items.map((item, i) => {
      const s = scores[i];
      const id = item[itemKey] || item.id || item.tool || '';
      return {
        ...item,
        _mcp_score:       s?.mcp_score    ?? SCORE_BASE,
        _mcp_events:      s?.event_count  ?? 0,
        _mcp_click_rate:  s?.click_rate   ?? 0,
        _mcp_purchase_rate: s?.purchase_rate ?? 0,
      };
    });

    // Only apply learned ranking when enough data exists
    const hasLearning = scored.some(i => i._mcp_events >= MIN_EVENTS_FOR_LEARNING);
    if (!hasLearning) return items; // not enough data yet — keep original order

    // Sort by score DESC
    scored.sort((a, b) => b._mcp_score - a._mcp_score);

    // Strip internal score fields before returning
    return scored.map(({ _mcp_score, _mcp_events, _mcp_click_rate, _mcp_purchase_rate, ...item }) => item);

  } catch { return items; } // failsafe: return original order
}

// ─── PHASE 4: Load user preference profile from KV ────────────────────────────
/**
 * Returns learned user preferences, or null if no data yet.
 * Fast: single KV read.
 */
export async function loadUserProfile(env, user_id) {
  if (!env?.SECURITY_HUB_KV || !user_id) return null;
  try {
    return await env.SECURITY_HUB_KV.get(`mcp:profile:${user_id}`, 'json');
  } catch { return null; }
}

// ─── PHASE 5: Load best context for a recommendation type ─────────────────────
/**
 * Returns the context that historically converts best for this item + type.
 * Uses KV context stats.
 */
export async function getBestContext(env, item_id, rec_type) {
  if (!env?.SECURITY_HUB_KV) return null;
  const contexts = ['scan_result', 'dashboard', 'exit_intent'];
  try {
    const rates = await Promise.all(
      contexts.map(ctx =>
        env.SECURITY_HUB_KV.get(`mcp:ctx:${ctx}:${rec_type}:${item_id}`, 'json').catch(() => null)
      )
    );
    const best = rates
      .map((r, i) => ({ ctx: contexts[i], rate: r?.rate ?? 0, shown: r?.shown ?? 0 }))
      .filter(r => r.shown >= 5) // minimum data threshold
      .sort((a, b) => b.rate - a.rate)[0];
    return best?.ctx || null;
  } catch { return null; }
}

// ─── PHASE 6: Dynamic pricing signal (visual only — NO price changes) ─────────
/**
 * Generates discount/urgency signals based on user profile + item performance.
 * CRITICAL: Only affects display text. Actual prices never change.
 *
 * @returns { show_discount, discount_label, urgency_label, social_proof }
 */
export async function getPricingSignal(env, item_id, item_price, user_profile, risk_level) {
  if (!env?.SECURITY_HUB_KV) return null;

  try {
    const kvKey    = `mcp:score:${item_id}`;
    const itemScore = await env.SECURITY_HUB_KV.get(kvKey, 'json').catch(() => null);

    // Low-performing item + price-sensitive user → show visual discount
    const isLowPerforming   = itemScore && itemScore.mcp_score < 40;
    const isPriceSensitive  = user_profile?.conversion_behavior === 'researcher' ||
                              user_profile?.conversion_behavior === 'browser';
    const isHighRisk        = risk_level === 'HIGH' || risk_level === 'CRITICAL';
    const isReturningBuyer  = user_profile?.conversion_behavior === 'quick_buyer' ||
                              (user_profile?.total_purchases ?? 0) >= 1;

    let signal = null;

    if (isHighRisk && isPriceSensitive) {
      // High risk + researcher: show urgency (not discount — already motivated)
      signal = {
        show_discount:   false,
        discount_label:  null,
        urgency_label:   '🚨 Act now — your security risk is HIGH',
        show_scarcity:   true,
        scarcity_label:  `${42 + new Date().getHours()} people secured their platform today`,
      };
    } else if (isLowPerforming && isPriceSensitive && !isReturningBuyer) {
      // Low-performing item + price-sensitive new user: show visual 15% off
      const displayPrice = Math.round(item_price * 0.85);
      signal = {
        show_discount:   true,
        original_price:  item_price,
        display_price:   displayPrice,
        discount_pct:    15,
        discount_label:  '15% off — for first-time buyers',
        urgency_label:   null,
        show_scarcity:   false,
      };
    } else if (isReturningBuyer) {
      // Returning buyer: loyalty signal
      signal = {
        show_discount:   false,
        discount_label:  null,
        urgency_label:   '🏆 Returning member pricing',
        show_scarcity:   false,
        loyalty:         true,
      };
    }

    return signal;
  } catch { return null; }
}

// ─── PHASE 7: A/B variant selector ────────────────────────────────────────────
/**
 * Selects A/B variant for an experiment.
 * Priority: winning variant > user-stable random > pure random (anonymous)
 * Deterministic per user_id so same user always gets same variant.
 */
export async function selectABVariant(env, experiment_id, user_id = null) {
  if (!env?.SECURITY_HUB_KV) return 'A'; // no KV = always A (safe default)

  try {
    // 1. Check if a winner has been determined
    const winner = await env.SECURITY_HUB_KV.get(`mcp:ab:winner:${experiment_id}`).catch(() => null);
    if (winner === 'A' || winner === 'B') return winner;

    // 2. Deterministic assignment by user_id (stable across sessions)
    if (user_id) {
      let hash = 0;
      for (const c of (user_id + experiment_id)) hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
      return (Math.abs(hash) % 2 === 0) ? 'A' : 'B';
    }

    // 3. Pure random for anonymous (50/50)
    return Math.random() < 0.5 ? 'A' : 'B';
  } catch { return 'A'; }
}

/**
 * Apply A/B variant to a recommendation item (tool, bundle, or upsell).
 * Mutates display fields only. Returns modified item.
 */
export async function applyABVariant(env, item, item_type, user_id) {
  if (!item) return item;

  try {
    for (const exp of AB_EXPERIMENTS) {
      if (exp.item_type !== item_type) continue;

      const variant      = await selectABVariant(env, exp.id, user_id);
      const variantCfg   = exp.variants[variant];
      if (!variantCfg) continue;

      // Apply variant config to item display fields
      const modified = { ...item, _ab_experiment: exp.id, _ab_variant: variant };

      if (exp.type === 'cta' && item.cta_text) {
        modified.cta_text     = item.cta_text + ' ' + (variantCfg.cta_suffix || '');
        modified.urgency_tag  = variantCfg.urgency_tag || null;
      }
      if (exp.type === 'urgency' && item.social_proof) {
        const n = item.social_proof?.viewing_now || 12;
        modified.social_proof = {
          ...item.social_proof,
          label: (variantCfg.viewing_now_label || '%N').replace('%N', n),
        };
        modified.show_countdown = variantCfg.countdown !== false;
      }

      return modified;
    }
  } catch { /* return original on any error */ }

  return item;
}

// ─── PHASE 4: Personalize recommendations using user profile ──────────────────
/**
 * Adjusts tool + training arrays based on user's learned preferences.
 * Moves previously-purchased items to end (avoid showing same thing twice).
 * Boosts items in preferred lists.
 */
export function personalizeRecommendations(tools, training, userProfile) {
  if (!userProfile) return { tools, training };

  try {
    const preferredTools    = new Set(userProfile.preferred_tools || []);
    const preferredTraining = new Set(userProfile.preferred_training || []);
    const boughtTraining    = new Set(userProfile.preferred_training || []); // already bought

    // For tools: boost preferred (already bought = exclude if more than 1 option)
    let adjustedTools = [...(tools || [])];
    if (preferredTools.size > 0 && adjustedTools.length > 1) {
      adjustedTools.sort((a, b) => {
        const aId = a.id || a.tool || '';
        const bId = b.id || b.tool || '';
        return (preferredTools.has(bId) ? 1 : 0) - (preferredTools.has(aId) ? 1 : 0);
      });
    }

    // For training: don't show already-purchased courses (move to end)
    let adjustedTraining = [...(training || [])];
    if (boughtTraining.size > 0 && adjustedTraining.length > 1) {
      adjustedTraining.sort((a, b) => {
        const aId  = a.id || '';
        const bId  = b.id || '';
        const aBought = boughtTraining.has(aId) ? 1 : 0;
        const bBought = boughtTraining.has(bId) ? 1 : 0;
        return aBought - bBought; // push bought items to end
      });
    }

    return { tools: adjustedTools, training: adjustedTraining };
  } catch { return { tools, training }; }
}

// ─── PHASE 3+7: Full adaptive enrichment pipeline ─────────────────────────────
/**
 * THE LEARNING PIPELINE — called from handleMCPControl.
 * Runs all learning phases in parallel, then applies results.
 * FAILSAFE: any failure returns original data unchanged.
 *
 * @param {object} env - Cloudflare env
 * @param {object} ctx - { module, risk_level, tier, user_id, user_profile,
 *                         tools, training, bundle_offer, upsell }
 * @returns {object} - enriched { tools, training, bundle_offer, upsell,
 *                                pricing_signal, ab_variants, best_context }
 */
export async function runLearningPipeline(env, ctx) {
  const {
    module, risk_level, tier, user_id,
    user_profile,
    tools = [], training = [], bundle_offer = null, upsell = null,
  } = ctx;

  const out = {
    tools, training, bundle_offer, upsell,
    pricing_signal: null,
    ab_variants: {},
    best_context: null,
    learning_applied: false,
  };

  if (!env?.SECURITY_HUB_KV) return out; // no KV — return unchanged

  try {
    // 1. Load item scores + apply personalization in parallel
    const [rankedTools, rankedTraining, bestCtx] = await Promise.all([
      reRankItems(tools, 'tool', env),
      reRankItems(training, 'id', env),
      bundle_offer ? getBestContext(env, bundle_offer.id, 'bundle') : Promise.resolve(null),
    ]);

    // 2. Personalize using user profile
    const { tools: personalizedTools, training: personalizedTraining } =
      personalizeRecommendations(rankedTools, rankedTraining, user_profile);

    out.tools    = personalizedTools;
    out.training = personalizedTraining;
    out.best_context = bestCtx;

    // 3. Apply A/B variants to bundle and upsell (parallel)
    const [bundleWithAB, upsellWithAB] = await Promise.all([
      bundle_offer ? applyABVariant(env, bundle_offer, 'bundle', user_id) : Promise.resolve(null),
      upsell?.show ? applyABVariant(env, upsell, 'training', user_id) : Promise.resolve(upsell),
    ]);

    out.bundle_offer = bundleWithAB;
    out.upsell       = upsellWithAB;

    // 4. Pricing signal for primary training recommendation
    if (personalizedTraining?.[0]) {
      const t = personalizedTraining[0];
      out.pricing_signal = await getPricingSignal(
        env, t.id, t.price || 0, user_profile, risk_level
      );
    }

    // 5. Collect AB variant info for telemetry
    const abKeys = {};
    if (bundleWithAB?._ab_experiment) abKeys[bundleWithAB._ab_experiment] = bundleWithAB._ab_variant;
    if (upsellWithAB?._ab_experiment) abKeys[upsellWithAB._ab_experiment] = upsellWithAB._ab_variant;
    out.ab_variants       = abKeys;
    out.learning_applied  = true;

    return out;
  } catch (e) {
    console.warn('[MCPLearning] Pipeline error (failsafe activated):', e.message);
    return out; // return original unchanged
  }
}

// ─── All exports use the export keyword on their declarations above ───────────
// (No duplicate export block needed)
