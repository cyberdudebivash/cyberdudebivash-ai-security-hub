/**
 * CYBERDUDEBIVASH AI Security Hub
 * BEHAVIORAL ANOMALY DETECTION ENGINE — System 2
 * Real Isolation Forest + statistical Z-score baseline deviation
 * NO MOCK DATA — all computation uses real D1 behavioral events
 *
 * Algorithm:
 *  1. Build per-user statistical baseline from last 30 days of behavior_events
 *  2. Compute Z-score deviation for current request vs baseline
 *  3. Run Isolation Forest on feature vector (sub-linear anomaly isolation)
 *  4. Composite score = 0.55 * iForest_score + 0.45 * z_score_normalized
 *  5. Persist anomaly_events when score >= 40
 */

function now() { return new Date().toISOString(); }

// ─── ISOLATION FOREST IMPLEMENTATION ───────────────────────────────────────

const IF_N_TREES     = 50;  // Number of isolation trees
const IF_SUBSAMPLE   = 64;  // Subsample size per tree (powers of 2 work best)
const IF_MAX_DEPTH   = 10;  // log2(subsample) ≈ 6, use 10 for safety

/**
 * Build a single isolation tree by recursive random splitting
 */
function buildITree(data, depth = 0) {
  if (depth >= IF_MAX_DEPTH || data.length <= 1) {
    return { type: 'leaf', size: data.length };
  }

  const nFeatures = data[0].length;
  const featIdx   = Math.floor(Math.random() * nFeatures);
  const vals      = data.map(d => d[featIdx]);
  const minVal    = Math.min(...vals);
  const maxVal    = Math.max(...vals);

  if (minVal === maxVal) {
    return { type: 'leaf', size: data.length };
  }

  const splitVal = minVal + Math.random() * (maxVal - minVal);
  const left     = data.filter(d => d[featIdx] < splitVal);
  const right    = data.filter(d => d[featIdx] >= splitVal);

  return {
    type:       'node',
    featIdx,
    splitVal,
    left:       buildITree(left,  depth + 1),
    right:      buildITree(right, depth + 1),
  };
}

/**
 * Compute path length for a single point through one tree
 */
function pathLength(point, node, depth = 0) {
  if (node.type === 'leaf') {
    return depth + cFactor(node.size);
  }
  if (point[node.featIdx] < node.splitVal) {
    return pathLength(point, node.left, depth + 1);
  }
  return pathLength(point, node.right, depth + 1);
}

/**
 * Average path length of unsuccessful BST search (normalization constant)
 */
function cFactor(n) {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  const H = Math.log(n - 1) + 0.5772156649; // Euler-Mascheroni
  return 2 * H - (2 * (n - 1) / n);
}

/**
 * Build Isolation Forest from sample matrix
 */
function buildIsolationForest(samples) {
  const n    = Math.min(samples.length, IF_SUBSAMPLE);
  const trees = [];

  for (let i = 0; i < IF_N_TREES; i++) {
    // Random subsample without replacement
    const shuffled = [...samples].sort(() => Math.random() - 0.5).slice(0, n);
    trees.push(buildITree(shuffled));
  }

  return { trees, subsample: n };
}

/**
 * Compute anomaly score for a single point: 0 (normal) → 1 (anomalous)
 */
function isolationScore(point, forest) {
  const avgDepth = forest.trees.reduce(
    (sum, tree) => sum + pathLength(point, tree), 0
  ) / forest.trees.length;

  const c = cFactor(forest.subsample);
  return Math.pow(2, -avgDepth / c); // Score in (0, 1)
}

// ─── FEATURE EXTRACTION ────────────────────────────────────────────────────

/**
 * Convert a behavior event row into a normalized feature vector
 * Features: [requests_per_min, failed_auth_ratio, unique_endpoints,
 *            hour_of_day_norm, geo_anomaly_flag, payload_size_norm,
 *            error_rate, session_age_norm]
 */
function extractFeatures(event) {
  return [
    Math.min((event.requests_per_min || 0) / 200, 1),
    Math.min((event.failed_auth_count || 0) / 20, 1),
    Math.min((event.unique_endpoints || 0) / 50, 1),
    ((event.hour_of_day || 12) / 23),
    event.geo_anomaly ? 1 : 0,
    Math.min((event.payload_size_bytes || 0) / 1_000_000, 1),
    Math.min((event.error_count || 0) / 100, 1),
    Math.min((event.session_age_seconds || 0) / 86400, 1),
  ];
}

// ─── STATISTICAL Z-SCORE BASELINE ─────────────────────────────────────────

/**
 * Compute mean and stddev for an array of numbers
 */
function stats(arr) {
  if (arr.length === 0) return { mean: 0, std: 1 };
  const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
  const variance = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
  return { mean, std: Math.sqrt(variance) || 1 };
}

/**
 * Compute composite Z-score across all features vs historical baseline
 * Returns normalized score 0–100
 */
function computeZScore(currentFeatures, baselineFeatures) {
  if (baselineFeatures.length === 0) return 50; // No baseline = medium risk

  const nFeatures = currentFeatures.length;
  let totalZ = 0;

  for (let i = 0; i < nFeatures; i++) {
    const col  = baselineFeatures.map(row => row[i]);
    const { mean, std } = stats(col);
    const z    = Math.abs((currentFeatures[i] - mean) / std);
    totalZ    += Math.min(z, 5); // Cap at 5σ per feature
  }

  const avgZ    = totalZ / nFeatures;          // 0–5
  const normZ   = Math.min(avgZ / 5, 1) * 100; // 0–100
  return normZ;
}

// ─── ANOMALY TYPES DETECTION ──────────────────────────────────────────────

/**
 * Detect specific anomaly types from event data
 */
function detectAnomalyTypes(event, baseline) {
  const types = [];

  if ((event.requests_per_min || 0) > 120) types.push('rate_spike');
  if ((event.failed_auth_count || 0) > 5)  types.push('auth_failure_burst');
  if (event.geo_anomaly)                    types.push('geo_anomaly');
  if ((event.unique_endpoints || 0) > 30)   types.push('endpoint_enumeration');
  if ((event.error_count || 0) > 50)        types.push('error_burst');
  if ((event.payload_size_bytes || 0) > 500_000) types.push('large_payload');

  // Time-based anomalies
  const hour = event.hour_of_day || new Date().getHours();
  if (hour >= 1 && hour <= 5)               types.push('off_hours_access');

  // Baseline deviations
  if (baseline.avg_requests_per_min > 0) {
    const ratio = (event.requests_per_min || 0) / baseline.avg_requests_per_min;
    if (ratio > 5) types.push('request_spike_5x');
    if (ratio > 10) types.push('request_spike_10x');
  }

  return types;
}

// ─── MAIN SCORING FUNCTION ─────────────────────────────────────────────────

/**
 * Score a user's current behavior against their historical baseline
 * Returns: { anomaly_score, anomaly_types, risk_level, if_score, z_score, baseline_count }
 */
export async function scoreUserBehavior(env, userId, currentEvent) {
  // Fetch 30-day behavioral baseline from D1
  const baselineRows = await env.DB.prepare(`
    SELECT requests_per_min, failed_auth_count, unique_endpoints,
           strftime('%H', created_at) as hour_of_day,
           geo_anomaly, payload_size_bytes, error_count, session_age_seconds
    FROM behavior_events
    WHERE user_id = ?
      AND created_at > datetime('now', '-30 days')
    ORDER BY created_at DESC
    LIMIT 500
  `).bind(userId).all().catch(() => ({ results: [] }));

  const baselineEvents = baselineRows.results || [];
  const baselineFeatures = baselineEvents.map(e => extractFeatures({
    ...e,
    hour_of_day: parseInt(e.hour_of_day || '12'),
  }));

  // Compute baseline stats for anomaly type detection
  const baselineStats = {
    avg_requests_per_min: baselineEvents.length > 0
      ? baselineEvents.reduce((s, e) => s + (e.requests_per_min || 0), 0) / baselineEvents.length
      : 0,
    avg_error_count: baselineEvents.length > 0
      ? baselineEvents.reduce((s, e) => s + (e.error_count || 0), 0) / baselineEvents.length
      : 0,
  };

  const currentFeatures = extractFeatures({
    ...currentEvent,
    hour_of_day: currentEvent.hour_of_day || new Date().getHours(),
  });

  // Z-score deviation
  const zScore = computeZScore(currentFeatures, baselineFeatures);

  // Isolation Forest (need baseline to have enough samples)
  let ifScore = 50; // Default neutral
  if (baselineFeatures.length >= 10) {
    // Include current event in the dataset for IForest
    const allFeatures = [...baselineFeatures, currentFeatures];
    const forest      = buildIsolationForest(allFeatures);
    const rawIfScore  = isolationScore(currentFeatures, forest);
    // rawIfScore: ~0.5 = normal, >0.7 = anomalous. Normalize to 0-100.
    ifScore = Math.min(100, Math.max(0, (rawIfScore - 0.4) / 0.6 * 100));
  }

  // Composite score: weighted blend
  const compositeScore = Math.round(0.55 * ifScore + 0.45 * zScore);

  // Anomaly types
  const anomalyTypes = detectAnomalyTypes(currentEvent, baselineStats);

  const riskLevel = compositeScore >= 80 ? 'CRITICAL'
                  : compositeScore >= 60 ? 'HIGH'
                  : compositeScore >= 40 ? 'MEDIUM'
                  : 'LOW';

  return {
    anomaly_score:    compositeScore,
    anomaly_types:    anomalyTypes,
    risk_level:       riskLevel,
    if_score:         Math.round(ifScore),
    z_score:          Math.round(zScore),
    baseline_count:   baselineFeatures.length,
    reasoning: `IForest=${Math.round(ifScore)}/100 (${baselineFeatures.length} samples) + ZScore=${Math.round(zScore)}/100 → Composite=${compositeScore}/100`,
  };
}

/**
 * Record a behavior event for a user (called from request middleware)
 * Enriches with computed metrics then stores in D1
 */
export async function recordBehaviorEvent(env, userId, ip, requestData) {
  const {
    endpoint        = '/',
    method          = 'GET',
    status_code     = 200,
    payload_size    = 0,
    response_time   = 0,
    user_agent      = '',
    country_code    = '',
    session_id      = '',
  } = requestData;

  // Fetch recent request count for this user (sliding window)
  const recentCount = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM behavior_events
    WHERE user_id=? AND created_at > datetime('now', '-1 minute')
  `).bind(userId).first().catch(() => ({ cnt: 0 }));

  const requestsPerMin = (recentCount?.cnt || 0) + 1;

  // Check for geographic anomaly: different country from last 5 events
  const lastCountry = await env.DB.prepare(`
    SELECT country_code FROM behavior_events
    WHERE user_id=? AND country_code != '' ORDER BY created_at DESC LIMIT 1
  `).bind(userId).first().catch(() => null);

  const geoAnomaly = lastCountry && country_code && lastCountry.country_code !== country_code;

  // Count recent auth failures
  const failedAuth = await env.DB.prepare(`
    SELECT COUNT(*) as cnt FROM behavior_events
    WHERE user_id=? AND status_code IN (401, 403) AND created_at > datetime('now', '-10 minutes')
  `).bind(userId).first().catch(() => ({ cnt: 0 }));

  // Count unique endpoints in last 5 minutes
  const uniqueEp = await env.DB.prepare(`
    SELECT COUNT(DISTINCT endpoint) as cnt FROM behavior_events
    WHERE user_id=? AND created_at > datetime('now', '-5 minutes')
  `).bind(userId).first().catch(() => ({ cnt: 0 }));

  const hour = new Date().getHours();

  const insertResult = await env.DB.prepare(`
    INSERT INTO behavior_events
      (user_id, ip, endpoint, method, status_code, payload_size_bytes,
       response_time_ms, user_agent, country_code, session_id,
       requests_per_min, failed_auth_count, unique_endpoints,
       hour_of_day, geo_anomaly, error_count, session_age_seconds, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    userId, ip, endpoint, method, status_code, payload_size,
    response_time, user_agent, country_code || '', session_id || '',
    requestsPerMin,
    failedAuth?.cnt || 0,
    (uniqueEp?.cnt || 0) + 1,
    hour,
    geoAnomaly ? 1 : 0,
    status_code >= 400 ? 1 : 0,
    0, // session_age_seconds — computed elsewhere
    now()
  ).run().catch(() => null);

  return {
    recorded: !!insertResult,
    requests_per_min: requestsPerMin,
    geo_anomaly: geoAnomaly,
    failed_auth: failedAuth?.cnt || 0,
  };
}

/**
 * Run full anomaly detection for a user with their latest event
 * Called from anomaly handler API
 */
export async function detectAnomaly(env, userId, latestEventData = {}) {
  // Fetch the most recent behavior event if no data passed
  let eventData = latestEventData;
  if (!eventData.requests_per_min) {
    const latest = await env.DB.prepare(`
      SELECT * FROM behavior_events WHERE user_id=? ORDER BY created_at DESC LIMIT 1
    `).bind(userId).first().catch(() => null);

    if (latest) {
      eventData = {
        ...latest,
        hour_of_day: parseInt(latest.hour_of_day || new Date().getHours()),
      };
    }
  }

  const result = await scoreUserBehavior(env, userId, eventData);

  // Persist anomaly event if score is noteworthy
  if (result.anomaly_score >= 40) {
    await env.DB.prepare(`
      INSERT INTO anomaly_events
        (user_id, ip, anomaly_score, anomaly_types, risk_level,
         if_score, z_score, baseline_count, reasoning, event_data, created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    `).bind(
      userId,
      eventData.ip || '',
      result.anomaly_score,
      JSON.stringify(result.anomaly_types),
      result.risk_level,
      result.if_score,
      result.z_score,
      result.baseline_count,
      result.reasoning,
      JSON.stringify(eventData),
      now()
    ).run().catch(() => {});
  }

  return {
    user_id:       userId,
    ...result,
    timestamp:     now(),
  };
}

/**
 * Batch anomaly scan — called from cron
 * Scans users with recent activity and scores them
 */
export async function runAnomalyBatch(env) {
  // Find users with activity in the last 15 minutes
  const activeUsers = await env.DB.prepare(`
    SELECT DISTINCT user_id FROM behavior_events
    WHERE created_at > datetime('now', '-15 minutes')
    LIMIT 50
  `).all().catch(() => ({ results: [] }));

  const results = [];

  for (const row of (activeUsers.results || [])) {
    try {
      const r = await detectAnomaly(env, row.user_id);
      if (r.anomaly_score >= 40) {
        results.push(r);
      }
    } catch (e) {
      // Silent — don't crash batch on single user error
    }
  }

  return {
    scanned:  (activeUsers.results || []).length,
    anomalies_detected: results.length,
    high_risk: results.filter(r => r.anomaly_score >= 80).length,
    results,
    timestamp: now(),
  };
}

/**
 * Get anomaly history for a user
 */
export async function getUserAnomalyHistory(env, userId, limit = 20) {
  const rows = await env.DB.prepare(`
    SELECT anomaly_score, anomaly_types, risk_level, if_score, z_score,
           baseline_count, reasoning, created_at
    FROM anomaly_events
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(userId, limit).all().catch(() => ({ results: [] }));

  return {
    user_id: userId,
    history: (rows.results || []).map(r => ({
      ...r,
      anomaly_types: (() => { try { return JSON.parse(r.anomaly_types); } catch { return []; } })(),
    })),
    timestamp: now(),
  };
}

/**
 * Get system-wide anomaly stats
 */
export async function getAnomalyStats(env) {
  const [total, byRisk, recent] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as cnt FROM anomaly_events WHERE created_at > datetime('now', '-24 hours')`).first().catch(() => ({ cnt: 0 })),
    env.DB.prepare(`SELECT risk_level, COUNT(*) as cnt FROM anomaly_events WHERE created_at > datetime('now', '-24 hours') GROUP BY risk_level`).all().catch(() => ({ results: [] })),
    env.DB.prepare(`SELECT user_id, anomaly_score, risk_level, anomaly_types, created_at FROM anomaly_events ORDER BY created_at DESC LIMIT 10`).all().catch(() => ({ results: [] })),
  ]);

  return {
    last_24h_total:   total?.cnt || 0,
    by_risk_level:    byRisk.results || [],
    recent_anomalies: (recent.results || []).map(r => ({
      ...r,
      anomaly_types: (() => { try { return JSON.parse(r.anomaly_types); } catch { return []; } })(),
    })),
    timestamp: now(),
  };
}
