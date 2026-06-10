/**
 * CYBERDUDEBIVASH AI Security Hub — High-Revenue Feature Handlers v1.0
 * ────────────────────────────────────────────────────────────────────
 * Routes:
 *
 *   IOC ENRICHMENT (all tiers, rate-limited):
 *   GET  /api/ioc/enrich?value=<ioc>&type=<type>   — Single IOC lookup
 *   POST /api/ioc/enrich/batch                      — Batch IOC lookup (PRO+)
 *   GET  /api/ioc/history                           — User's enrichment history
 *
 *   ATTACK SURFACE MANAGEMENT (PRO/ENTERPRISE):
 *   POST /api/asm/targets                           — Add domain to monitor
 *   GET  /api/asm/targets                           — List user's ASM targets
 *   POST /api/asm/targets/:id/scan                  — Trigger manual scan
 *   GET  /api/asm/targets/:id/report                — Get full ASM report
 *   DELETE /api/asm/targets/:id                     — Remove target
 *
 *   BRAND PROTECTION (PRO/ENTERPRISE):
 *   POST /api/brand/monitors                        — Add brand to monitor
 *   GET  /api/brand/monitors                        — List user's monitors
 *   POST /api/brand/monitors/:id/scan               — Trigger brand scan
 *   GET  /api/brand/monitors/:id/threats            — Get detected threats
 *
 *   THREAT ACTOR PROFILING (all tiers):
 *   GET  /api/threat-actors                         — List all APTs (filterable)
 *   GET  /api/threat-actors/:id                     — Get actor profile
 *   GET  /api/threat-actors/search?q=               — Search actors
 *   POST /api/threat-actors/attribute               — Attribute IOC to actor
 *   POST /api/admin/threat-actors/seed              — Seed APT database (admin)
 */

import { enrichIOC, enrichIOCBatch }               from '../services/iocEnrichmentEngine.js';
import { runASMScan, getASMReport }                 from '../services/asmEngine.js';
import { runBrandScan, generateTyposquattingVariants } from '../services/brandProtectionEngine.js';
import {
  listThreatActors, getThreatActor, searchThreatActors,
  attributeIOC, seedThreatActors,
} from '../services/threatActorEngine.js';

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
});

// ─── Tier helpers ─────────────────────────────────────────────────────────────
const DAILY_LIMITS = { FREE: 10, PRO: 500, ENTERPRISE: -1 };

async function checkAndTrackUsage(env, authCtx, feature) {
  const tier  = authCtx?.tier || 'FREE';
  const limit = DAILY_LIMITS[tier] ?? DAILY_LIMITS.FREE;
  if (limit === -1) return { allowed: true, remaining: -1 };

  if (!env.KV) return { allowed: true, remaining: limit };

  const key   = `usage:${feature}:${authCtx?.user_id || authCtx?.ip}:${new Date().toISOString().slice(0, 10)}`;
  const used  = parseInt(await env.KV.get(key) || '0', 10);

  if (used >= limit) {
    return { allowed: false, remaining: 0, limit, tier, used };
  }

  await env.KV.put(key, String(used + 1), { expirationTtl: 86400 }).catch(() => {});
  return { allowed: true, remaining: limit - used - 1, limit, tier };
}

// ─── ─── ─── IOC ENRICHMENT ─── ─── ───────────────────────────────────────────

export async function handleIOCEnrich(request, env, authCtx) {
  const url    = new URL(request.url);
  const value  = url.searchParams.get('value')?.trim();
  const type   = url.searchParams.get('type') || null;

  if (!value) return json({ success: false, error: 'Missing ?value= parameter' }, 400);
  if (value.length > 512) return json({ success: false, error: 'Value too long (max 512 chars)' }, 400);

  // Rate limit
  const usage = await checkAndTrackUsage(env, authCtx, 'ioc_enrich');
  if (!usage.allowed) {
    return json({
      success: false,
      error:   `Daily IOC enrichment limit reached (${usage.limit}/day on ${usage.tier} plan)`,
      upgrade: 'https://tools.cyberdudebivash.com/#pricing',
    }, 429);
  }

  try {
    const result = await enrichIOC(env, value, type);

    // Log request
    if (env.DB) {
      env.DB.prepare(`
        INSERT INTO ioc_requests (id, user_id, ioc_type, ioc_value, verdict, from_cache)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        `req_${Date.now()}`,
        authCtx?.user_id || null,
        result.type, value, result.verdict,
        result.from_cache ? 1 : 0,
      ).run().catch(() => {});
    }

    return json({
      success: true,
      data:    result,
      quota:   { remaining: usage.remaining, limit: usage.limit },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleIOCEnrichBatch(request, env, authCtx) {
  const tier = authCtx?.tier || 'FREE';
  if (tier === 'FREE') {
    return json({
      success: false,
      error:   'Batch IOC enrichment requires PRO or ENTERPRISE plan',
      upgrade: 'https://tools.cyberdudebivash.com/#pricing',
    }, 403);
  }

  const body = await request.json().catch(() => ({}));
  const iocs = body.iocs;
  if (!Array.isArray(iocs) || !iocs.length) {
    return json({ success: false, error: 'Missing iocs array in body' }, 400);
  }
  if (iocs.length > 20) {
    return json({ success: false, error: 'Max 20 IOCs per batch (ENTERPRISE: 50)' }, 400);
  }

  try {
    const results = await enrichIOCBatch(env, iocs);
    return json({ success: true, data: results, count: results.length });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── ─── ─── ATTACK SURFACE MANAGEMENT ─── ─── ────────────────────────────────

export async function handleASMAddTarget(request, env, authCtx, ctx) {
  const tier = authCtx?.tier || 'FREE';
  if (tier === 'FREE') {
    return json({
      success: false,
      error:   'Attack Surface Management requires PRO or ENTERPRISE plan',
      upgrade: 'https://tools.cyberdudebivash.com/#pricing',
      features: ['External subdomain discovery', 'Certificate monitoring', 'Service exposure alerts', 'Continuous scan every 24h'],
    }, 403);
  }

  const body = await request.json().catch(() => ({}));
  const domain = body.domain?.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(domain)) {
    return json({ success: false, error: 'Invalid domain format' }, 400);
  }

  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  const targetId = `asm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const userId   = authCtx?.user_id || authCtx?.ip || 'anon';

  try {
    await env.DB.prepare(`
      INSERT INTO asm_targets (id, user_id, domain, org_name, scan_status)
      VALUES (?, ?, ?, ?, 'pending')
    `).bind(targetId, userId, domain, body.org_name || domain).run();

    // Trigger background scan via ctx.waitUntil so it survives the HTTP response
    const scanPromise = runASMScan(env, targetId, domain).catch(e =>
      console.error('[ASM] Background scan error:', e.message)
    );
    if (ctx?.waitUntil) ctx.waitUntil(scanPromise);

    return json({
      success: true,
      data: {
        target_id:  targetId,
        domain,
        status:     'scanning',
        message:    'ASM scan started. Results available in ~60 seconds.',
        report_url: `/api/asm/targets/${targetId}/report`,
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleASMListTargets(request, env, authCtx) {
  const userId = authCtx?.user_id || authCtx?.ip || 'anon';
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    const rows = await env.DB.prepare(`
      SELECT id, domain, org_name, scan_status, asm_score, risk_grade,
             total_assets, last_scan, next_scan, created_at
      FROM asm_targets WHERE user_id = ? ORDER BY created_at DESC LIMIT 20
    `).bind(userId).all();

    return json({ success: true, data: rows.results || [] });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleASMGetReport(request, env, authCtx, targetId) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    const report = await getASMReport(env, targetId);
    if (!report) return json({ success: false, error: 'Target not found' }, 404);

    return json({ success: true, data: report });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleASMTriggerScan(request, env, authCtx, targetId, ctx) {
  const tier = authCtx?.tier || 'FREE';
  if (tier === 'FREE') {
    return json({ success: false, error: 'ASM requires PRO or ENTERPRISE plan' }, 403);
  }
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    const target = await env.DB.prepare('SELECT * FROM asm_targets WHERE id = ?').bind(targetId).first();
    if (!target) return json({ success: false, error: 'Target not found' }, 404);

    // Mark as scanning
    await env.DB.prepare(`UPDATE asm_targets SET scan_status = 'scanning', updated_at = datetime('now') WHERE id = ?`).bind(targetId).run();

    // Trigger background scan via ctx.waitUntil
    const scanP = runASMScan(env, targetId, target.domain).catch(e =>
      console.error('[ASM] Scan error:', e.message)
    );
    if (ctx?.waitUntil) ctx.waitUntil(scanP);

    return json({
      success: true,
      data: { target_id: targetId, domain: target.domain, status: 'scanning' },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── ─── ─── BRAND PROTECTION ─── ─── ────────────────────────────────────────

export async function handleBrandAddMonitor(request, env, authCtx, ctx) {
  const tier = authCtx?.tier || 'FREE';
  if (tier === 'FREE') {
    return json({
      success: false,
      error:   'Brand Protection requires PRO or ENTERPRISE plan',
      upgrade: 'https://tools.cyberdudebivash.com/#pricing',
      features: ['Typosquatting detection', 'Domain impersonation alerts', 'Phishing domain monitoring', 'MX-enabled fake domain alerts'],
    }, 403);
  }

  const body = await request.json().catch(() => ({}));
  const domain = body.primary_domain?.trim().toLowerCase();
  const brand  = body.brand_name?.trim();

  if (!domain || !brand) {
    return json({ success: false, error: 'Missing brand_name or primary_domain' }, 400);
  }

  const monitorId = `bm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const userId    = authCtx?.user_id || authCtx?.ip || 'anon';

  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    await env.DB.prepare(`
      INSERT INTO brand_monitors (id, user_id, brand_name, primary_domain, keywords)
      VALUES (?, ?, ?, ?, ?)
    `).bind(monitorId, userId, brand, domain, JSON.stringify(body.keywords || [])).run();

    // Trigger background scan via ctx.waitUntil
    const brandScanP = runBrandScan(env, monitorId, brand, domain).catch(e =>
      console.error('[Brand] Scan error:', e.message)
    );
    if (ctx?.waitUntil) ctx.waitUntil(brandScanP);

    return json({
      success: true,
      data: {
        monitor_id:  monitorId,
        brand,
        domain,
        status:      'scanning',
        message:     'Brand scan started. Results available in ~90 seconds.',
        threats_url: `/api/brand/monitors/${monitorId}/threats`,
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleBrandListMonitors(request, env, authCtx) {
  const userId = authCtx?.user_id || authCtx?.ip || 'anon';
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    const rows = await env.DB.prepare(`
      SELECT id, brand_name, primary_domain, scan_status, total_threats,
             critical_threats, last_scan, created_at
      FROM brand_monitors WHERE user_id = ? ORDER BY created_at DESC LIMIT 20
    `).bind(userId).all();

    return json({ success: true, data: rows.results || [] });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleBrandGetThreats(request, env, authCtx, monitorId) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  const url      = new URL(request.url);
  const minScore = parseInt(url.searchParams.get('min_score') || '0', 10);
  const category = url.searchParams.get('category');

  try {
    let sql = 'SELECT * FROM brand_threats WHERE monitor_id = ?';
    const bindings = [monitorId];
    if (minScore > 0) { sql += ' AND risk_score >= ?'; bindings.push(minScore); }
    if (category)     { sql += ' AND category = ?';    bindings.push(category); }
    sql += ' ORDER BY risk_score DESC LIMIT 100';

    const [monitor, threats] = await Promise.all([
      env.DB.prepare('SELECT * FROM brand_monitors WHERE id = ?').bind(monitorId).first(),
      env.DB.prepare(sql).bind(...bindings).all(),
    ]);

    if (!monitor) return json({ success: false, error: 'Monitor not found' }, 404);

    return json({
      success: true,
      data: {
        monitor: {
          id: monitor.id, brand: monitor.brand_name, domain: monitor.primary_domain,
          last_scan: monitor.last_scan, total_threats: monitor.total_threats,
        },
        threats: threats.results || [],
        summary: {
          total:          (threats.results || []).length,
          critical:       (threats.results || []).filter(t => t.risk_score >= 70).length,
          active_phishing: (threats.results || []).filter(t => t.category === 'active_phishing').length,
          parked:         (threats.results || []).filter(t => t.category === 'parked').length,
        },
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleBrandTriggerScan(request, env, authCtx, monitorId, ctx) {
  if (!env.DB) return json({ success: false, error: 'Database unavailable' }, 503);

  try {
    const monitor = await env.DB.prepare('SELECT * FROM brand_monitors WHERE id = ?').bind(monitorId).first();
    if (!monitor) return json({ success: false, error: 'Monitor not found' }, 404);

    const brandP = runBrandScan(env, monitorId, monitor.brand_name, monitor.primary_domain).catch(e =>
      console.error('[Brand] Scan error:', e.message)
    );
    if (ctx?.waitUntil) ctx.waitUntil(brandP);

    return json({
      success: true,
      data: { monitor_id: monitorId, status: 'scanning', message: 'Brand scan triggered' },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── ─── ─── THREAT ACTOR PROFILING ─── ─── ──────────────────────────────────

export async function handleListThreatActors(request, env, authCtx) {
  const url   = new URL(request.url);
  const opts  = {
    country:    url.searchParams.get('country'),
    motivation: url.searchParams.get('motivation'),
    sector:     url.searchParams.get('sector'),
    limit:      parseInt(url.searchParams.get('limit') || '20', 10),
  };

  try {
    const actors = await listThreatActors(env, opts);
    return json({
      success: true,
      data:    actors,
      count:   actors.length,
      filters: opts,
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleGetThreatActor(request, env, authCtx, actorId) {
  try {
    const actor = await getThreatActor(env, actorId);
    if (!actor) return json({ success: false, error: 'Threat actor not found' }, 404);
    return json({ success: true, data: actor });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleSearchThreatActors(request, env, authCtx) {
  const url = new URL(request.url);
  const q   = url.searchParams.get('q')?.trim();
  if (!q || q.length < 2) {
    return json({ success: false, error: 'Query must be at least 2 characters' }, 400);
  }

  try {
    const results = await searchThreatActors(env, q);
    return json({ success: true, data: results, count: results.length, query: q });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleAttributeIOC(request, env, authCtx) {
  const body  = await request.json().catch(() => ({}));
  const value = body.value?.trim();
  const type  = body.type || 'unknown';
  if (!value) return json({ success: false, error: 'Missing value' }, 400);

  try {
    const matches = attributeIOC(value, type);
    return json({
      success: true,
      data: {
        value, type,
        attributed_to: matches,
        confidence:    matches.length > 0 ? 'HIGH' : 'NOT ATTRIBUTED',
        message:       matches.length > 0
          ? `IOC attributed to ${matches.length} known threat actor(s)`
          : 'IOC not found in known threat actor IOC databases',
      },
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

export async function handleSeedThreatActors(request, env, authCtx) {
  const apiKey  = request.headers.get('x-api-key') || '';
  const isAdmin = (env.ADMIN_KEY && apiKey === env.ADMIN_KEY);
  if (!isAdmin) return json({ success: false, error: 'Admin access required' }, 403);

  try {
    const result = await seedThreatActors(env);
    return json({ success: true, data: result, message: `Seeded ${result.seeded} threat actors into D1` });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// ─── CRQ: Cyber Risk Quantification ──────────────────────────────────────────
export async function handleCRQAssessment(request, env, authCtx) {
  const body = await request.json().catch(() => ({}));
  const {
    org_name,
    industry        = 'General',
    employee_count  = 500,
    revenue_usd     = 10_000_000,
    current_controls = [],
  } = body;

  if (!org_name) return json({ success: false, error: 'Missing org_name' }, 400);

  // Industry risk multipliers (based on Ponemon/IBM Cost of Data Breach 2025)
  const INDUSTRY_RISK = {
    Healthcare:       { multiplier: 2.1, avg_breach_cost: 10_930_000 },
    Finance:          { multiplier: 1.9, avg_breach_cost: 6_080_000 },
    Technology:       { multiplier: 1.6, avg_breach_cost: 5_970_000 },
    Energy:           { multiplier: 1.8, avg_breach_cost: 5_290_000 },
    Retail:           { multiplier: 1.3, avg_breach_cost: 3_280_000 },
    Manufacturing:    { multiplier: 1.4, avg_breach_cost: 4_470_000 },
    Government:       { multiplier: 1.5, avg_breach_cost: 2_070_000 },
    Education:        { multiplier: 1.2, avg_breach_cost: 3_850_000 },
    General:          { multiplier: 1.4, avg_breach_cost: 4_880_000 },
  };

  const riskProfile = INDUSTRY_RISK[industry] || INDUSTRY_RISK.General;

  // Threat scenarios with Annual Probability of Occurrence (APO)
  const THREAT_SCENARIOS = [
    { name: 'Ransomware Attack',        apo: 0.27, impact_pct: 0.08 },
    { name: 'Data Breach (External)',   apo: 0.32, impact_pct: 0.05 },
    { name: 'Business Email Compromise', apo: 0.35, impact_pct: 0.02 },
    { name: 'Supply Chain Compromise',  apo: 0.15, impact_pct: 0.04 },
    { name: 'Insider Threat',           apo: 0.20, impact_pct: 0.03 },
    { name: 'DDoS / Service Disruption', apo: 0.40, impact_pct: 0.01 },
    { name: 'Cloud Misconfiguration Breach', apo: 0.25, impact_pct: 0.03 },
  ];

  // Control effectiveness reductions
  const CONTROL_REDUCTIONS = {
    mfa:            0.60,
    edr:            0.40,
    backup:         0.50,
    soc:            0.35,
    email_security: 0.45,
    patching:       0.30,
    training:       0.25,
    zero_trust:     0.55,
  };

  const controlReduction = current_controls.reduce((sum, c) =>
    sum + (CONTROL_REDUCTIONS[c] || 0), 0
  );
  const effectiveReduction = Math.min(controlReduction, 0.80); // max 80% reduction

  // Calculate ALE (Annualized Loss Expectancy) per scenario
  const scenarios = THREAT_SCENARIOS.map(s => {
    const sle      = revenue_usd * s.impact_pct * riskProfile.multiplier;
    const ale      = sle * s.apo * (1 - effectiveReduction);
    return {
      scenario:    s.name,
      probability: `${Math.round(s.apo * 100)}%`,
      sle_usd:     Math.round(sle),
      ale_usd:     Math.round(ale),
    };
  });

  const totalALE         = scenarios.reduce((sum, s) => sum + s.ale_usd, 0);
  const avgBreachCost    = riskProfile.avg_breach_cost * (1 - effectiveReduction);
  const insuranceGap     = Math.max(0, avgBreachCost - (body.current_insurance_usd || 0));
  const controlInvestment = Math.round(totalALE * 0.15);  // 15% of ALE = efficient control spend
  const roiControls      = totalALE > 0 ? ((totalALE * 0.4 - controlInvestment) / controlInvestment * 100) : 0;

  const riskBand =
    totalALE >= 5_000_000 ? 'CRITICAL' :
    totalALE >= 1_000_000 ? 'HIGH' :
    totalALE >= 250_000   ? 'MEDIUM' : 'LOW';

  const assessmentId = `crq_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  // Store in D1
  if (env.DB) {
    env.DB.prepare(`
      INSERT INTO crq_assessments
        (id, user_id, org_name, industry, employee_count, revenue_usd,
         annualized_loss_exp, single_loss_exp, threat_scenarios, top_risk,
         risk_band, insurance_gap_usd, control_investment, roi_security_controls)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      assessmentId,
      authCtx?.user_id || null,
      org_name, industry, employee_count, revenue_usd,
      totalALE, avgBreachCost,
      JSON.stringify(scenarios),
      scenarios.sort((a, b) => b.ale_usd - a.ale_usd)[0]?.scenario || '',
      riskBand, insuranceGap, controlInvestment, roiControls,
    ).run().catch(() => {});
  }

  return json({
    success: true,
    data: {
      assessment_id:          assessmentId,
      org_name, industry,
      risk_band:                      riskBand,
      annualized_loss_expectancy_usd: totalALE,
      avg_breach_cost_usd:    Math.round(avgBreachCost),
      insurance_gap_usd:      Math.round(insuranceGap),
      recommended_security_investment_usd: controlInvestment,
      roi_of_security_controls_pct: Math.round(roiControls),
      threat_scenarios:       scenarios.sort((a, b) => b.ale_usd - a.ale_usd),
      executive_summary: `${org_name} faces an estimated annualized cyber loss of $${(totalALE / 1000).toFixed(0)}K in the ${industry} sector. Primary risks are ${scenarios[0]?.scenario} and ${scenarios[1]?.scenario}. Recommended minimum security investment: $${(controlInvestment / 1000).toFixed(0)}K/year with projected 30-40% risk reduction.`,
      controls_assessed:      current_controls,
      effective_risk_reduction: `${Math.round(effectiveReduction * 100)}%`,
    },
  });
}
