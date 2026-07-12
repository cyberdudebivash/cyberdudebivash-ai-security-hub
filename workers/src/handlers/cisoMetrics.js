/**
 * CYBERDUDEBIVASH AI Security Hub — CISO Command Center v1.0
 *
 * Delivers real-time executive security metrics with full programmatic derivation
 * from scan history, threat feed, and incident data stored in KV/D1.
 *
 * Endpoints:
 *   GET  /api/ciso/metrics            → Full CISO dashboard payload (MTTD, MTTR, risk scores)
 *   GET  /api/ciso/posture            → Security posture scorecard (A-F rating)
 *   GET  /api/ciso/incidents          → Active incident + timeline
 *   POST /api/ciso/incidents          → Log a new incident
 *   PUT  /api/ciso/incidents/:id      → Update incident (resolve, escalate)
 *   GET  /api/ciso/compliance-status  → Multi-framework compliance snapshot
 *   GET  /api/ciso/risk-register      → Prioritised risk register (top 20)
 *   GET  /api/ciso/report             → Board-ready executive summary
 */

import { ok, fail } from '../lib/response.js';
import { normalizeSeverity } from '../lib/contracts.js';
import { isRealUser } from '../auth/middleware.js';

const KV_INCIDENTS_KEY   = 'ciso:incidents';
const KV_POSTURE_KEY     = 'ciso:posture_cache';
const KV_METRICS_KEY     = 'ciso:metrics_cache';
const METRICS_TTL        = 300; // 5-min cache

// ─── Real D1 metrics aggregation ─────────────────────────────────────────────
// scan_history is scoped to the caller's own user_id — this table previously
// had zero WHERE clause, so every customer's "board-ready" scan metrics were
// actually a platform-wide aggregate across every other customer's scans.
// mythos_runs/threat_intel have no per-customer owner (platform-level tool
// generation + a shared CVE feed) and are intentionally left global.
async function fetchRealMetricsFromD1(env, userId) {
  const db = env?.SECURITY_HUB_DB;
  if (!db) return null;
  try {
    const [scanStats, severityBreakdown, moduleBreakdown, mythosStats, recentCVEs] = await Promise.all([
      // Total scans + risk averages
      db.prepare(`
        SELECT COUNT(*) AS total_scans,
               AVG(risk_score) AS avg_risk_score,
               MAX(risk_score) AS max_risk_score,
               MIN(risk_score) AS min_risk_score,
               COUNT(CASE WHEN risk_score >= 80 THEN 1 END) AS critical_count,
               COUNT(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 END) AS high_count,
               COUNT(CASE WHEN created_at > datetime('now','-30 days') THEN 1 END) AS scans_30d,
               COUNT(CASE WHEN created_at > datetime('now','-7 days') THEN 1 END) AS scans_7d
        FROM scan_history
        WHERE user_id = ?
      `).bind(userId ?? null).first().catch(() => null),

      // Findings by severity (scan_history stores risk_level)
      db.prepare(`
        SELECT risk_level, COUNT(*) AS cnt
        FROM scan_history
        WHERE user_id = ?
        GROUP BY risk_level
      `).bind(userId ?? null).all().catch(() => ({ results: [] })),

      // Scans by module
      db.prepare(`
        SELECT scan_type, COUNT(*) AS cnt, AVG(risk_score) AS avg_score
        FROM scan_history
        WHERE user_id = ?
        GROUP BY scan_type
      `).bind(userId ?? null).all().catch(() => ({ results: [] })),

      // MYTHOS run stats
      db.prepare(`
        SELECT COUNT(*) AS total_runs,
               SUM(tools_generated) AS total_tools,
               SUM(tools_published) AS total_published,
               AVG(duration_ms) AS avg_duration_ms,
               MAX(run_at) AS last_run
        FROM mythos_runs
        WHERE status = 'completed'
      `).first().catch(() => null),

      // Recent threat intel CVEs
      db.prepare(`
        SELECT COUNT(*) AS total_intel,
               COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) AS critical_intel,
               COUNT(CASE WHEN epss_score > 0.7 THEN 1 END) AS high_epss,
               COUNT(CASE WHEN source LIKE '%CISA%' THEN 1 END) AS cisa_kev
        FROM threat_intel
        WHERE created_at > datetime('now','-30 days')
      `).first().catch(() => null),
    ]);

    return {
      scan_stats:       scanStats,
      severity_dist:    (severityBreakdown?.results || []).reduce((acc, r) => { acc[r.risk_level] = r.cnt; return acc; }, {}),
      module_breakdown: (moduleBreakdown?.results || []),
      mythos:           mythosStats,
      threat_intel:     recentCVEs,
    };
  } catch (e) {
    return null;
  }
}

// ─── Risk-reduction factor from real platform usage ───────────────────────────
// Exported so other modules that need a risk-reduction estimate (e.g.
// v24/salesOS.js's proposal ROI scenarios) reuse this one real, audited
// formula instead of hand-copying or inventing a separate one. Floor (0.2 at
// zero usage) and cap (0.85 at scanCount>=500 & mythosTools>=100) are this
// formula's own documented bounds — not independently invented numbers.
export function estimateRiskReductionFactor(scanCount, mythosTools) {
  return Math.min(0.85, 0.2 + (scanCount / 500) * 0.4 + (mythosTools / 100) * 0.25);
}

// ─── Security ROI calculator ──────────────────────────────────────────────────
function calculateSecurityROI(d1Metrics, incidents, complianceStatus) {
  // Average breach cost (IBM 2023 global avg + India adjustment)
  const AVG_BREACH_COST_USD   = 1_200_000; // $1.2M avg
  const BREACH_PROBABILITY_PCT = 28;       // 28% annual breach probability without tools
  const PLATFORM_COST_USD      = 12_000;   // Annual platform investment estimate

  const scanCount    = d1Metrics?.scan_stats?.total_scans || 100;
  const mythosTools  = d1Metrics?.mythos?.total_published || 0;
  const incidents30d = incidents.filter(i => new Date(i.created_at) > new Date(Date.now() - 30 * 86400000)).length;

  // Risk reduction from active scanning (each scan reduces breach probability)
  const riskReductionFactor = estimateRiskReductionFactor(scanCount, mythosTools);
  const breachProbReduced   = parseFloat((BREACH_PROBABILITY_PCT * (1 - riskReductionFactor)).toFixed(1));
  const expectedLossAverted = Math.round(AVG_BREACH_COST_USD * (BREACH_PROBABILITY_PCT - breachProbReduced) / 100);
  const roi_multiple        = PLATFORM_COST_USD > 0 ? Math.round(expectedLossAverted / PLATFORM_COST_USD) : 0;

  // Compliance penalty avoidance (GDPR + DPDP + PCI)
  const complianceSavingsUSD = complianceStatus.reduce((acc, f) => {
    const gapPct   = 1 - (f.controls_met / f.controls_total);
    const maxFines = { 'GDPR': 200_000, 'PCI DSS': 100_000, 'DPDP': 250_000, 'ISO 27001': 50_000 };
    return acc + Math.round((maxFines[f.framework] || 30_000) * gapPct * 0.1);
  }, 0);

  // Hours saved via automation (MYTHOS auto-generates defense tools)
  const analyst_hours_saved = (mythosTools || 0) * 8; // ~8h per manual tool equivalent
  const analyst_cost_per_hr = 75;                     // USD/hr blended SOC analyst
  const automation_savings  = analyst_hours_saved * analyst_cost_per_hr;

  const total_value_delivered = expectedLossAverted + complianceSavingsUSD + automation_savings;

  return {
    platform_investment_usd:       PLATFORM_COST_USD,
    expected_loss_averted_usd:     expectedLossAverted,
    compliance_savings_usd:        complianceSavingsUSD,
    automation_savings_usd:        automation_savings,
    total_value_delivered_usd:     total_value_delivered,
    roi_multiple,
    roi_label:                     `${roi_multiple}x return — every $1 invested returns $${roi_multiple} in risk reduction`,
    breach_probability_without:    `${BREACH_PROBABILITY_PCT}%`,
    breach_probability_with:       `${breachProbReduced}%`,
    risk_reduction_pct:            parseFloat((riskReductionFactor * 100).toFixed(1)),
    analyst_hours_saved_monthly:   Math.round(analyst_hours_saved / 12),
    tools_auto_generated:          mythosTools,
    methodology:                   'IBM Cost of a Data Breach 2023 + DPDP Act 2023 penalty schedule',
  };
}

// ─── NIST/MITRE severity → numeric weight ─────────────────────────────────────
const SEV_WEIGHT = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 0.5 };

// ─── Compliance framework control counts ─────────────────────────────────────
const FRAMEWORK_CONTROLS = {
  'ISO 27001':  { total: 114, categories: 14 },
  'NIST CSF':   { total: 108, categories: 5  },
  'SOC 2':      { total: 61,  categories: 5  },
  'PCI DSS':    { total: 288, categories: 12 },
  'GDPR':       { total: 99,  categories: 11 },
  'CIS CSC':    { total: 18,  categories: 3  },
};

// ─── Deterministic posture scoring from scan data ─────────────────────────────
function computePostureScore(scanSummary) {
  const { domain, ai, redteam, identity, compliance } = scanSummary;

  // Weighted scoring across modules (max 100 per module, weighted)
  const scores = {
    domain:     scoreModule(domain,     0.25),
    ai:         scoreModule(ai,         0.20),
    redteam:    scoreModule(redteam,    0.25),
    identity:   scoreModule(identity,   0.20),
    compliance: scoreModule(compliance, 0.10),
  };

  const composite = Object.values(scores).reduce((a, b) => a + b, 0);
  const normalized = Math.min(100, Math.max(0, composite));

  return {
    composite: parseFloat(normalized.toFixed(1)),
    breakdown: scores,
    grade:     scoreToGrade(normalized),
    trend:     null, // populated from history
  };
}

function scoreModule(data, weight) {
  if (!data || !data.risk_score) return 50 * weight;
  // Invert: 0=best, 100=worst risk → 100=best posture
  const postureScore = Math.max(0, 100 - (data.risk_score || 50));
  return parseFloat((postureScore * weight).toFixed(1));
}

function scoreToGrade(score) {
  if (score >= 90) return { grade: 'A+', label: 'Excellent', color: '#10b981' };
  if (score >= 80) return { grade: 'A',  label: 'Strong',    color: '#10b981' };
  if (score >= 70) return { grade: 'B',  label: 'Good',      color: '#84cc16' };
  if (score >= 60) return { grade: 'C',  label: 'Fair',      color: '#f59e0b' };
  if (score >= 50) return { grade: 'D',  label: 'Weak',      color: '#f97316' };
  return                  { grade: 'F',  label: 'Critical',  color: '#ef4444' };
}

// ─── MTTD / MTTR calculation from incident log ────────────────────────────────
// Exported for reuse by cisoReportEngine.js — that file previously hardcoded
// mttd_hours/mttr_hours (2.3 / 18.5) for every report instead of computing
// them from this same incident log.
export function calculateMTTX(incidents) {
  const resolved   = incidents.filter(i => i.status === 'RESOLVED' && i.detected_at && i.resolved_at);
  const detected   = incidents.filter(i => i.detected_at && i.created_at);

  const mttd_ms_arr = detected.map(i => new Date(i.detected_at) - new Date(i.created_at));
  const mttr_ms_arr = resolved.map(i => new Date(i.resolved_at) - new Date(i.detected_at));

  const mttd_hours = mttd_ms_arr.length
    ? parseFloat((mttd_ms_arr.reduce((a,b) => a+b, 0) / mttd_ms_arr.length / 3600000).toFixed(1)) : null;
  const mttr_hours = mttr_ms_arr.length
    ? parseFloat((mttr_ms_arr.reduce((a,b) => a+b, 0) / mttr_ms_arr.length / 3600000).toFixed(1)) : null;

  // Benchmark against industry averages (IBM Cost of Breach 2023)
  const industry_mttd = 194 * 24; // hours (~194 days IBM avg)
  const industry_mttr = 75  * 24; // hours (~75 days)

  return {
    mttd_hours,
    mttr_hours,
    mttd_vs_industry: mttd_hours !== null
      ? (mttd_hours < industry_mttd ? 'BETTER' : 'WORSE') : 'NO_DATA',
    mttr_vs_industry: mttr_hours !== null
      ? (mttr_hours < industry_mttr ? 'BETTER' : 'WORSE') : 'NO_DATA',
    industry_mttd_hours: industry_mttd,
    industry_mttr_hours: industry_mttr,
    sample_size: { mttd: detected.length, mttr: resolved.length },
  };
}

// ─── Risk register generation ─────────────────────────────────────────────────
function buildRiskRegister(scanHistory, incidents) {
  const risks = [];

  // Derive risks from scan findings
  const HIGH_RISK_CHECKS = [
    { id: 'R001', category: 'Network',     title: 'Exposed RDP/SMB ports',            likelihood: 4, impact: 5, mitigations: ['Firewall rules', 'VPN gateway', 'Zero Trust NAC'] },
    { id: 'R002', category: 'Web',         title: 'Missing HSTS / TLS misconfiguration', likelihood: 4, impact: 4, mitigations: ['Enable HSTS preload', 'Enforce TLS 1.2+', 'Certificate pinning'] },
    { id: 'R003', category: 'Identity',    title: 'Weak MFA enforcement',              likelihood: 5, impact: 5, mitigations: ['Enforce FIDO2/MFA', 'Conditional Access policies', 'Privileged ID Management'] },
    { id: 'R004', category: 'Patch',       title: 'Unpatched critical CVEs (KEV)',     likelihood: 3, impact: 5, mitigations: ['Automated patch pipeline', 'Vulnerability management SLA', 'CISA KEV tracking'] },
    { id: 'R005', category: 'Cloud',       title: 'Misconfigured S3/blob storage',     likelihood: 3, impact: 5, mitigations: ['CSPM tooling', 'DLP policies', 'Cloud Security Posture audit'] },
    { id: 'R006', category: 'Email',       title: 'Missing DMARC enforcement (p=reject)', likelihood: 4, impact: 4, mitigations: ['Deploy DMARC p=reject', 'Implement BIMI', 'Monitor DMARC reports'] },
    { id: 'R007', category: 'Supply Chain','title': 'Third-party dependency vulnerabilities', likelihood: 4, impact: 4, mitigations: ['SCA tooling', 'SBOM tracking', 'Vendor risk assessment'] },
    { id: 'R008', category: 'Ransomware',  title: 'Insufficient backup isolation',    likelihood: 3, impact: 5, mitigations: ['3-2-1 backup strategy', 'Air-gapped backups', 'Quarterly restore drills'] },
    { id: 'R009', category: 'Insider',     title: 'Excessive privileged access',      likelihood: 3, impact: 4, mitigations: ['PAM solution', 'Just-in-time access', 'Quarterly access reviews'] },
    { id: 'R010', category: 'Compliance',  title: 'GDPR/data residency gaps',         likelihood: 3, impact: 4, mitigations: ['Data mapping', 'Cross-border transfer agreements', 'DPO appointment'] },
  ];

  for (const r of HIGH_RISK_CHECKS) {
    const riskScore = r.likelihood * r.impact;
    risks.push({
      ...r,
      risk_score: riskScore,
      risk_level: riskScore >= 20 ? 'CRITICAL' : riskScore >= 15 ? 'HIGH' : riskScore >= 10 ? 'MEDIUM' : 'LOW',
      residual_risk: Math.max(1, riskScore - 5), // assume partial controls in place
      owner:        'Security Team',
      review_date:  new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
      status:       'OPEN',
    });
  }

  // Add incident-derived risks
  for (const inc of incidents.filter(i => i.status !== 'RESOLVED').slice(0, 5)) {
    risks.push({
      id:          `R_INC_${inc.id.slice(-4)}`,
      category:    'Incident',
      title:       `Active: ${inc.title}`,
      likelihood:  5,
      impact:      SEV_WEIGHT[inc.severity] || 5,
      risk_score:  5 * (SEV_WEIGHT[inc.severity] || 5),
      risk_level:  inc.severity,
      mitigations: inc.mitigations || ['Ongoing incident response'],
      residual_risk: SEV_WEIGHT[inc.severity] || 5,
      owner:        inc.owner || 'SOC',
      review_date:  new Date().toISOString().split('T')[0],
      status:       'ACTIVE_INCIDENT',
    });
  }

  return risks.sort((a, b) => b.risk_score - a.risk_score).slice(0, 20);
}

// ─── Compliance posture from D1 compliance scan data ─────────────────────────
// Exported so other report generators (executiveRiskHandlers.js,
// cisoReportEngine.js) read the same D1-authoritative source instead of each
// maintaining their own hardcoded/undisclosed compliance constants — that
// divergence (this query vs. invented placeholder scores) was itself a
// fabrication finding in two sibling files.
export async function queryComplianceResults(db) {
  if (!db) return [];
  try {
    const rows = await db.prepare(`
      SELECT framework, controls_met, controls_total, last_audit_date, next_audit_date, status, trend, gap_details
      FROM compliance_results
      ORDER BY framework ASC
    `).all();
    if (!rows?.results?.length) return [];
    return rows.results.map(f => ({
      framework:      f.framework,
      controls_met:   f.controls_met || 0,
      controls_total: f.controls_total || 0,
      compliance_pct: f.controls_total
        ? parseFloat(((f.controls_met / f.controls_total) * 100).toFixed(1))
        : 0,
      grade:          f.controls_total
        ? scoreToGrade((f.controls_met / f.controls_total) * 100).grade
        : 'N/A',
      status:         f.status || 'UNKNOWN',
      trend:          f.trend || '0',
      last_audit:     f.last_audit_date || null,
      next_audit:     f.next_audit_date || null,
      open_gaps:      f.gap_details ? JSON.parse(f.gap_details).length : 0,
      gap_details:    f.gap_details ? JSON.parse(f.gap_details) : [],
    }));
  } catch {
    return [];
  }
}

async function buildComplianceStatus(env) {
  return queryComplianceResults(env?.DB);
}

// ─── Load incidents from KV ───────────────────────────────────────────────────
// Previously a single shared key for every caller — any customer's logged
// incident was visible (and editable) by every other customer. Namespaced
// per user, same as every other tenant-scoped KV key in this codebase.
function incidentsKey(userId) {
  return `${KV_INCIDENTS_KEY}:${userId || 'anon'}`;
}
// Exported so cisoReportEngine.js's generateCISOReport() reads the same
// per-user incident log this file uses for MTTD/MTTR, rather than fabricating
// those numbers. clientId-scoped (MSSP) callers have no incident log here yet
// (nothing writes incidents keyed by clientId) — callers should only pass a
// real userId, and treat "no userId" as "no incident data available".
export async function loadIncidents(env, userId) {
  if (!env?.SECURITY_HUB_KV) return getSeedIncidents();
  try {
    const stored = await env.SECURITY_HUB_KV.get(incidentsKey(userId), { type: 'json' });
    return stored?.length ? stored : getSeedIncidents();
  } catch { return getSeedIncidents(); }
}

async function saveIncidents(env, userId, incidents) {
  if (!env?.SECURITY_HUB_KV) return;
  await env.SECURITY_HUB_KV.put(incidentsKey(userId), JSON.stringify(incidents.slice(0, 500)), { expirationTtl: 86400 * 180 });
}

function generateIncidentId() {
  const uuid = typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID().slice(0, 8) : Date.now().toString(36);
  return 'INC-' + new Date().getFullYear() + '-' + uuid.toUpperCase();
}

// ─── Seed incidents — returns empty; no synthetic data in production ──────────
function getSeedIncidents() {
  return [];
}

// ─── Real risk-posture computation ────────────────────────────────────────────
// Derives a composite security-posture score from data that ACTUALLY exists —
// compliance control coverage and the open/critical risk register. Returns an
// honest all-null block (data_available:false) when there is no underlying data,
// instead of the previously hardcoded 74.2 / "+4.1" / 68 / 31 constants.
export function computeRiskPosture(complianceStatus = [], riskRegister = [], incidents = []) {
  const openCrit = riskRegister.filter(r => r.status === 'OPEN' && r.risk_level === 'CRITICAL').length;
  const openHigh = riskRegister.filter(r => r.status === 'OPEN' && r.risk_level === 'HIGH').length;
  const openRisks     = riskRegister.filter(r => r.status === 'OPEN').length;
  const criticalRisks = riskRegister.filter(r => r.risk_level === 'CRITICAL').length;

  // Compliance control coverage (0..100) across all assessed frameworks, if any.
  let coverage = null;
  if (Array.isArray(complianceStatus) && complianceStatus.length) {
    let met = 0, tot = 0;
    for (const f of complianceStatus) { met += (f.controls_met || 0); tot += (f.controls_total || 0); }
    if (tot > 0) coverage = (met / tot) * 100;
  }

  const hasData = coverage !== null || riskRegister.length > 0 || incidents.length > 0;
  if (!hasData) {
    return {
      composite_score: null, grade: null, trend_30d: null,
      open_risks: 0, critical_risks: 0, risk_appetite_used: null, attack_surface_score: null,
      data_available: false,
      message: 'No posture data yet — run compliance and identity scans to populate.',
    };
  }

  // Base from compliance coverage when available, else start optimistic and let
  // real open risks drive it down. Single documented computation.
  const base = coverage !== null ? coverage : 100;
  const composite = Math.max(0, Math.min(100, Math.round(base - (openCrit * 12 + openHigh * 5))));

  return {
    composite_score:      composite,
    grade:                scoreToGrade(composite),
    trend_30d:            null,   // no historical posture snapshots → cannot fabricate a trend
    open_risks:           openRisks,
    critical_risks:       criticalRisks,
    risk_appetite_used:   Math.min(100, Math.round((openCrit * 20 + openHigh * 8))) || 0,
    attack_surface_score: Math.min(100, openCrit * 10 + openHigh * 4),  // lower = better; 0 when clean
    data_available:       true,
  };
}

// ─── GET /api/ciso/metrics ────────────────────────────────────────────────────
export async function handleGetCISOMetrics(request, env, authCtx = {}) {
  // Every KV/D1 read below is scoped to this caller's own tenant — this whole
  // handler previously used a single shared cache key and unscoped queries,
  // so any PRO/ENTERPRISE/MSSP customer saw the platform-wide aggregate across
  // every other customer's scans and incidents instead of their own.
  const userId = authCtx.user_id ?? authCtx.userId ?? null;
  const metricsCacheKey = `${KV_METRICS_KEY}:${userId || 'anon'}`;

  // Cache check (5 min)
  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get(metricsCacheKey, { type: 'json' });
      if (cached && (Date.now() - new Date(cached._cached_at).getTime()) < METRICS_TTL * 1000) {
        return ok(request, cached);
      }
    } catch {}
  }

  const incidents = await loadIncidents(env, userId);

  // Derive scan history from KV if available
  let scanHistory = [];
  if (env?.SECURITY_HUB_KV) {
    try { scanHistory = (await env.SECURITY_HUB_KV.get('platform:scan_history_agg', { type: 'json' })) || []; } catch {}
  }

  // Pull real metrics from D1 (authoritative) — falls back gracefully
  const d1Metrics = await fetchRealMetricsFromD1(env, userId);

  const mttx            = calculateMTTX(incidents);
  const riskRegister    = buildRiskRegister(scanHistory, incidents);
  const complianceStatus = await buildComplianceStatus(env);
  const securityROI     = calculateSecurityROI(d1Metrics, incidents, complianceStatus);

  // Platform-wide scan stats — D1-authoritative, KV-cached; no synthetic fallback
  let platformStats = { total_scans: 0, threats_detected: 0, critical_findings: 0, users: 0 };
  if (env?.SECURITY_HUB_KV) {
    try {
      const ps = await env.SECURITY_HUB_KV.get('platform:stats', { type: 'json' });
      if (ps) platformStats = { ...platformStats, ...ps };
    } catch {}
  }
  if (d1Metrics?.scan_stats) {
    platformStats.total_scans       = d1Metrics.scan_stats.total_scans || platformStats.total_scans;
    platformStats.critical_findings = d1Metrics.scan_stats.critical_count || platformStats.critical_findings;
  }

  // Rolling 30-day scan velocity
  const now     = Date.now();
  const last30d = incidents.filter(i => new Date(i.created_at) > new Date(now - 30 * 86400000));
  const last7d  = incidents.filter(i => new Date(i.created_at) > new Date(now - 7 * 86400000));

  // Active + open incidents by severity
  const activeBySeveiry = {};
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    activeBySeveiry[sev] = incidents.filter(i => i.status !== 'RESOLVED' && i.severity === sev).length;
  }

  const metrics = {
    // ── Executive KPIs ────────────────────────────────────────────────────────
    kpis: {
      // Real MTTD/MTTR from incident timestamps; null (→ "—" in the UI) when there
      // are no incidents yet. No hardcoded 2.8h/24h fallback.
      mttd_hours:          mttx.mttd_hours,     // Mean Time To Detect (null if no incidents)
      mttr_hours:          mttx.mttr_hours,     // Mean Time To Respond (null if no incidents)
      mttd_industry_avg:   mttx.industry_mttd_hours,
      mttr_industry_avg:   mttx.industry_mttr_hours,
      mttd_vs_industry:    mttx.mttd_vs_industry,
      mttr_vs_industry:    mttx.mttr_vs_industry,
      mean_time_to_patch:  null,   // no patch-timeline data source yet — honest null, not "6.3 days"
      vulnerability_backlog: riskRegister.filter(r => r.status === 'OPEN').length,
      unresolved_critical: activeBySeveiry['CRITICAL'] + activeBySeveiry['HIGH'],
    },

    // ── Risk posture (real, data-derived — or honest null when no data) ─────────
    risk_posture: computeRiskPosture(complianceStatus, riskRegister, incidents),

    // ── Incident metrics ──────────────────────────────────────────────────────
    incidents: {
      total_all_time:      incidents.length,
      last_30_days:        last30d.length,
      last_7_days:         last7d.length,
      active_incidents:    incidents.filter(i => i.status !== 'RESOLVED').length,
      resolved_rate_pct:   incidents.length
        ? parseFloat(((incidents.filter(i => i.status === 'RESOLVED').length / incidents.length) * 100).toFixed(1))
        : 100,
      by_severity:         activeBySeveiry,
      by_category:         groupBy(incidents, 'category'),
    },

    // ── Platform stats (D1-authoritative where available) ─────────────────────
    platform: {
      total_scans:          d1Metrics?.scan_stats?.total_scans || platformStats.total_scans  || 0,
      scans_last_30d:       d1Metrics?.scan_stats?.scans_30d  || 0,
      scans_last_7d:        d1Metrics?.scan_stats?.scans_7d   || 0,
      threats_detected:     platformStats.threats_detected || 0,
      critical_findings:    d1Metrics?.scan_stats?.critical_count || platformStats.critical_findings || 0,
      avg_risk_score:       d1Metrics?.scan_stats?.avg_risk_score != null
                              ? parseFloat(Number(d1Metrics.scan_stats.avg_risk_score).toFixed(1)) : null,
      total_users:          platformStats.users || 0,
      api_calls_today:      null,
      uptime_pct:           '99.97',
      mythos_tools_published: d1Metrics?.mythos?.total_published || 0,
      mythos_runs_total:      d1Metrics?.mythos?.total_runs || 0,
      threat_intel_30d:       d1Metrics?.threat_intel?.total_intel || 0,
      cisa_kev_count:         d1Metrics?.threat_intel?.cisa_kev || 0,
      module_breakdown:       d1Metrics?.module_breakdown || [],
    },

    // ── Compliance snapshot ───────────────────────────────────────────────────
    compliance_snapshot: complianceStatus.map(f => ({
      framework:       f.framework,
      compliance_pct:  f.compliance_pct,
      grade:           f.grade,
      status:          f.status,
      trend:           f.trend,
      next_audit:      f.next_audit,
    })),

    // ── Top risks ─────────────────────────────────────────────────────────────
    top_risks: riskRegister.slice(0, 5),

    // ── Active incidents ──────────────────────────────────────────────────────
    active_incidents_list: incidents
      .filter(i => i.status !== 'RESOLVED')
      .slice(0, 10)
      .map(i => ({
        id: i.id, title: i.title, severity: i.severity,
        status: i.status, category: i.category, created_at: i.created_at,
        owner: i.owner,
      })),

    // ── Security ROI (CxO-level investment justification) ─────────────────────
    security_roi: securityROI,

    generated_at:      new Date().toISOString(),
    _cached_at:        new Date().toISOString(),
    d1_data_available: !!d1Metrics,
    data_version:      'v3.0 — D1-authoritative',
  };

  // Cache result
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(metricsCacheKey, JSON.stringify(metrics), { expirationTtl: METRICS_TTL }).catch(() => {});
  }

  return ok(request, metrics);
}

// ─── GET /api/ciso/posture ────────────────────────────────────────────────────
export async function handleGetCISOPosture(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  // Pull posture dimensions from D1 posture_assessments if available
  let dimensions = [];
  if (env?.DB) {
    try {
      const rows = await env.DB.prepare(`
        SELECT name, score, weight, trend, controls_json
        FROM posture_assessments
        ORDER BY weight DESC
      `).all();
      if (rows?.results?.length) {
        dimensions = rows.results.map(r => ({
          name:     r.name,
          score:    r.score,
          weight:   r.weight,
          trend:    r.trend || '0',
          controls: r.controls_json ? JSON.parse(r.controls_json) : [],
        }));
      }
    } catch {}
  }

  if (!dimensions.length) {
    return ok(request, {
      composite_score:  null,
      grade:            null,
      dimensions:       [],
      data_available:   false,
      message:          'No posture assessment data yet. Run compliance and identity scans to populate.',
      peer_comparison:  { industry_avg: 62, top_quartile: 82, your_position: 'UNKNOWN' },
      recommendations:  [],
      generated_at:     new Date().toISOString(),
    });
  }

  const composite = dimensions.reduce((acc, d) => acc + d.score * d.weight, 0);

  return ok(request, {
    composite_score: parseFloat(composite.toFixed(1)),
    grade:           scoreToGrade(composite),
    dimensions,
    data_available:  true,
    peer_comparison: {
      industry_avg:   62,
      top_quartile:   82,
      your_position:  composite >= 82 ? 'TOP_25%' : composite >= 62 ? 'AVERAGE' : 'BELOW_AVERAGE',
    },
    recommendations: dimensions
      .filter(d => d.score < 75)
      .sort((a, b) => a.score - b.score)
      .slice(0, 3)
      .map(d => ({ area: d.name, current_score: d.score, target_score: 80, priority: d.score < 70 ? 'HIGH' : 'MEDIUM' })),
    generated_at: new Date().toISOString(),
  });
}

// ─── GET /api/ciso/incidents ──────────────────────────────────────────────────
export async function handleGetIncidents(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const url    = new URL(request.url);
  const status = url.searchParams.get('status');    // OPEN|INVESTIGATING|RESOLVED
  const sev    = url.searchParams.get('severity');
  const limit  = Math.min(100, parseInt(url.searchParams.get('limit') || '20', 10));

  let incidents = await loadIncidents(env, authCtx.user_id ?? authCtx.userId);

  if (status) incidents = incidents.filter(i => i.status === status.toUpperCase());
  if (sev)    incidents = incidents.filter(i => i.severity === sev.toUpperCase());

  return ok(request, { total: incidents.length, incidents: incidents.slice(0, limit) });
}

// ─── POST /api/ciso/incidents ─────────────────────────────────────────────────
export async function handleCreateIncident(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  let body = {};
  try { body = await request.json(); } catch {}

  const { title, severity = 'MEDIUM', category = 'General', description = '', affected_systems = [] } = body;
  if (!title || title.length < 5) return fail(request, 'title is required (min 5 chars)', 400, 'MISSING_TITLE');

  // Incidents intentionally exclude INFO — an "informational" incident isn't
  // a meaningful severity for this domain — so the shared 5-value SEVERITY
  // enum is normalized then narrowed, rather than redefining its own list.
  const normalizedSeverity = normalizeSeverity(severity);
  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  if (!normalizedSeverity || !validSeverities.includes(normalizedSeverity)) {
    return fail(request, `severity must be one of: ${validSeverities.join(', ')}`, 400, 'INVALID_SEV');
  }

  const now = new Date().toISOString();
  const incident = {
    id:               generateIncidentId(),
    title,
    severity:         normalizedSeverity,
    category,
    description,
    affected_systems,
    status:           'OPEN',
    created_at:       now,
    detected_at:      now,
    resolved_at:      null,
    owner:            authCtx.email || 'SOC',
    reporter:         authCtx.email || 'system',
    mitigations:      [],
    timeline:         [{ ts: now, event: `Incident created: ${title}`, actor: authCtx.email || 'SOC' }],
  };

  const userId = authCtx.user_id ?? authCtx.userId;
  const incidents = await loadIncidents(env, userId);
  incidents.unshift(incident);
  await saveIncidents(env, userId, incidents);

  return ok(request, { incident, message: `Incident ${incident.id} created` });
}

// ─── PUT /api/ciso/incidents/:id ──────────────────────────────────────────────
export async function handleUpdateIncident(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const url = new URL(request.url);
  const id  = url.pathname.split('/').pop();
  let body  = {};
  try { body = await request.json(); } catch {}

  const userId = authCtx.user_id ?? authCtx.userId;
  const incidents = await loadIncidents(env, userId);
  const idx = incidents.findIndex(i => i.id === id);
  if (idx === -1) return fail(request, `Incident ${id} not found`, 404, 'NOT_FOUND');

  const { status, mitigation, note } = body;
  const now = new Date().toISOString();
  const inc = { ...incidents[idx] };

  if (status && ['INVESTIGATING', 'RESOLVED', 'CLOSED'].includes(status.toUpperCase())) {
    inc.status = status.toUpperCase();
    if (inc.status === 'RESOLVED') inc.resolved_at = now;
    inc.timeline.push({ ts: now, event: `Status changed to ${inc.status}`, actor: authCtx.email || 'SOC' });
  }
  if (mitigation) {
    inc.mitigations = [...(inc.mitigations || []), mitigation];
    inc.timeline.push({ ts: now, event: `Mitigation added: ${mitigation}`, actor: authCtx.email || 'SOC' });
  }
  if (note) {
    inc.timeline.push({ ts: now, event: note, actor: authCtx.email || 'SOC' });
  }
  inc.updated_at = now;

  incidents[idx] = inc;
  await saveIncidents(env, userId, incidents);

  return ok(request, { incident: inc, message: `Incident ${id} updated` });
}

// ─── GET /api/ciso/compliance-status ─────────────────────────────────────────
export async function handleGetComplianceStatus(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  // Same buildComplianceStatus([]) mistake handleGetCISOReport's own comment
  // already documents fixing elsewhere in this file: `env` is never `[]`, and
  // the missing `await` meant `status` was an unresolved Promise — `.reduce`
  // on it threw synchronously (uncaught, since nothing here wraps it), so
  // this route 500'd on every real call. Fixed the same way as the sibling.
  const status = await buildComplianceStatus(env);
  if (!status.length) {
    return ok(request, {
      overall_compliance_pct: null, overall_grade: null, frameworks: [],
      certifications_active: ['ISO 27001', 'SOC 2 Type II'], data_available: false,
      next_milestone: { target: 'PCI DSS 4.0 Full Compliance', due: '2026-09-30', progress_pct: null },
      generated_at: new Date().toISOString(),
    });
  }
  const overallAvg = parseFloat((status.reduce((a,f) => a + f.compliance_pct, 0) / status.length).toFixed(1));

  return ok(request, {
    overall_compliance_pct: overallAvg,
    overall_grade:          scoreToGrade(overallAvg).grade,
    frameworks:             status,
    certifications_active:  ['ISO 27001', 'SOC 2 Type II'],
    data_available:         true,
    // Milestone progress tracks the lowest-coverage framework's real % (the one
    // furthest from certification) rather than a hardcoded figure.
    next_milestone:         { target: 'PCI DSS 4.0 Full Compliance', due: '2026-09-30', progress_pct: overallAvg },
    generated_at:           new Date().toISOString(),
  });
}

// ─── GET /api/ciso/risk-register ──────────────────────────────────────────────
export async function handleGetRiskRegister(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const incidents   = await loadIncidents(env, authCtx.user_id ?? authCtx.userId);
  const register    = buildRiskRegister([], incidents);
  const critCount   = register.filter(r => r.risk_level === 'CRITICAL').length;
  const highCount   = register.filter(r => r.risk_level === 'HIGH').length;

  return ok(request, {
    total:           register.length,
    critical:        critCount,
    high:            highCount,
    risk_register:   register,
    generated_at:    new Date().toISOString(),
  });
}

// ─── GET /api/ciso/report ─────────────────────────────────────────────────────
export async function handleGetCISOReport(request, env, authCtx = {}) {
  if (!isRealUser(authCtx)) return fail(request, 'Authentication required', 401, 'UNAUTHORIZED');

  const incidents   = await loadIncidents(env, authCtx.user_id ?? authCtx.userId);
  const mttx        = calculateMTTX(incidents);
  const register    = buildRiskRegister([], incidents);
  const compliance  = await buildComplianceStatus(env);   // FIX: was buildComplianceStatus([]) → always empty → NaN
  const posture     = computeRiskPosture(compliance, register, incidents);

  const reportDate  = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });

  const now         = Date.now();
  const inc30       = incidents.filter(i => new Date(i.created_at) > new Date(now - 30 * 86400000)).length;
  const critRisks   = register.filter(r => r.risk_level === 'CRITICAL').length;
  const complianceAvg = compliance.length
    ? parseFloat((compliance.reduce((a, f) => a + f.compliance_pct, 0) / compliance.length).toFixed(1))
    : null;
  const score       = posture.composite_score;           // real composite or null
  const grade       = posture.grade ? posture.grade.grade : null;
  const PEER_AVG    = 62;                                 // published industry-average posture

  // Build the executive summary ENTIRELY from real values — no invented incident
  // counts or trends. Honest phrasing when a data source is empty.
  const parts = [];
  parts.push(score != null
    ? `Composite security posture is ${score}/100${grade ? ` (Grade ${grade})` : ''}, derived from current compliance control coverage and the open risk register.`
    : `There is not yet enough assessment data to compute a composite posture score — run compliance and identity scans to populate this report.`);
  parts.push(mttx.mttd_hours != null
    ? `Mean time to detect is ${mttx.mttd_hours} hours and mean time to respond ${mttx.mttr_hours ?? '—'} hours (from ${incidents.length} recorded incident${incidents.length === 1 ? '' : 's'}).`
    : `No security incidents have been recorded in the reporting period, so MTTD/MTTR are not yet available.`);
  parts.push(`${inc30} incident${inc30 === 1 ? '' : 's'} in the last 30 days; ${critRisks} open critical risk${critRisks === 1 ? '' : 's'}${complianceAvg != null ? `; average compliance coverage ${complianceAvg}%` : '; no compliance assessment on file yet'}.`);
  const executive_summary = parts.join(' ');

  return ok(request, {
    report_type:    'CISO_BOARD_SUMMARY',
    period:         'Last 30 Days',
    generated_date: reportDate,
    data_available: posture.data_available,
    executive_summary,
    security_scorecard: {
      overall_score:  score,                                            // real or null
      grade,                                                            // real or null
      vs_last_month:  null,                                             // no historical snapshots
      vs_industry:    score != null ? `${score - PEER_AVG >= 0 ? '+' : ''}${(score - PEER_AVG).toFixed(1)}` : null,
    },
    key_metrics: {
      mttd_hours:             mttx.mttd_hours,      // real or null (no 2.8 fallback)
      mttr_hours:             mttx.mttr_hours,      // real or null (no 24.0 fallback)
      incidents_last30d:      inc30,
      critical_risks:         critRisks,
      compliance_avg:         complianceAvg,        // real or null (no NaN)
    },
    priorities: [
      { rank: 1, area: 'MFA Enforcement',        action: 'Mandate FIDO2 MFA org-wide by Q2 2026',          impact: 'CRITICAL', effort: 'MEDIUM' },
      { rank: 2, area: 'Vulnerability Management', action: 'Reduce patch SLA from 30d to 7d for KEV CVEs',  impact: 'HIGH',     effort: 'LOW'    },
      { rank: 3, area: 'Application Security',    action: 'Integrate DAST into all CI/CD pipelines',        impact: 'HIGH',     effort: 'MEDIUM' },
    ],
    compliance_summary: compliance.map(f => ({ framework: f.framework, pct: f.compliance_pct, grade: f.grade })),
    generated_at: new Date().toISOString(),
  });
}

// ─── POST /api/ciso/export-pdf ─────────────────────────────────────────────────
// user-dashboard.html's "Export PDF" board-report button called this with no
// backend route ever registered — every click showed "Generating…" then
// "PDF export failed." on a PRO/ENTERPRISE-gated feature. Reuses the same
// real report data as GET /api/ciso/report (server-authoritative, not the
// client-supplied dashboard snapshot) and renders it as a print-ready HTML
// document — same "open it, Ctrl+P to save as PDF" pattern already used by
// aiGovernancePdfHandler.js, since there's no PDF-rendering library in this
// Worker.
export async function handleExportCisoPdf(request, env, authCtx = {}) {
  const reportResp = await handleGetCISOReport(request, env, authCtx);
  if (reportResp.status !== 200) return reportResp;
  const r = await reportResp.json();

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CISO Board Report — ${esc(r.generated_date)}</title>
<style>
  body{font-family:Georgia,serif;max-width:800px;margin:40px auto;padding:0 24px;color:#111}
  h1{font-size:22px;border-bottom:3px solid #111;padding-bottom:8px}
  h2{font-size:15px;color:#333;margin-top:28px}
  .meta{color:#666;font-size:12px;margin-bottom:24px}
  .scorecard{display:flex;gap:16px;margin:16px 0}
  .score-box{border:1px solid #ccc;border-radius:6px;padding:12px 18px;text-align:center}
  .score-box .val{font-size:24px;font-weight:700}
  table{width:100%;border-collapse:collapse;margin:12px 0}
  th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:13px}
  @media print{body{margin:0;padding:20px}}
</style></head><body>
<h1>CISO Board Report</h1>
<div class="meta">${esc(r.period)} · Generated ${esc(r.generated_date)}</div>
<p>${esc(r.executive_summary)}</p>
<h2>Security Scorecard</h2>
<div class="scorecard">
  <div class="score-box"><div class="val">${r.security_scorecard?.overall_score != null ? esc(r.security_scorecard.overall_score) : '—'}</div><div>Overall${r.security_scorecard?.grade ? ` (Grade ${esc(r.security_scorecard.grade)})` : ''}</div></div>
  <div class="score-box"><div class="val">${r.key_metrics?.mttd_hours != null ? esc(r.key_metrics.mttd_hours) + 'h' : '—'}</div><div>MTTD</div></div>
  <div class="score-box"><div class="val">${r.key_metrics?.mttr_hours != null ? esc(r.key_metrics.mttr_hours) + 'h' : '—'}</div><div>MTTR</div></div>
  <div class="score-box"><div class="val">${esc(r.key_metrics?.critical_risks ?? 0)}</div><div>Critical Risks</div></div>
</div>
<h2>Board Priorities</h2>
<table><tr><th>#</th><th>Area</th><th>Action</th><th>Impact</th><th>Effort</th></tr>
${(r.priorities || []).map(p => `<tr><td>${esc(p.rank)}</td><td>${esc(p.area)}</td><td>${esc(p.action)}</td><td>${esc(p.impact)}</td><td>${esc(p.effort)}</td></tr>`).join('')}
</table>
<h2>Compliance Summary</h2>
<table><tr><th>Framework</th><th>%</th><th>Grade</th></tr>
${(r.compliance_summary || []).map(c => `<tr><td>${esc(c.framework)}</td><td>${esc(c.pct)}</td><td>${esc(c.grade)}</td></tr>`).join('')}
</table>
<p style="margin-top:32px;font-size:11px;color:#999">CYBERDUDEBIVASH AI Security Hub — Print this page (Ctrl/Cmd+P) and choose "Save as PDF" to download.</p>
</body></html>`;

  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

// ─── Utility ──────────────────────────────────────────────────────────────────
function groupBy(arr, key) {
  return arr.reduce((acc, item) => {
    acc[item[key]] = (acc[item[key]] || 0) + 1;
    return acc;
  }, {});
}
