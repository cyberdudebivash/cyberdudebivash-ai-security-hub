/**
 * CYBERDUDEBIVASH Executive Risk Platform — v1.0
 * Phase B Revenue Product 4
 *
 * Endpoints:
 *   POST /api/executive/risk-brief     — Board-level risk executive brief
 *   GET  /api/executive/dashboard      — Executive KPI dashboard
 *   POST /api/executive/forecast       — 90-day risk forecast
 *   POST /api/executive/board-report   — Full board presentation data
 *
 * Audience: CISO, CTO, Board of Directors, Enterprise Risk Committees
 * Pricing: ENTERPRISE plan required
 */

import { callClaude } from '../core/mythosAIProvider.js';
import { buildReportShell } from './reportingEngine.js';
import { generateAdaptiveRecommendations } from '../core/adaptiveCyberBrain.js';
import { RadarService } from '../services/radarService.js';

function ok(data, status = 200) { return Response.json(data, { status }); }

// Reports below interpolate org/sector/AI-generated narrative into HTML —
// escape to prevent XSS (mirrors siemExport.js's buildExecutivePDF convention).
function escHTML(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function wantsHTML(request, body) {
  const fmt = (body?.format || new URL(request.url).searchParams.get('format') || '').toLowerCase();
  return fmt === 'html' || fmt === 'pdf';
}

function htmlReportResponse(html, filename) {
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Content-Disposition': `inline; filename="${filename}"`,
    },
  });
}

// RBAC-0: also accepts a real Platform Admin / Super Admin staff session
// (auth/rbac.js isPlatformAdmin), not just the ADMIN_KEY bypass or a paying
// ENTERPRISE subscriber. Purely additive — both existing pass conditions
// (isAdmin, tier==='ENTERPRISE') are unchanged.
async function enterpriseOnly(authCtx, env) {
  if (authCtx?.isAdmin) return null;
  if (authCtx?.tier === 'ENTERPRISE') return null;
  const { isPlatformAdmin } = await import('../auth/rbac.js');
  if (await isPlatformAdmin(authCtx, env)) return null;
  return ok({ success: false, error: 'Executive Risk Platform requires ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing', features: ['Board-ready risk briefs', 'Quarterly risk forecasting', 'Peer benchmarking', 'Regulatory exposure analysis', 'PDF board reports'] }, 403);
}

// ─── KPI fetchers from D1 ─────────────────────────────────────────────────────
async function fetchPlatformKPIs(env) {
  const kpis = {};
  if (!env.DB) return kpis;

  try {
    const [userRow, orderRow, asmRow, actorRow, cveRow, mythos] = await Promise.all([
      env.DB.prepare('SELECT COUNT(*) as cnt FROM users').first(),
      env.DB.prepare("SELECT COUNT(*) as cnt, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as paid FROM service_orders").first().catch(() => null),
      env.DB.prepare('SELECT COUNT(*) as cnt, AVG(asm_score) as avg_score FROM asm_targets').first().catch(() => null),
      env.DB.prepare('SELECT COUNT(*) as cnt FROM threat_actors WHERE active = 1').first().catch(() => null),
      env.DB.prepare('SELECT COUNT(*) as cnt FROM threat_intel WHERE cvss_score >= 9').first().catch(() => null),
      env.DB.prepare('SELECT SUM(tools_generated) as tools, SUM(solutions_published) as pub, MAX(created_at) as last FROM mythos_runs').first().catch(() => null),
    ]);

    kpis.total_users       = userRow?.cnt || 0;
    kpis.total_orders      = orderRow?.cnt || 0;
    kpis.paid_orders       = orderRow?.paid || 0;
    kpis.asm_targets       = asmRow?.cnt || 0;
    kpis.avg_asm_score     = Math.round(asmRow?.avg_score || 0);
    kpis.active_actors     = actorRow?.cnt || 0;
    kpis.critical_cves     = cveRow?.cnt || 0;
    kpis.mythos_tools      = mythos?.tools || 0;
    kpis.mythos_published  = mythos?.pub || 0;
    kpis.mythos_last_run   = mythos?.last || null;
  } catch {}

  return kpis;
}

async function fetchCVEKPIs(env) {
  if (!env.DB) return {};
  try {
    const rows = await env.DB.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN cvss_score >= 9 THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN cvss_score >= 7 AND cvss_score < 9 THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN actively_exploited = 1 THEN 1 ELSE 0 END) as kev
      FROM threat_intel
    `).first();
    return rows || {};
  } catch { return {}; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 1: POST /api/executive/risk-brief — Board-Level Risk Brief
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleExecutiveRiskBrief(request, env, authCtx) {
  const gate = await enterpriseOnly(authCtx, env);
  if (gate) return gate;

  const body    = await request.json().catch(() => ({}));
  const org     = body.organization || body.org_name || body.org || 'Your Organization';
  const sector  = body.sector || body.industry || 'Technology';
  const domain  = body.domain || '';
  const period  = body.period || 'Q2 2026';

  // Gather platform intelligence
  const [kpis, cveKpis] = await Promise.all([fetchPlatformKPIs(env), fetchCVEKPIs(env)]);

  // Pull recent scan findings from KV
  let sslRisk = 35, threatLevel = 'MEDIUM';
  try {
    const kv = env.KV || env.SECURITY_HUB_KV;
    if (domain) {
      const cached = await kv?.get(`ssl_result:${domain}`);
      if (cached) {
        const d = JSON.parse(cached);
        sslRisk = d.risk_score || d.executive_summary?.risk_score || 35;
      }
    }
  } catch {}

  // Composite enterprise risk score
  const riskDrivers = {
    external_exposure:  sslRisk,
    threat_landscape:   kpis.active_actors > 10 ? 75 : kpis.active_actors > 5 ? 55 : 35,
    vulnerability_debt: cveKpis.critical > 50 ? 80 : cveKpis.critical > 20 ? 60 : 40,
    compliance_posture: 45,
    ai_security:        65,
  };
  const compositeRisk = Math.round(Object.values(riskDrivers).reduce((s, v) => s + v, 0) / Object.keys(riskDrivers).length);
  const riskRating = compositeRisk >= 70 ? 'HIGH' : compositeRisk >= 50 ? 'MEDIUM' : 'LOW';

  // AI executive narrative
  let executiveSummary = null;
  try {
    const result = await callClaude(env, {
      prompt: `Write a board-level cybersecurity risk brief for ${org} (${sector}, ${period}).
Data points: Composite risk score: ${compositeRisk}/100 (${riskRating}). Active threat actors targeting sector: ${kpis.active_actors}. Critical CVEs in environment: ${cveKpis.critical || 0}. KEV-listed vulnerabilities: ${cveKpis.kev || 0}. Platform users: ${kpis.total_users}.

Write 3-4 paragraphs covering: (1) Current risk posture and trending, (2) Top 3 threats requiring board attention, (3) Regulatory and compliance exposure, (4) Recommended board-level actions and resource priorities. Use authoritative, boardroom-appropriate language.`,
      tier: 'ENTERPRISE',
      max_tokens: 600,
      temperature: 0.3,
    });
    executiveSummary = result?.content?.trim() || null;
  } catch {}

  const boardActions = compositeRisk >= 70
    ? ['Authorize emergency security investment', 'Brief audit committee', 'Initiate cyber insurance review']
    : compositeRisk >= 50
    ? ['Review security budget allocation', 'Approve CISO 90-day remediation plan', 'Schedule next board update']
    : ['Maintain current program', 'Continue quarterly reporting', 'Benchmark against industry peers'];

  if (wantsHTML(request, body)) {
    const riskColor = compositeRisk >= 70 ? '#ef4444' : compositeRisk >= 50 ? '#f97316' : '#22c55e';
    const bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Composite Risk</div><div class="kpi-value" style="color:${riskColor}">${compositeRisk}/100</div><div class="kpi-sub">${escHTML(riskRating)}</div></div>
  <div class="kpi"><div class="kpi-label">Active APT Actors</div><div class="kpi-value">${kpis.active_actors || 0}</div><div class="kpi-sub">Tracked in sector</div></div>
  <div class="kpi"><div class="kpi-label">Critical CVEs</div><div class="kpi-value" style="color:#ef4444">${cveKpis.critical || 0}</div><div class="kpi-sub">CVSS &ge; 9</div></div>
  <div class="kpi"><div class="kpi-label">KEV-Listed</div><div class="kpi-value" style="color:#f97316">${cveKpis.kev || 0}</div><div class="kpi-sub">Actively exploited</div></div>
</div>
<div class="section">
  <h2>Executive Summary</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">${escHTML(executiveSummary) || 'No narrative available for this period.'}</p>
</div>
<div class="section">
  <h2>Risk Drivers</h2>
  <table><thead><tr><th>Driver</th><th>Score</th></tr></thead><tbody>
    ${Object.entries(riskDrivers).map(([k, v]) => `<tr><td>${escHTML(k.replace(/_/g, ' '))}</td><td>${v}/100</td></tr>`).join('')}
  </tbody></table>
</div>
<div class="section">
  <h2>Recommended Board Actions</h2>
  <table><thead><tr><th>#</th><th>Action</th></tr></thead><tbody>
    ${boardActions.map((a, i) => `<tr><td>${i + 1}</td><td>${escHTML(a)}</td></tr>`).join('')}
  </tbody></table>
</div>`;

    const html = buildReportShell({
      brandName: 'CYBERDUDEBIVASH SENTINEL APEX',
      primaryColor: '#6366f1',
      title: `Executive Risk Brief — ${org}`,
      metaLine: `Organization: ${escHTML(org)} &middot; Sector: ${escHTML(sector)} &middot; Period: ${escHTML(period)} &middot; CONFIDENTIAL — BOARD USE ONLY`,
      bodyHTML,
      footerNote: `CYBERDUDEBIVASH SENTINEL APEX &middot; Confidential &middot; Generated ${new Date().toISOString()}`,
    });
    return htmlReportResponse(html, `executive-risk-brief-${org.replace(/\W+/g, '-').toLowerCase()}.html`);
  }

  return ok({
    success:      true,
    service:      'CDB-EXEC-001',
    document:     'Executive Cybersecurity Risk Brief',
    organization: org,
    sector,
    period,
    prepared_by:  'CYBERDUDEBIVASH SENTINEL APEX',
    classification: 'CONFIDENTIAL — BOARD USE ONLY',
    risk_snapshot: {
      composite_risk_score: compositeRisk,
      risk_rating:          riskRating,
      trend:                'STABLE',
      last_assessment:      new Date().toISOString().slice(0, 10),
      drivers:              riskDrivers,
    },
    threat_landscape: {
      active_apt_actors:     kpis.active_actors || 0,
      critical_cves_tracked: cveKpis.critical  || 0,
      kev_listed_vulns:      cveKpis.kev       || 0,
      high_cvss_cves:        cveKpis.high      || 0,
    },
    platform_posture: {
      users_protected:     kpis.total_users    || 0,
      asm_targets_monitored: kpis.asm_targets  || 0,
      mythos_tools_active: kpis.mythos_published || 0,
      scans_completed:     kpis.total_orders   || 0,
    },
    executive_summary: executiveSummary,
    board_actions: boardActions,
    next_brief:    'Schedule: POST /api/executive/risk-brief (recommended monthly)',
    pdf_export:    'Self-service — POST with {"format":"html"} or append ?format=html for a print-ready board report (Ctrl+P -> Save as PDF)',
    powered_by:    'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:     new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 2: GET /api/executive/dashboard — Executive KPI Dashboard
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleExecutiveDashboard(request, env, authCtx) {
  if (!authCtx?.isAdmin && !['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    const { isPlatformAdmin } = await import('../auth/rbac.js');
    if (!(await isPlatformAdmin(authCtx, env))) {
      return ok({ success: false, error: 'Executive dashboard requires PRO or ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing' }, 403);
    }
  }

  const [kpis, cveKpis] = await Promise.all([fetchPlatformKPIs(env), fetchCVEKPIs(env)]);

  // Revenue metrics from D1
  let revenueKpis = {};
  try {
    const rev = await env.DB?.prepare(`
      SELECT
        COUNT(*) as total_orders,
        SUM(CASE WHEN status='completed' THEN amount_inr ELSE 0 END) as total_revenue_inr,
        COUNT(DISTINCT user_id) as paying_customers
      FROM service_orders
    `).first();
    revenueKpis = rev || {};
  } catch {}

  const compositeRisk = Math.min(100, Math.round(
    (kpis.active_actors > 10 ? 70 : kpis.active_actors > 5 ? 50 : 30) * 0.3 +
    (cveKpis.critical > 50 ? 75 : cveKpis.critical > 20 ? 55 : 35) * 0.3 +
    (kpis.avg_asm_score || 35) * 0.4
  ));

  return ok({
    success:    true,
    service:    'CDB-EXEC-002',
    dashboard:  'Executive Security KPI Dashboard',
    as_of:      new Date().toISOString(),
    security_kpis: {
      composite_risk_score:  compositeRisk,
      risk_trend:            'STABLE',
      active_threat_actors:  kpis.active_actors  || 0,
      critical_cves:         cveKpis.critical    || 0,
      kev_vulnerabilities:   cveKpis.kev         || 0,
      asm_targets_monitored: kpis.asm_targets    || 0,
      avg_attack_surface_score: kpis.avg_asm_score || 0,
      mythos_defense_tools:  kpis.mythos_published || 0,
    },
    platform_kpis: {
      total_users:        kpis.total_users    || 0,
      scans_completed:    kpis.total_orders   || 0,
      paid_services:      kpis.paid_orders    || 0,
      paying_customers:   revenueKpis.paying_customers || 0,
      revenue_inr:        revenueKpis.total_revenue_inr || 0,
      mythos_ai_runs:     kpis.mythos_tools   || 0,
    },
    threat_intelligence: {
      total_cves_tracked:   cveKpis.total    || 0,
      high_cvss_cves:       cveKpis.high     || 0,
      critical_cvss_cves:   cveKpis.critical || 0,
      kev_listed:           cveKpis.kev      || 0,
      active_apt_groups:    kpis.active_actors || 0,
    },
    status_summary: {
      platform:         'OPERATIONAL',
      threat_feeds:     kpis.active_actors > 0 ? 'ACTIVE' : 'SEEDING',
      ai_engine:        kpis.mythos_last_run ? 'ACTIVE' : 'INITIALIZING',
      cron_automation:  'RUNNING (5 jobs)',
    },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 3: POST /api/executive/forecast — 90-Day Risk Forecast
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleExecutiveForecast(request, env, authCtx) {
  const gate = await enterpriseOnly(authCtx, env);
  if (gate) return gate;

  const body   = await request.json().catch(() => ({}));
  const org    = body.organization || body.org || 'Your Organization';
  const sector = body.sector || 'Technology';
  const horizon = body.horizon_days || 90;

  const [kpis, cveKpis] = await Promise.all([fetchPlatformKPIs(env), fetchCVEKPIs(env)]);

  const today         = new Date();
  const forecastEnd   = new Date(today.getTime() + horizon * 86400000);
  const currentRisk   = Math.min(100, 35 + (kpis.active_actors || 0) * 2 + (cveKpis.critical || 0) * 0.3);

  // Scenario modeling (simplified quantitative risk)
  const scenarios = [
    {
      name:        'Base Case',
      probability: 0.60,
      risk_delta:  +5,
      risk_score:  Math.min(100, currentRisk + 5),
      drivers:     ['Steady threat actor activity', 'Routine CVE disclosures', 'Normal patch cycle'],
      impact:      'LOW',
    },
    {
      name:        'Adverse Case',
      probability: 0.30,
      risk_delta:  +22,
      risk_score:  Math.min(100, currentRisk + 22),
      drivers:     ['Zero-day exploitation in sector', 'Ransomware group targets industry', 'Supply chain compromise event'],
      impact:      'HIGH',
      mitigations: ['Enhanced EDR monitoring', 'Patch acceleration', 'Incident response readiness drill'],
    },
    {
      name:        'Severe Case',
      probability: 0.10,
      risk_delta:  +45,
      risk_score:  Math.min(100, currentRisk + 45),
      drivers:     ['Nation-state campaign targeting sector', 'Critical infrastructure attack wave', 'AI-powered attack campaigns at scale'],
      impact:      'CRITICAL',
      mitigations: ['Activate incident response team', 'Enable enhanced threat monitoring', 'Engage CISA/sector ISAC', 'Board notification required'],
    },
  ];

  const expectedRisk = Math.round(scenarios.reduce((s, sc) => s + sc.risk_score * sc.probability, 0));

  // AI forecast narrative
  let forecastNarrative = null;
  try {
    const result = await callClaude(env, {
      prompt: `Generate a 90-day cybersecurity risk forecast for ${org} (${sector} sector).
Current risk: ${Math.round(currentRisk)}/100. Active threat actors: ${kpis.active_actors}. Critical CVEs: ${cveKpis.critical || 0}. Expected 90-day risk: ${expectedRisk}/100.
Cover: (1) threat trends over the forecast horizon, (2) sector-specific risk drivers, (3) top 3 proactive investments to reduce risk, (4) key risk indicators to monitor. Authoritative, data-driven tone. 5-6 sentences.`,
      tier: 'ENTERPRISE',
      max_tokens: 450,
      temperature: 0.25,
    });
    forecastNarrative = result?.content?.trim() || null;
  } catch {}

  return ok({
    success:      true,
    service:      'CDB-EXEC-003',
    document:     '90-Day Cybersecurity Risk Forecast',
    organization: org,
    sector,
    forecast_period: {
      start:        today.toISOString().slice(0, 10),
      end:          forecastEnd.toISOString().slice(0, 10),
      horizon_days: horizon,
    },
    current_risk: {
      score:   Math.round(currentRisk),
      level:   currentRisk >= 70 ? 'HIGH' : currentRisk >= 50 ? 'MEDIUM' : 'LOW',
    },
    forecast: {
      expected_risk_score: expectedRisk,
      expected_risk_level: expectedRisk >= 70 ? 'HIGH' : expectedRisk >= 50 ? 'MEDIUM' : 'LOW',
      risk_change:         expectedRisk - Math.round(currentRisk),
      scenarios,
    },
    key_risk_indicators: [
      { kri: 'CVE critical count', current: cveKpis.critical || 0, threshold: 100, status: (cveKpis.critical || 0) > 100 ? 'BREACH' : 'NORMAL' },
      { kri: 'Active APT actors', current: kpis.active_actors || 0, threshold: 15, status: (kpis.active_actors || 0) > 15 ? 'BREACH' : 'NORMAL' },
      { kri: 'Unpatched KEV vulns', current: cveKpis.kev || 0, threshold: 5, status: (cveKpis.kev || 0) > 5 ? 'BREACH' : 'NORMAL' },
    ],
    forecast_narrative:  forecastNarrative,
    strategic_recommendations: [
      'Complete AI Security Posture Management assessment via /api/aispm/owasp-llm',
      'Enroll all critical assets in Attack Surface Management monitoring',
      'Schedule board briefing on adverse scenario preparation',
    ],
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 4: POST /api/executive/board-report — Full Board Report Data
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleBoardReport(request, env, authCtx) {
  const gate = await enterpriseOnly(authCtx, env);
  if (gate) return gate;

  const body   = await request.json().catch(() => ({}));
  const org    = body.organization || body.org || 'Your Organization';
  const sector = body.sector || 'Technology';
  const quarter = body.quarter || `Q${Math.ceil((new Date().getMonth() + 1) / 3)} ${new Date().getFullYear()}`;

  const [kpis, cveKpis] = await Promise.all([fetchPlatformKPIs(env), fetchCVEKPIs(env)]);

  const compositeRisk = Math.min(100, Math.round(
    35 + (kpis.active_actors || 0) * 2 + (cveKpis.critical || 0) * 0.3
  ));

  // Full AI narrative
  let boardNarrative = null;
  try {
    const result = await callClaude(env, {
      prompt: `Write a complete board cybersecurity report for ${org} (${sector}, ${quarter}).
Platform data: Users: ${kpis.total_users}, Scans: ${kpis.total_orders}, Risk score: ${compositeRisk}/100, APT actors: ${kpis.active_actors}, Critical CVEs: ${cveKpis.critical || 0}.
Structure: (1) Executive Summary (2-3 sentences), (2) Risk Posture heading with data, (3) Top Threats, (4) Program Accomplishments, (5) Board Resolutions Requested. Use authoritative board-level tone. 8-10 sentences total.`,
      tier: 'ENTERPRISE',
      max_tokens: 700,
      temperature: 0.25,
    });
    boardNarrative = result?.content?.trim() || null;
  } catch {}

  const rating = compositeRisk >= 70 ? 'HIGH' : compositeRisk >= 50 ? 'MEDIUM' : 'LOW';
  const boardResolutions = compositeRisk >= 70
    ? ['Authorize $X emergency security budget', 'Mandate CISO 30-day remediation plan', 'Initiate cyber insurance review', 'Brief audit committee on risk posture']
    : ['Approve annual security roadmap', 'Allocate budget for continuous monitoring platform', 'Schedule next board briefing in 90 days'];
  const appendices = [
    { title: 'Threat Actor Landscape', source: '/api/intel/actor' },
    { title: 'CVE Exposure Report',    source: '/api/intel/cve' },
    { title: 'Attack Surface Summary', source: '/api/asm/targets' },
    { title: '90-Day Risk Forecast',   source: '/api/executive/forecast' },
  ];

  if (wantsHTML(request, body)) {
    const riskColor = compositeRisk >= 70 ? '#ef4444' : compositeRisk >= 50 ? '#f97316' : '#22c55e';
    const bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Composite Risk</div><div class="kpi-value" style="color:${riskColor}">${compositeRisk}/100</div><div class="kpi-sub">${escHTML(rating)}</div></div>
  <div class="kpi"><div class="kpi-label">Active Threats</div><div class="kpi-value">${kpis.active_actors || 0}</div><div class="kpi-sub">APT actors tracked</div></div>
  <div class="kpi"><div class="kpi-label">Critical Vulns</div><div class="kpi-value" style="color:#ef4444">${cveKpis.critical || 0}</div><div class="kpi-sub">CVSS &ge; 9</div></div>
  <div class="kpi"><div class="kpi-label">KEV Vulns</div><div class="kpi-value" style="color:#f97316">${cveKpis.kev || 0}</div><div class="kpi-sub">Actively exploited</div></div>
</div>
<div class="section">
  <h2>Executive Summary</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">${escHTML(boardNarrative) || 'No narrative available for this period.'}</p>
</div>
<div class="section">
  <h2>Program Metrics</h2>
  <table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>
    <tr><td>Users Protected</td><td>${kpis.total_users || 0}</td></tr>
    <tr><td>Assessments Completed</td><td>${kpis.total_orders || 0}</td></tr>
    <tr><td>AI Defense Tools</td><td>${kpis.mythos_published || 0}</td></tr>
    <tr><td>ASM Targets Monitored</td><td>${kpis.asm_targets || 0}</td></tr>
  </tbody></table>
</div>
<div class="section">
  <h2>Board Resolutions Requested</h2>
  <table><thead><tr><th>#</th><th>Resolution</th></tr></thead><tbody>
    ${boardResolutions.map((r, i) => `<tr><td>${i + 1}</td><td>${escHTML(r)}</td></tr>`).join('')}
  </tbody></table>
</div>
<div class="section">
  <h2>Appendices</h2>
  <table><thead><tr><th>Title</th><th>Source</th></tr></thead><tbody>
    ${appendices.map(a => `<tr><td>${escHTML(a.title)}</td><td>${escHTML(a.source)}</td></tr>`).join('')}
  </tbody></table>
</div>`;

    const html = buildReportShell({
      brandName: 'CYBERDUDEBIVASH SENTINEL APEX',
      primaryColor: '#6366f1',
      title: `Board Cybersecurity Report — ${org}`,
      metaLine: `Organization: ${escHTML(org)} &middot; Sector: ${escHTML(sector)} &middot; ${escHTML(quarter)} &middot; BOARD CONFIDENTIAL`,
      bodyHTML,
      footerNote: `CYBERDUDEBIVASH SENTINEL APEX &middot; Confidential &middot; Generated ${new Date().toISOString()}`,
    });
    return htmlReportResponse(html, `board-report-${org.replace(/\W+/g, '-').toLowerCase()}.html`);
  }

  return ok({
    success:      true,
    service:      'CDB-EXEC-004',
    document:     'Board Cybersecurity Report',
    organization: org,
    sector,
    quarter,
    classification: 'BOARD CONFIDENTIAL',
    prepared_by:  'CYBERDUDEBIVASH SENTINEL APEX AI',
    sections: {
      executive_summary: boardNarrative,
      risk_posture: {
        composite_score:   compositeRisk,
        rating,
        active_threats:    kpis.active_actors || 0,
        critical_vulns:    cveKpis.critical   || 0,
        kev_vulns:         cveKpis.kev        || 0,
      },
      program_metrics: {
        users_protected:       kpis.total_users    || 0,
        assessments_completed: kpis.total_orders   || 0,
        ai_defense_tools:      kpis.mythos_published || 0,
        asm_targets_monitored: kpis.asm_targets    || 0,
      },
      board_resolutions: boardResolutions,
    },
    appendices,
    pdf_note:   'Self-service — POST with {"format":"html"} or append ?format=html for a print-ready board pack (Ctrl+P -> Save as PDF)',
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 5: POST /api/executive/playbook-recommendations — P10.6
// Aggregates threat intel, radar, customer assets, and ASM into enriched
// playbook recommendations. Read-only — never executes any action.
// ═══════════════════════════════════════════════════════════════════════════════

// Minimal MITRE ATT&CK technique lookup — only IDs already used in this codebase
const MITRE_TECHNIQUES = {
  T1190: { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  T1133: { technique_id: 'T1133', technique_name: 'External Remote Services', tactic: 'Initial Access' },
  T1059: { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  T1078: { technique_id: 'T1078', technique_name: 'Valid Accounts', tactic: 'Defense Evasion' },
  T1486: { technique_id: 'T1486', technique_name: 'Data Encrypted for Impact', tactic: 'Impact' },
  T1566: { technique_id: 'T1566', technique_name: 'Phishing', tactic: 'Initial Access' },
  T1055: { technique_id: 'T1055', technique_name: 'Process Injection', tactic: 'Privilege Escalation' },
  T1027: { technique_id: 'T1027', technique_name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' },
  T1548: { technique_id: 'T1548', technique_name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
  T1562: { technique_id: 'T1562', technique_name: 'Impair Defenses', tactic: 'Defense Evasion' },
};

function resolveMitreMapping(techniqueId) {
  if (!techniqueId) return [];
  const entry = MITRE_TECHNIQUES[techniqueId];
  return entry
    ? [entry]
    : [{ technique_id: techniqueId, technique_name: 'See MITRE ATT&CK catalog', tactic: 'Unknown' }];
}

function riskReductionEstimate(impact, isKev) {
  if (impact === 'CRITICAL' && isKev) return '15–25%';
  if (impact === 'CRITICAL')          return '10–20%';
  if (impact === 'HIGH')              return '5–12%';
  if (impact === 'MEDIUM')            return '3–8%';
  return '1–5%';
}

function deriveBusinessImpact(impact, category, sector) {
  const base = {
    CRITICAL: 'Severe — potential data breach, regulatory violation, or service outage',
    HIGH:     'Significant — elevated breach risk, compliance exposure, or customer trust damage',
    MEDIUM:   'Moderate — exploitable under active threat conditions; address within sprint cycle',
    LOW:      'Low — limited direct exposure; address in next security review cycle',
  };
  const sectorSuffix = sector && sector !== 'technology' ? ` (${sector} sector)` : '';
  return (base[impact] || 'Unknown business impact') + sectorSuffix;
}

function buildEvidenceList(action, allVulns) {
  const ev = [];
  const matchedVuln = action.cve
    ? allVulns.find(v => v.cve_id === action.cve)
    : null;
  if (matchedVuln?.in_kev)     ev.push('Listed in CISA Known Exploited Vulnerabilities (KEV) catalog');
  if (matchedVuln?.cvss >= 9)  ev.push(`CVSS ${matchedVuln.cvss.toFixed(1)} — Critical severity score`);
  else if (matchedVuln?.cvss >= 7) ev.push(`CVSS ${matchedVuln.cvss.toFixed(1)} — High severity score`);
  if (matchedVuln?.epss > 0.5) ev.push(`EPSS ${(matchedVuln.epss * 100).toFixed(1)}% exploitation probability in next 30 days`);
  if (matchedVuln?.ransomware)  ev.push('Known ransomware group association');
  if (action.mitre_ref)         ev.push(`MITRE ATT&CK technique: ${action.mitre_ref}`);
  return ev.length > 0 ? ev : ['No evidence available'];
}

export async function handlePlaybookRecommendations(request, env, authCtx) {
  const gate = await enterpriseOnly(authCtx, env);
  if (gate) return gate;

  const body   = await request.json().catch(() => ({}));
  const sector = (body.sector || 'technology').toLowerCase();
  const limit  = Math.min(parseInt(body.limit || '15', 10) || 15, 25);
  const userId = authCtx?.userId ?? authCtx?.user_id ?? null;
  const tier   = authCtx?.tier || 'ENTERPRISE';

  // ── 1. Fetch threat intel, customer assets, and ASM targets from D1 ────────
  let vulns          = [];
  let customerAssets = [];
  let asmTargets     = [];

  if (env.DB) {
    const [tiRows, assetRows, asmRows] = await Promise.all([
      env.DB.prepare(`
        SELECT cve_id, title, description, cvss_score, epss_score,
               actively_exploited, known_ransomware, NULL AS mitre_technique, severity
        FROM threat_intel
        WHERE severity IN ('CRITICAL','HIGH')
        ORDER BY cvss_score DESC LIMIT 25
      `).all().catch(() => ({ results: [] })),
      userId
        ? env.DB.prepare(`
            SELECT asset_value, asset_type
            FROM customer_assets
            WHERE owner_id = ? AND asset_type IN ('cve_watchlist','technology')
            LIMIT 50
          `).bind(userId).all().catch(() => ({ results: [] }))
        : Promise.resolve({ results: [] }),
      userId
        ? env.DB.prepare(`
            SELECT id, target, asm_score
            FROM asm_targets
            WHERE user_id = ? ORDER BY asm_score DESC LIMIT 10
          `).bind(userId).all().catch(() => ({ results: [] }))
        : Promise.resolve({ results: [] }),
    ]);

    vulns = (tiRows.results || []).map(r => ({
      cve_id:     r.cve_id  || null,
      title:      r.title   || r.cve_id || 'Unknown vulnerability',
      cvss:       r.cvss_score  || 0,
      epss:       r.epss_score  || 0,
      in_kev:     !!(r.actively_exploited),
      ransomware: !!(r.known_ransomware),
      severity:   r.severity || 'HIGH',
      mitre:      r.mitre_technique || null,
      description: r.description   || null,
    }));

    customerAssets = assetRows.results || [];
    asmTargets     = asmRows.results   || [];
  }

  // ── 2. Radar trending threats ──────────────────────────────────────────────
  let radarSignals = [];
  try {
    const svc = new RadarService(env);
    radarSignals = (await svc.getTrending({ limit: 10 })) || [];
  } catch {}

  // ── 3. Build findings for adaptiveCyberBrain from real data ───────────────
  const watchedCveIds = customerAssets
    .filter(a => a.asset_type === 'cve_watchlist')
    .map(a => a.asset_value)
    .filter(Boolean);

  const watchlistFindings = watchedCveIds.length > 0
    ? vulns
        .filter(v => watchedCveIds.includes(v.cve_id))
        .map(v => ({
          severity:    v.cvss >= 9 ? 'CRITICAL' : 'HIGH',
          title:       v.title,
          description: v.description || `${v.cve_id} — CVSS ${v.cvss}`,
          remediation: `Apply vendor patch for ${v.cve_id}. Verify CISA KEV exploitation status.`,
          category:    v.in_kev ? 'kev_exploit' : 'vulnerability',
        }))
    : [];

  // Fall back to top KEV/critical vulns if no watchlist is registered
  const effectiveFindings = watchlistFindings.length > 0
    ? watchlistFindings
    : vulns
        .filter(v => v.in_kev || v.cvss >= 9)
        .slice(0, 5)
        .map(v => ({
          severity:    'CRITICAL',
          title:       v.title,
          description: v.description || `${v.cve_id} — CVSS ${v.cvss}`,
          remediation: `Apply vendor patch for ${v.cve_id}. Monitor CISA KEV for exploitation updates.`,
          category:    'vulnerability',
        }));

  const adaptiveScore = vulns.length > 0
    ? Math.min(100, Math.round(
        35 +
        vulns.filter(v => v.in_kev).length * 20 +
        vulns.filter(v => v.cvss >= 9).length * 8
      ))
    : 35;

  // ── 4. Call the existing recommendation engine — REUSE, not replace ───────
  const adaptive = await generateAdaptiveRecommendations(env, {
    findings:      effectiveFindings.slice(0, 10),
    vulns:         vulns.slice(0, 15),
    adaptiveScore,
    attackChains:  [],
    sector,
    tier,
    userId,
  });

  // ── 5. Enrich with full P10.6 schema (read-only enrichment only) ───────────
  const asmAssetNames = asmTargets.map(t => t.target).filter(Boolean);
  const techStack     = customerAssets
    .filter(a => a.asset_type === 'technology')
    .map(a => a.asset_value)
    .filter(Boolean);

  const recommendations = (adaptive.actions || []).slice(0, limit).map((action, idx) => {
    const matchedVuln = action.cve
      ? vulns.find(v => v.cve_id === action.cve)
      : (action.priority === 1 ? vulns.find(v => v.in_kev) : null);

    const mitreRef = action.mitre_ref || matchedVuln?.mitre || null;
    const isKev    = !!(matchedVuln?.in_kev);
    const cvss     = matchedVuln?.cvss ?? null;
    const epss     = matchedVuln?.epss ?? null;

    const evidence   = buildEvidenceList(action, vulns);
    const confidence =
      (isKev && cvss !== null && cvss >= 9) ? 'HIGH'   :
      (cvss !== null && cvss >= 7 || isKev) ? 'MEDIUM' : 'LOW';

    const affectedAssets =
      asmAssetNames.length > 0 ? asmAssetNames.slice(0, 3) :
      techStack.length   > 0 ? techStack.slice(0, 3)     :
      ['No assets registered — add via POST /api/customer/assets'];

    const refs = [];
    if (action.cve) refs.push(`https://nvd.nist.gov/vuln/detail/${action.cve}`);
    if (isKev)      refs.push('https://www.cisa.gov/known-exploited-vulnerabilities-catalog');
    if (mitreRef)   refs.push(`https://attack.mitre.org/techniques/${mitreRef}/`);

    return {
      id:                       `rec_${Date.now().toString(36)}_${idx}`,
      title:                    action.title,
      priority:                 action.priority,
      urgency:                  action.urgency,
      category:                 action.category,
      evidence,
      confidence,
      affected_assets:          affectedAssets,
      recommended_action:       action.detail || action.title,
      mitre_mapping:            resolveMitreMapping(mitreRef),
      kev_status:               isKev,
      epss:                     epss !== null ? +epss.toFixed(4) : null,
      cvss:                     cvss !== null ? +cvss.toFixed(1) : null,
      business_impact:          deriveBusinessImpact(action.impact, action.category, sector),
      estimated_effort:         action.effort || 'Unknown',
      estimated_risk_reduction: riskReductionEstimate(action.impact, isKev),
      references:               refs,
    };
  });

  const kevCount  = recommendations.filter(r => r.kev_status).length;
  const highCount = recommendations.filter(r => r.cvss !== null && r.cvss >= 9).length;
  const aggregateRR = Math.min(60, kevCount * 12 + highCount * 6);

  return ok({
    success:                  true,
    service:                  'CDB-EXEC-P106',
    playbook_id:              `pb_${Date.now().toString(36)}`,
    generated_at:             new Date().toISOString(),
    scope: {
      sector,
      threat_intel_signals:    vulns.length,
      radar_signals:           radarSignals.length,
      customer_assets:         customerAssets.length,
      asm_targets:             asmTargets.length,
    },
    adaptive_risk_score:      adaptiveScore,
    recommendations,
    total_recommendations:    recommendations.length,
    soc_playbook:             adaptive.soc_playbook,
    quick_wins:               adaptive.quick_wins,
    estimated_total_effort:   adaptive.estimated_total_effort,
    aggregate_risk_reduction: aggregateRR > 0
      ? `Up to ${aggregateRR}% risk reduction if all recommendations implemented`
      : 'Risk reduction estimate unavailable — insufficient threat intelligence data',
    note: recommendations.length === 0
      ? 'No threat intelligence data available. Ensure threat_intel table is populated and assets are registered at POST /api/customer/assets.'
      : (adaptive.personalization_note || null),
    data_sources: [
      'CYBERDUDEBIVASH Sentinel APEX Threat Intelligence',
      'CISA Known Exploited Vulnerabilities (KEV)',
      'NVD / CVSS',
      'Cyber Signal Radar',
      'Customer Asset Registry',
    ],
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX AI — P10.6 Playbook Recommendation Engine',
  });
}
