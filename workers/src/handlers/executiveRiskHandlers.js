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

function enterpriseOnly(authCtx) {
  if (authCtx?.isAdmin) return null;
  if (authCtx?.tier === 'ENTERPRISE') return null;
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
  const gate = enterpriseOnly(authCtx);
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
    return ok({ success: false, error: 'Executive dashboard requires PRO or ENTERPRISE plan', upgrade: 'https://tools.cyberdudebivash.com/#pricing' }, 403);
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
  const gate = enterpriseOnly(authCtx);
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
  const gate = enterpriseOnly(authCtx);
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
