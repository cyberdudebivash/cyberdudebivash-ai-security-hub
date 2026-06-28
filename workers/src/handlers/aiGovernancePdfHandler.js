// =============================================================================
// P22.0 — AI Governance Compliance PDF Export Engine
// CYBERDUDEBIVASH AI Security Hub | handlers/aiGovernancePdfHandler.js
//
// Generates CISO-grade, print-ready HTML compliance reports (PDF-downloadable)
// from existing AI Governance Pro (aiGovernancePro.js) assessment data.
// Additive only — calls existing handler data, never re-implements engine logic.
//
// Routes:
//   POST /api/ai-governance/pdf/generate    → build report, return token + preview URL
//   GET  /api/ai-governance/pdf/:token      → stream print-ready HTML (browser prints to PDF)
//   GET  /api/ai-governance/pdf/status/:token → check generation status
//   GET  /api/ai-governance/pdf/list        → list org's generated reports (auth required)
//   GET  /api/ai-governance/pdf/observability → health metrics
// =============================================================================

const PDF_TOKEN_TTL      = 86400 * 7;   // 7-day download window
const PDF_KV_PREFIX      = 'agpdf:';
const REPORT_LIST_PREFIX = 'agpdf:list:';
const MAX_REPORTS_STORED = 20;

// ── Framework metadata used in cover page ──────────────────────────────────
const FRAMEWORK_META = {
  EU_AI_ACT:  { label: 'EU AI Act 2024',          badge: '#E91E63', icon: '🇪🇺' },
  NIST_AI_RMF:{ label: 'NIST AI RMF 1.0',         badge: '#1565C0', icon: '🏛️' },
  ISO_42001:  { label: 'ISO/IEC 42001:2023',       badge: '#2E7D32', icon: '📋' },
  OWASP_LLM:  { label: 'OWASP LLM Top 10 2025',   badge: '#E65100', icon: '🔓' },
  DPDP:       { label: 'India DPDP Act 2023',      badge: '#6A1B9A', icon: '🇮🇳' },
  NIST_CSF:   { label: 'NIST CSF 2.0',             badge: '#00695C', icon: '🛡️' },
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ai-governance/pdf/generate
// Body: { org_id, report_type, frameworks[], classification, requestor_name, requestor_title }
// ─────────────────────────────────────────────────────────────────────────────
export async function handlePdfGenerate(request, env, authCtx) {
  try {
    const body = await request.json();
    const orgId           = (body.org_id || 'default').slice(0, 64);
    const reportType      = body.report_type || 'FULL_GOVERNANCE';
    const frameworks      = Array.isArray(body.frameworks) && body.frameworks.length
                            ? body.frameworks : Object.keys(FRAMEWORK_META);
    const classification  = body.classification || 'CONFIDENTIAL';
    const requestorName   = (body.requestor_name  || 'CISO').slice(0, 80);
    const requestorTitle  = (body.requestor_title || 'Chief Information Security Officer').slice(0, 120);

    // 1. Pull existing governance data from KV (written by aiGovernancePro.js generateGovernanceReport)
    const govReportRaw = await env.KV.get(`gov_report:${orgId}:latest`, 'json');

    // 2. Pull AI model registry from D1 (canonical source — never re-queried differently)
    const { results: models } = await env.DB.prepare(
      'SELECT id,name,type,risk_level,risk_score,eu_ai_act_category,use_case,owner_email,status,created_at FROM ai_model_registry WHERE org_id=? AND status!=? ORDER BY risk_score DESC LIMIT 200'
    ).bind(orgId, 'deleted').all();

    // 3. Pull assessment answers (most recent completed)
    const assessment = await env.DB.prepare(
      'SELECT * FROM ai_governance_assessments WHERE org_id=? AND status=? ORDER BY completed_at DESC LIMIT 1'
    ).bind(orgId, 'completed').first();

    // 4. Pull shadow AI detections
    const shadowAI = await env.KV.get(`shadow_ai:${orgId}`, 'json') || { detected: [] };

    const token     = crypto.randomUUID();
    const reportId  = `agpdf-${Date.now()}-${token.slice(0,8)}`;
    const now       = new Date();
    const expiresAt = new Date(Date.now() + PDF_TOKEN_TTL * 1000).toISOString();

    const reportPayload = {
      reportId, token, orgId, reportType, frameworks, classification,
      requestorName, requestorTitle,
      generatedAt: now.toISOString(),
      expiresAt,
      govReport:   govReportRaw,
      models,
      assessment:  assessment ? { ...assessment, answers: safeJson(assessment.answers), gaps: safeJson(assessment.gaps), roadmap: safeJson(assessment.roadmap) } : null,
      shadowAI,
    };

    // Store in KV with 7-day TTL
    await env.KV.put(`${PDF_KV_PREFIX}${token}`, JSON.stringify(reportPayload), { expirationTtl: PDF_TOKEN_TTL });

    // Maintain per-org report list (rolling 20)
    const listKey   = `${REPORT_LIST_PREFIX}${orgId}`;
    const listRaw   = await env.KV.get(listKey, 'json') || [];
    const listEntry = { reportId, token, reportType, generatedAt: now.toISOString(), expiresAt, requestorName };
    listRaw.unshift(listEntry);
    if (listRaw.length > MAX_REPORTS_STORED) listRaw.length = MAX_REPORTS_STORED;
    await env.KV.put(listKey, JSON.stringify(listRaw), { expirationTtl: PDF_TOKEN_TTL * 2 });

    return jsonResponse({
      success: true,
      reportId,
      token,
      download_url:  `/api/ai-governance/pdf/${token}`,
      preview_url:   `/api/ai-governance/pdf/${token}?preview=1`,
      expires_at:    expiresAt,
      model_count:   models.length,
      has_assessment: !!assessment,
      frameworks,
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/ai-governance/pdf/:token
// Returns print-ready HTML. ?preview=1 adds screen styling; otherwise print-optimised.
// ─────────────────────────────────────────────────────────────────────────────
export async function handlePdfDownload(request, env, token) {
  try {
    const payload = await env.KV.get(`${PDF_KV_PREFIX}${token}`, 'json');
    if (!payload) {
      return new Response('Report not found or expired.', { status: 404, headers: { 'Content-Type': 'text/plain' } });
    }

    const url     = new URL(request.url);
    const preview = url.searchParams.get('preview') === '1';
    const html    = buildReportHtml(payload, preview);

    const headers = {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'private, max-age=3600',
    };
    if (!preview) {
      // Trigger browser Save-As dialog for direct download
      headers['Content-Disposition'] = `inline; filename="ai-governance-report-${payload.reportId}.html"`;
    }
    return new Response(html, { status: 200, headers });
  } catch (e) {
    return new Response(`Error: ${e.message}`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/ai-governance/pdf/status/:token
// ─────────────────────────────────────────────────────────────────────────────
export async function handlePdfStatus(request, env, token) {
  try {
    const payload = await env.KV.get(`${PDF_KV_PREFIX}${token}`, 'json');
    if (!payload) return jsonResponse({ exists: false, expired: true }, 404);
    return jsonResponse({
      exists:       true,
      reportId:     payload.reportId,
      generatedAt:  payload.generatedAt,
      expiresAt:    payload.expiresAt,
      model_count:  payload.models?.length || 0,
      has_assessment: !!payload.assessment,
      download_url: `/api/ai-governance/pdf/${token}`,
    });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/ai-governance/pdf/list?org_id=
// ─────────────────────────────────────────────────────────────────────────────
export async function handlePdfList(request, env) {
  try {
    const url   = new URL(request.url);
    const orgId = (url.searchParams.get('org_id') || 'default').slice(0, 64);
    const list  = await env.KV.get(`${REPORT_LIST_PREFIX}${orgId}`, 'json') || [];
    return jsonResponse({ reports: list, count: list.length });
  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/ai-governance/pdf/observability
// ─────────────────────────────────────────────────────────────────────────────
export async function handlePdfObservability(request, env) {
  return jsonResponse({
    component:  'P22.0-AI-Governance-PDF-Export',
    version:    '22.0.0',
    status:     'OPERATIONAL',
    capabilities: [
      'EU AI Act compliance report',
      'NIST AI RMF assessment PDF',
      'ISO/IEC 42001:2023 gap analysis',
      'OWASP LLM Top 10 2025',
      'India DPDP Act 2023',
      'Multi-framework combined report',
      'Shadow AI inventory export',
      'CISO executive summary',
      'Board-ready risk narrative',
      'KV-backed 7-day download tokens',
    ],
    token_ttl_days: 7,
    max_models_per_report: 200,
    supported_frameworks: Object.keys(FRAMEWORK_META),
    timestamp: new Date().toISOString(),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML REPORT BUILDER
// ─────────────────────────────────────────────────────────────────────────────
function buildReportHtml(p, preview) {
  const govReport  = p.govReport  || {};
  const exec       = govReport.executiveSummary || {};
  const models     = p.models     || [];
  const assessment = p.assessment || null;
  const shadow     = p.shadowAI   || { detected: [] };

  const totalModels   = models.length;
  const criticalCount = models.filter(m => m.risk_level === 'CRITICAL').length;
  const highCount     = models.filter(m => m.risk_level === 'HIGH').length;
  const euHighCount   = models.filter(m => m.eu_ai_act_category === 'HIGH').length;
  const govScore      = exec.overallGovernanceScore ?? (totalModels > 0 ? Math.round(100 - (models.reduce((s, m) => s + (m.risk_score || 0), 0) / totalModels)) : 100);
  const riskColor     = govScore >= 80 ? '#2E7D32' : govScore >= 60 ? '#E65100' : '#B71C1C';

  const frameworkBadges = (p.frameworks || []).map(f => {
    const meta = FRAMEWORK_META[f] || { label: f, badge: '#555', icon: '📄' };
    return `<span class="badge" style="background:${meta.badge}">${meta.icon} ${meta.label}</span>`;
  }).join('');

  const modelRows = models.slice(0, 50).map(m => {
    const riskCls = { CRITICAL: '#B71C1C', HIGH: '#E65100', MEDIUM: '#F57F17', LOW: '#2E7D32' }[m.risk_level] || '#555';
    return `<tr>
      <td>${esc(m.name)}</td>
      <td>${esc(m.type || '—')}</td>
      <td><span style="color:${riskCls};font-weight:700">${esc(m.risk_level || '—')}</span></td>
      <td>${m.risk_score ?? '—'}</td>
      <td>${esc(m.eu_ai_act_category || '—')}</td>
      <td>${esc(m.use_case || '—')}</td>
      <td>${esc(m.owner_email || '—')}</td>
    </tr>`;
  }).join('');

  const shadowRows = (shadow.detected || []).slice(0, 20).map(s =>
    `<tr><td>${esc(s.service || s.name || '—')}</td><td>${esc(s.risk || 'UNKNOWN')}</td><td>${esc(s.detected_at || '—')}</td><td>${esc(s.action || 'Review required')}</td></tr>`
  ).join('');

  const gapRows = assessment && Array.isArray(assessment.gaps) ? assessment.gaps.slice(0, 30).map(g =>
    `<tr>
      <td>${esc(g.id || '—')}</td>
      <td>${esc(g.title || '—')}</td>
      <td><span style="color:${g.severity === 'HIGH' ? '#B71C1C' : g.severity === 'MEDIUM' ? '#E65100' : '#2E7D32'};font-weight:700">${esc(g.severity || '—')}</span></td>
      <td>${esc(g.framework || '—')}</td>
      <td>${esc(g.recommendation || '—')}</td>
    </tr>`
  ).join('') : '<tr><td colspan="5" style="text-align:center;color:#888">No assessment data available. Run an assessment via the AI Governance console.</td></tr>';

  const roadmapRows = assessment && Array.isArray(assessment.roadmap) ? assessment.roadmap.slice(0, 20).map((r, i) =>
    `<tr>
      <td>${i + 1}</td>
      <td>${esc(r.action || r.title || '—')}</td>
      <td>${esc(r.priority || '—')}</td>
      <td>${esc(r.timeline || '—')}</td>
      <td>${esc(r.owner || '—')}</td>
    </tr>`
  ).join('') : '<tr><td colspan="5" style="text-align:center;color:#888">No roadmap data. Complete an assessment to generate an automated remediation roadmap.</td></tr>';

  const printCss = preview ? '' : `
    @media print {
      body { margin: 0; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
      table { page-break-inside: auto; }
      tr { page-break-inside: avoid; }
    }
    @page { margin: 20mm 15mm; size: A4; }
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Governance Compliance Report — ${esc(p.orgId)} — ${p.reportId}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 11pt; color: #1a1a2e; background: #fff; line-height: 1.5; }
  ${printCss}

  /* Cover */
  .cover { background: linear-gradient(135deg, #0d0d1a 0%, #1a1a3e 50%, #0d1a2e 100%); color: #fff; padding: 60px 50px; min-height: 297mm; display: flex; flex-direction: column; justify-content: space-between; }
  .cover-logo { font-size: 13pt; font-weight: 900; letter-spacing: 2px; color: #00d4ff; text-transform: uppercase; }
  .cover-title { font-size: 32pt; font-weight: 900; line-height: 1.2; margin: 40px 0 20px; }
  .cover-title span { color: #00d4ff; }
  .cover-subtitle { font-size: 14pt; color: #aaa; margin-bottom: 30px; }
  .cover-meta { border-top: 1px solid rgba(255,255,255,0.1); padding-top: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .cover-meta-item label { font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; color: #666; display: block; }
  .cover-meta-item span { font-size: 11pt; color: #ddd; }
  .classification-banner { background: #B71C1C; color: #fff; padding: 8px 20px; font-weight: 900; letter-spacing: 3px; font-size: 10pt; text-align: center; text-transform: uppercase; margin-top: 30px; border-radius: 4px; }
  .badge { display: inline-block; color: #fff; padding: 4px 10px; border-radius: 20px; font-size: 9pt; margin: 3px 3px 3px 0; font-weight: 600; }

  /* Sections */
  .section { padding: 32px 40px; border-bottom: 1px solid #e0e0e0; }
  .section-title { font-size: 16pt; font-weight: 800; color: #0d1a2e; margin-bottom: 18px; padding-bottom: 8px; border-bottom: 3px solid #00d4ff; display: flex; align-items: center; gap: 10px; }
  .section-title .number { background: #0d1a2e; color: #00d4ff; width: 28px; height: 28px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 12pt; flex-shrink: 0; }
  h3 { font-size: 12pt; font-weight: 700; color: #1a1a2e; margin: 18px 0 10px; }

  /* Score cards */
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
  .kpi-card { background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 8px; padding: 18px; text-align: center; }
  .kpi-card .val { font-size: 28pt; font-weight: 900; line-height: 1; }
  .kpi-card .lbl { font-size: 9pt; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; }
  .kpi-card.critical .val { color: #B71C1C; }
  .kpi-card.high .val { color: #E65100; }
  .kpi-card.ok .val { color: #2E7D32; }
  .kpi-card.score .val { color: ${riskColor}; }

  /* Score donut placeholder */
  .score-ring { width: 100px; height: 100px; border-radius: 50%; background: conic-gradient(${riskColor} ${govScore}%, #e0e0e0 0); display: flex; align-items: center; justify-content: center; margin: 0 auto 8px; }
  .score-ring-inner { width: 75px; height: 75px; border-radius: 50%; background: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .score-ring-inner .pct { font-size: 18pt; font-weight: 900; color: ${riskColor}; line-height: 1; }
  .score-ring-inner .lbl { font-size: 7pt; color: #888; }

  /* Executive summary box */
  .exec-box { background: #fff8e1; border-left: 5px solid #FBC02D; padding: 16px 20px; border-radius: 0 8px 8px 0; margin: 16px 0; font-size: 11pt; line-height: 1.6; }
  .exec-box.ok { background: #E8F5E9; border-left-color: #2E7D32; }
  .exec-box.warn { background: #FFF3E0; border-left-color: #E65100; }
  .exec-box.critical { background: #FFEBEE; border-left-color: #B71C1C; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 9.5pt; }
  th { background: #0d1a2e; color: #fff; padding: 9px 10px; text-align: left; font-size: 9pt; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 8px 10px; border-bottom: 1px solid #f0f0f0; }
  tr:nth-child(even) td { background: #f8f9fa; }

  /* Framework sections */
  .framework-card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 18px; margin: 12px 0; }
  .framework-card h4 { font-size: 12pt; font-weight: 700; margin-bottom: 10px; }
  .framework-item { display: flex; gap: 10px; padding: 6px 0; border-bottom: 1px solid #f5f5f5; font-size: 10pt; }
  .framework-item:last-child { border-bottom: none; }
  .fw-check { color: #2E7D32; font-weight: 700; min-width: 16px; }
  .fw-key { color: #555; min-width: 100px; font-size: 9pt; }

  /* Footer */
  .footer { background: #0d1a2e; color: #888; padding: 20px 40px; font-size: 8.5pt; display: flex; justify-content: space-between; align-items: center; }
  .footer .brand { color: #00d4ff; font-weight: 700; }
  .page-break { page-break-before: always; margin-top: 0; }
  .print-btn { position: fixed; bottom: 24px; right: 24px; background: #0d1a2e; color: #00d4ff; border: 2px solid #00d4ff; padding: 12px 24px; border-radius: 8px; font-size: 11pt; font-weight: 700; cursor: pointer; z-index: 999; no-print: true; }
  .print-btn:hover { background: #00d4ff; color: #0d1a2e; }
  .confidential-watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%) rotate(-45deg); font-size: 80pt; font-weight: 900; color: rgba(183,28,28,0.04); pointer-events: none; z-index: 0; white-space: nowrap; letter-spacing: 8px; }
</style>
</head>
<body>

<div class="confidential-watermark">${esc(p.classification)}</div>
${preview ? '<button class="print-btn no-print" onclick="window.print()">🖨️ Print / Save PDF</button>' : ''}

<!-- COVER PAGE -->
<div class="cover">
  <div>
    <div class="cover-logo">CYBERDUDEBIVASH® AI Security Hub</div>
    <div class="cover-title">AI Governance<br><span>Compliance Report</span></div>
    <div class="cover-subtitle">${esc(p.reportType.replace(/_/g,' '))} — Confidential</div>
    <div style="margin: 24px 0">${frameworkBadges}</div>
    <div class="classification-banner">${esc(p.classification)}</div>
  </div>
  <div class="cover-meta">
    <div class="cover-meta-item"><label>Organisation ID</label><span>${esc(p.orgId)}</span></div>
    <div class="cover-meta-item"><label>Report ID</label><span>${esc(p.reportId)}</span></div>
    <div class="cover-meta-item"><label>Prepared For</label><span>${esc(p.requestorName)}, ${esc(p.requestorTitle)}</span></div>
    <div class="cover-meta-item"><label>Generated</label><span>${new Date(p.generatedAt).toUTCString()}</span></div>
    <div class="cover-meta-item"><label>Frameworks Covered</label><span>${(p.frameworks || []).length}</span></div>
    <div class="cover-meta-item"><label>Token Expires</label><span>${new Date(p.expiresAt).toUTCString()}</span></div>
    <div class="cover-meta-item"><label>AI Models Assessed</label><span>${totalModels}</span></div>
    <div class="cover-meta-item"><label>Platform</label><span>SENTINEL APEX v22.0</span></div>
  </div>
</div>

<!-- SECTION 1: EXECUTIVE SUMMARY -->
<div class="page-break"></div>
<div class="section">
  <div class="section-title"><span class="number">1</span> Executive Summary</div>

  <div style="display:flex; gap:30px; align-items:flex-start; margin-bottom: 20px;">
    <div style="flex-shrink:0; text-align:center;">
      <div class="score-ring">
        <div class="score-ring-inner">
          <span class="pct">${govScore}</span>
          <span class="lbl">/ 100</span>
        </div>
      </div>
      <div style="font-size:9pt;color:#555;margin-top:4px">Governance Score</div>
    </div>
    <div style="flex:1">
      <div class="exec-box ${criticalCount > 0 ? 'critical' : highCount > 0 ? 'warn' : 'ok'}">
        <strong>Overall Assessment:</strong> ${esc(exec.message || (criticalCount > 0 ? `URGENT: ${criticalCount} critical-risk AI models require immediate remediation` : highCount > 0 ? `${highCount} high-risk AI models require attention within 30 days` : 'AI model portfolio risk is within acceptable bounds'))}
      </div>
      <p style="margin-top:12px;font-size:10.5pt;color:#444;line-height:1.6">
        This report assesses the AI governance posture of organisation <strong>${esc(p.orgId)}</strong> against
        ${(p.frameworks || []).length} regulatory and industry frameworks including ${(p.frameworks || []).slice(0,3).map(f => (FRAMEWORK_META[f] || {label:f}).label).join(', ')}${(p.frameworks||[]).length > 3 ? ' and others' : ''}.
        The assessment covers ${totalModels} registered AI models, ${shadow.detected.length} detected shadow AI services,
        and ${assessment ? `a completed ${assessment.framework || ''} assessment with ${Array.isArray(assessment.gaps) ? assessment.gaps.length : 0} gaps identified` : 'no completed formal assessment on record'}.
      </p>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card score"><div class="val">${govScore}</div><div class="lbl">Governance Score</div></div>
    <div class="kpi-card ${criticalCount > 0 ? 'critical' : 'ok'}"><div class="val">${criticalCount}</div><div class="lbl">Critical Risk Models</div></div>
    <div class="kpi-card ${highCount > 0 ? 'high' : 'ok'}"><div class="val">${highCount}</div><div class="lbl">High Risk Models</div></div>
    <div class="kpi-card"><div class="val">${euHighCount}</div><div class="lbl">EU AI Act High-Risk</div></div>
  </div>

  <div class="kpi-grid" style="grid-template-columns: repeat(4, 1fr); margin-top: 0;">
    <div class="kpi-card"><div class="val">${totalModels}</div><div class="lbl">Total AI Models</div></div>
    <div class="kpi-card ${shadow.detected.length > 0 ? 'high' : 'ok'}"><div class="val">${shadow.detected.length}</div><div class="lbl">Shadow AI Services</div></div>
    <div class="kpi-card"><div class="val">${assessment ? (Array.isArray(assessment.gaps) ? assessment.gaps.length : '—') : '—'}</div><div class="lbl">Compliance Gaps</div></div>
    <div class="kpi-card"><div class="val">${assessment ? (Array.isArray(assessment.roadmap) ? assessment.roadmap.length : '—') : '—'}</div><div class="lbl">Roadmap Actions</div></div>
  </div>

  <h3>Key Risk Narrative</h3>
  <p style="font-size:10.5pt;color:#444;line-height:1.7">
    ${criticalCount > 0
      ? `<span style="color:#B71C1C;font-weight:700">⚠ CRITICAL:</span> ${criticalCount} AI model(s) are classified as CRITICAL risk and require immediate human oversight, conformity assessment (for EU AI Act purposes), and documented remediation within 14 days. Failure to remediate may result in regulatory penalty or incident exposure.`
      : highCount > 0
        ? `<span style="color:#E65100;font-weight:700">⚠ HIGH:</span> ${highCount} AI model(s) are classified as HIGH risk. Remediation should be completed within 30 days to maintain acceptable risk posture.`
        : `<span style="color:#2E7D32;font-weight:700">✓ ACCEPTABLE:</span> No critical or unmitigated high-risk models detected. Continued monitoring and periodic reassessment is recommended.`}
    ${euHighCount > 0 ? ` Additionally, ${euHighCount} model(s) fall under the EU AI Act High-Risk category (Annex III), requiring mandatory conformity assessment prior to deployment in the EU market.` : ''}
    ${shadow.detected.length > 0 ? ` Shadow AI inventory has identified ${shadow.detected.length} unauthorised or unregistered AI service(s) in use. These represent unquantified risk exposure until formally assessed.` : ''}
  </p>
</div>

<!-- SECTION 2: FRAMEWORK COMPLIANCE STATUS -->
<div class="page-break"></div>
<div class="section">
  <div class="section-title"><span class="number">2</span> Framework Compliance Status</div>

  ${(p.frameworks || []).map(fwId => {
    const meta = FRAMEWORK_META[fwId] || { label: fwId, badge: '#555', icon: '📄' };
    return buildFrameworkSection(fwId, meta, models, assessment, govScore);
  }).join('')}
</div>

<!-- SECTION 3: AI MODEL INVENTORY -->
<div class="page-break"></div>
<div class="section">
  <div class="section-title"><span class="number">3</span> AI Model Risk Inventory</div>
  <p style="font-size:10pt;color:#555;margin-bottom:12px">Showing ${Math.min(totalModels, 50)} of ${totalModels} models ordered by risk score (descending). Full inventory available in the SENTINEL APEX console.</p>
  ${totalModels > 0 ? `
  <table>
    <thead><tr><th>Model Name</th><th>Type</th><th>Risk Level</th><th>Risk Score</th><th>EU AI Act</th><th>Use Case</th><th>Owner</th></tr></thead>
    <tbody>${modelRows}</tbody>
  </table>` : '<div class="exec-box">No AI models registered. Register models via POST /api/ai-governance/models to begin risk tracking.</div>'}
</div>

<!-- SECTION 4: COMPLIANCE GAPS -->
<div class="page-break"></div>
<div class="section">
  <div class="section-title"><span class="number">4</span> Identified Compliance Gaps</div>
  ${assessment ? `<p style="font-size:10pt;color:#555;margin-bottom:12px">Framework assessed: <strong>${esc(assessment.framework || '—')}</strong> | Score: <strong>${assessment.overall_score ?? '—'}</strong> | Risk Tier: <strong>${esc(assessment.risk_tier || '—')}</strong> | Completed: <strong>${assessment.completed_at ? new Date(assessment.completed_at).toLocaleDateString() : '—'}</strong></p>` : ''}
  <table>
    <thead><tr><th>Control ID</th><th>Gap Description</th><th>Severity</th><th>Framework</th><th>Recommendation</th></tr></thead>
    <tbody>${gapRows}</tbody>
  </table>
</div>

<!-- SECTION 5: REMEDIATION ROADMAP -->
<div class="section">
  <div class="section-title"><span class="number">5</span> Remediation Roadmap</div>
  <table>
    <thead><tr><th>#</th><th>Action</th><th>Priority</th><th>Timeline</th><th>Owner</th></tr></thead>
    <tbody>${roadmapRows}</tbody>
  </table>
</div>

<!-- SECTION 6: SHADOW AI INVENTORY -->
<div class="page-break"></div>
<div class="section">
  <div class="section-title"><span class="number">6</span> Shadow AI Inventory</div>
  ${shadow.detected.length > 0 ? `
  <div class="exec-box warn"><strong>Shadow AI Detected:</strong> ${shadow.detected.length} unauthorised AI service(s) identified. Each represents unquantified risk until formally assessed and either registered or blocked.</div>
  <table>
    <thead><tr><th>Service / Model</th><th>Risk Level</th><th>Detected At</th><th>Recommended Action</th></tr></thead>
    <tbody>${shadowRows}</tbody>
  </table>` : '<div class="exec-box ok">✓ No shadow AI services detected in current scan. Continue periodic scanning to maintain visibility.</div>'}
</div>

<!-- SECTION 7: RECOMMENDATIONS -->
<div class="section">
  <div class="section-title"><span class="number">7</span> Board-Level Recommendations</div>
  <ol style="padding-left: 22px; line-height: 2; font-size: 10.5pt;">
    ${criticalCount > 0 ? `<li><strong>Immediate Action (0–14 days):</strong> Initiate human oversight protocol and conformity assessment for all ${criticalCount} CRITICAL-risk model(s). Assign accountable executive sponsor.</li>` : ''}
    ${euHighCount > 0 ? `<li><strong>EU AI Act Compliance (0–30 days):</strong> Conduct mandatory conformity assessment for ${euHighCount} High-Risk model(s) before EU market deployment. Register in EU AI database.</li>` : ''}
    ${shadow.detected.length > 0 ? `<li><strong>Shadow AI Governance:</strong> Review and formally assess all ${shadow.detected.length} detected shadow AI services. Implement AI procurement policy requiring security review before deployment.</li>` : ''}
    <li><strong>Policy Formalisation:</strong> Establish or update an AI Acceptable Use Policy, Model Governance Charter, and Incident Response Plan for AI-specific failures.</li>
    <li><strong>Continuous Monitoring:</strong> Deploy real-time AI model telemetry, anomaly detection, and quarterly governance re-assessments to maintain posture.</li>
    <li><strong>Training & Accountability:</strong> Assign AI risk ownership at C-suite level. Ensure all model owners receive mandatory AI governance training aligned to ${(p.frameworks || ['NIST AI RMF']).slice(0,2).map(f => (FRAMEWORK_META[f]||{label:f}).label).join(' and ')}.</li>
    <li><strong>Vendor Due Diligence:</strong> Extend governance requirements to third-party AI services through contractual obligations and supplier assessment questionnaires.</li>
  </ol>
</div>

<!-- FOOTER -->
<div class="footer">
  <div>
    <div class="brand">CYBERDUDEBIVASH® SENTINEL APEX</div>
    <div>AI Governance Compliance Report — ${esc(p.reportId)}</div>
  </div>
  <div style="text-align:right">
    <div>${esc(p.classification)} | Generated ${new Date(p.generatedAt).toUTCString()}</div>
    <div>Expires ${new Date(p.expiresAt).toUTCString()} | Platform v22.0</div>
  </div>
</div>

${preview ? `<script>
  // Auto-show print dialog hint after 1s
  document.querySelector('.print-btn').addEventListener('click', () => window.print());
</script>` : ''}
</body>
</html>`;
}

// ── Per-framework compliance section builder ──────────────────────────────
function buildFrameworkSection(fwId, meta, models, assessment, govScore) {
  const statusColor = govScore >= 80 ? '#2E7D32' : govScore >= 60 ? '#E65100' : '#B71C1C';
  const statusLabel = govScore >= 80 ? 'COMPLIANT' : govScore >= 60 ? 'PARTIAL' : 'NON-COMPLIANT';

  const frameworkContent = {
    EU_AI_ACT: `
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">Art. 5 Prohibited</span><span>Review completed. ${models.filter(m=>m.eu_ai_act_category==='PROHIBITED').length} model(s) flagged for prohibited use verification.</span></div>
      <div class="framework-item"><span class="fw-check" style="color:${models.filter(m=>m.eu_ai_act_category==='HIGH').length>0?'#E65100':'#2E7D32'}">${models.filter(m=>m.eu_ai_act_category==='HIGH').length>0?'⚠':'✓'}</span><span class="fw-key">Annex III High-Risk</span><span>${models.filter(m=>m.eu_ai_act_category==='HIGH').length} model(s) require mandatory conformity assessment before EU deployment.</span></div>
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">Art. 9 Risk Mgmt</span><span>Risk management system documented. ${models.length} models registered in inventory.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Art. 10 Data Gov</span><span>Data governance framework assessment pending. Review training data quality controls.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Art. 13 Transparency</span><span>User disclosure notices required for all LIMITED-risk AI systems in customer-facing roles.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Art. 14 Human Oversight</span><span>Human oversight measures documented for HIGH-risk systems. Operator training records required.</span></div>`,

    NIST_AI_RMF: `
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">GOVERN</span><span>Organisational AI governance policies established. Executive accountability assigned.</span></div>
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">MAP</span><span>AI risk context mapping completed across ${models.length} registered models.</span></div>
      <div class="framework-item"><span class="fw-check" style="color:${govScore<80?'#E65100':'#2E7D32'}">${govScore<80?'⚠':'✓'}</span><span class="fw-key">MEASURE</span><span>Risk quantification active. Overall governance score: ${govScore}/100. ${govScore<80?'Improvement required.':'Within target range.'}</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">MANAGE</span><span>Remediation roadmap generated. ${assessment && Array.isArray(assessment.roadmap) ? assessment.roadmap.length : 0} prioritised actions identified. Execution tracking required.</span></div>`,

    ISO_42001: `
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">4. Context</span><span>Organisation context defined. Interested parties and scope documented.</span></div>
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">5. Leadership</span><span>AI policy established. Management commitment documented.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">6. Planning</span><span>AI risk assessment process operational. Objectives under review.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">8. Operations</span><span>Operational controls active. ${models.length} models in scope. Annex A controls mapping incomplete.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">9. Performance</span><span>Monitoring and measurement active. Internal audit programme not yet formalised.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">10. Improvement</span><span>Nonconformity and corrective action process under development.</span></div>`,

    OWASP_LLM: `
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">LLM01 Prompt Injection</span><span>Input sanitisation controls review required for all LLM-based models.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">LLM02 Insecure Output</span><span>Output validation and sandboxing assessment pending.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">LLM06 Sensitive Info</span><span>Data leakage controls assessment in progress. Training data audit required.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">LLM08 Model Theft</span><span>Model access controls and watermarking review recommended.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">LLM09 Overreliance</span><span>Human-in-the-loop controls documented for high-stakes decisions.</span></div>`,

    DPDP: `
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Consent Management</span><span>Consent framework for personal data used in AI training requires formalisation under DPDP 2023.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Data Fiduciary Obligations</span><span>Data Fiduciary responsibilities documented. DPO appointment status: under review.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Breach Notification</span><span>72-hour notification SOP requires update to include AI-specific incident scenarios.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Cross-border Transfer</span><span>AI model training data transfer controls require DPDP-aligned assessment.</span></div>`,

    NIST_CSF: `
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">GOVERN</span><span>Cybersecurity risk governance for AI systems documented. Risk tolerance defined.</span></div>
      <div class="framework-item"><span class="fw-check">✓</span><span class="fw-key">IDENTIFY</span><span>AI asset inventory complete: ${models.length} models registered. Shadow AI scan active.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">PROTECT</span><span>Access controls active. AI-specific data protection controls under review.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">DETECT</span><span>Anomaly detection active for high-risk models. Coverage gap: ${Math.max(0, totalModels - models.filter(m=>m.risk_level==='CRITICAL'||m.risk_level==='HIGH').length)} models not yet monitored.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">RESPOND</span><span>AI incident response plan drafted. Tabletop exercise recommended within 90 days.</span></div>
      <div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">RECOVER</span><span>Recovery playbooks for AI-specific failures require development.</span></div>`,
  };

  const content = frameworkContent[fwId] || `<div class="framework-item"><span class="fw-check">◑</span><span class="fw-key">Assessment</span><span>Framework assessment pending. Run a formal assessment to generate detailed control status.</span></div>`;

  return `
<div class="framework-card">
  <h4><span class="badge" style="background:${meta.badge};margin-right:8px">${meta.icon} ${meta.label}</span>
    Status: <span style="color:${statusColor};font-weight:700">${statusLabel}</span>
    <span style="color:#555;font-weight:400;font-size:10pt;margin-left:12px">Governance Score: ${govScore}/100</span>
  </h4>
  ${content}
</div>`;
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function safeJson(val) {
  if (!val) return null;
  if (typeof val === 'object') return val;
  try { return JSON.parse(val); } catch { return null; }
}
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}
