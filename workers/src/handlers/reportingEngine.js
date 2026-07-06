/**
 * CYBERDUDEBIVASH® AI Security Hub — v33.0 Phase 3
 * reportingEngine.js — Enterprise Reporting Center
 *
 * APIs:
 *   GET  /api/reports              list own org report jobs
 *   POST /api/reports              create report job
 *   GET  /api/reports/:id          job status + download info
 *   GET  /api/reports/:id/download download report (token-gated)
 *   POST /api/reports/schedule     create scheduled report
 *   GET  /api/reports/templates    list available templates
 */

import { complianceEngine } from '../engine.js';

// MSSP/COMPLIANCE report bodies below interpolate DB-sourced org/customer
// strings into HTML — escape to prevent XSS (mirrors siemExport.js convention).
function escHTML(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const REPORT_TEMPLATES = [
  {
    id: 'tpl-security-posture',
    type: 'SECURITY_POSTURE',
    name: 'Security Posture Report',
    description: 'Overall risk score, top findings, remediation progress, compliance coverage.',
    audience: 'Security Team',
    pages: 4,
    sections: ['Executive Summary','Risk Score Breakdown','Critical Findings','Remediation Progress','Recommendations'],
    available_to: ['pro','enterprise','admin','mssp_admin'],
  },
  {
    id: 'tpl-board',
    type: 'BOARD',
    name: 'Board Executive Report',
    description: 'One-page board-ready security and revenue summary.',
    audience: 'C-Suite / Board',
    pages: 1,
    sections: ['Platform Health','Revenue KPIs','Risk Posture','Strategic Recommendations'],
    available_to: ['enterprise','admin'],
  },
  {
    id: 'tpl-mssp',
    type: 'MSSP',
    name: 'MSSP Customer Report',
    description: 'Per-tenant risk, case status, SLA compliance, action items.',
    audience: 'MSSP Customers',
    pages: 3,
    sections: ['Customer Overview','Risk Dashboard','Open Cases','SLA Compliance','Action Items'],
    available_to: ['mssp_admin','admin'],
  },
  {
    id: 'tpl-cti',
    type: 'CTI',
    name: 'Threat Intelligence Report',
    description: 'Top IOCs, active threat actors, CVE summary, MITRE coverage.',
    audience: 'SOC / Threat Analysts',
    pages: 5,
    sections: ['Threat Landscape','Top IOCs','Threat Actors','CVE Summary','MITRE ATT&CK Coverage'],
    available_to: ['pro','enterprise','admin','mssp_admin'],
  },
  {
    id: 'tpl-compliance',
    type: 'COMPLIANCE',
    name: 'Compliance Report',
    description: 'Framework coverage: SOC2, ISO27001, PCI-DSS, HIPAA, NIST.',
    audience: 'Compliance / Audit Teams',
    pages: 6,
    sections: ['Compliance Score','SOC2 Controls','ISO27001 Controls','PCI-DSS Controls','HIPAA Controls','Gap Analysis'],
    available_to: ['enterprise','admin'],
  },
  {
    id: 'tpl-ai-security',
    type: 'AI_SECURITY',
    name: 'AI Security Report',
    description: 'AI asset inventory, OWASP LLM findings, red team results, governance posture.',
    audience: 'AI / Platform Security Teams',
    pages: 4,
    sections: ['AI Asset Inventory','OWASP LLM Top 10','Red Team Findings','Governance Posture','Remediation Plan'],
    available_to: ['enterprise','admin'],
  },
];

function genJobId() { return 'rpt_' + Date.now().toString(36) + '_' + crypto.randomUUID().slice(0, 8); }
function genToken() { return crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, ''); }

// `available_to`/`roles` arrays mix two things that used to both be broken:
// lowercase tier names ('pro','enterprise') compared against req.user.tier,
// which is UPPERCASE by DB CHECK constraint (schema_master.sql) — so the
// tier check never matched anyone, even genuine paying customers — and
// role names ('admin','mssp_admin') compared against req.user.role, which
// is never populated anywhere in the codebase (no JWT claim, no DB column)
// — so that check never matched anyone either, including real admins. This
// made every report type and the whole scheduling feature 100% unreachable
// at every tier. Fixed to compare tiers case-insensitively and to resolve
// the two role concepts onto mechanisms that actually exist: 'admin' means
// the platform-owner ADMIN_KEY bypass (isAdmin), 'mssp_admin' means a real
// paying MSSP-tier customer. (2026-07-06 revenue-mechanisms audit, P2-7.)
function hasAccess(allowList, req) {
  if (!req?.user) return false;
  if (req.user.isAdmin === true) return true;
  const tier = String(req.user.tier || '').toUpperCase();
  if (allowList.includes('mssp_admin') && tier === 'MSSP') return true;
  return allowList.some(entry => entry.toUpperCase() === tier);
}

function requireRole(req, roles) {
  return hasAccess(roles, req);
}

function canAccessReportType(type, req) {
  const tpl = REPORT_TEMPLATES.find(t => t.type === type);
  if (!tpl) return false;
  return hasAccess(tpl.available_to, req);
}

/**
 * Shared print-ready HTML report shell (CSS + header/footer chrome).
 * This is the platform's single "PDF engine" — Workers has no binary PDF
 * library, so reports render as styled, @media-print-ready HTML that browsers
 * print/save-as-PDF. Reused by SIEM Export's `executive_pdf` format — do not
 * fork another copy of this template elsewhere.
 */
export function buildReportShell({ brandName, primaryColor, title, metaLine, bodyHTML, footerNote }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
  :root { --primary: ${primaryColor}; --dark: #0a0e1a; --surface: #0f1729; --border: #1e293b; --text: #e2e8f0; --muted: #64748b; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; background: var(--dark); color: var(--text); padding: 32px; }
  .header { border-bottom: 2px solid var(--primary); padding-bottom: 16px; margin-bottom: 32px; }
  .header h1 { font-size: 24px; font-weight: 800; color: var(--primary); }
  .header .meta { font-size: 12px; color: var(--muted); margin-top: 6px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 32px; }
  .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .kpi-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }
  .kpi-value { font-size: 28px; font-weight: 800; margin: 4px 0; }
  .kpi-sub { font-size: 11px; color: var(--muted); }
  .section { margin-bottom: 28px; }
  .section h2 { font-size: 16px; font-weight: 700; color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: var(--surface); padding: 8px 12px; text-align: left; font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: 700; }
  .critical { background: #ef444433; color: #ef4444; }
  .high { background: #f9731633; color: #f97316; }
  .medium { background: #eab30833; color: #eab308; }
  .low { background: #22c55e33; color: #22c55e; }
  .footer { margin-top: 48px; border-top: 1px solid var(--border); padding-top: 16px; font-size: 11px; color: var(--muted); text-align: center; }
  @media print { body { background: white; color: black; } .header h1 { color: var(--primary); } }
</style>
</head>
<body>
<div class="header">
  <h1>${brandName}</h1>
  <div class="meta">${metaLine}</div>
</div>
${bodyHTML}
<div class="footer">
  ${footerNote || `${brandName} · Confidential · CYBERDUDEBIVASH® Platform v33.0`}
</div>
</body></html>`;
}

/**
 * Slide-deck-style HTML export ("PowerPoint" format). Shares the same
 * print-to-PDF mechanism as buildReportShell — Workers has no binary
 * PDF/PPTX library, so the deck renders as styled HTML with one element per
 * slide: navigable on-screen (buttons / arrow keys) and paginated via
 * @media print for a "print → Save as PDF" export. Consumes the SAME
 * bodyHTML produced by generateReportHTML's existing report-type branches —
 * split into slides by its top-level .kpi-grid/.section blocks — so it adds
 * zero duplicate report-type logic.
 */
export function buildSlideDeckShell({ brandName, primaryColor, title, metaLine, bodyHTML, footerNote }) {
  const slides = bodyHTML
    .split(/(?=<div class="(?:kpi-grid|section)">)/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => `<section class="slide">${s}</section>`)
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
  :root { --primary: ${primaryColor}; --dark: #0a0e1a; --surface: #0f1729; --border: #1e293b; --text: #e2e8f0; --muted: #64748b; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html, body { background: var(--dark); color: var(--text); font-family: system-ui, sans-serif; }
  .deck { position: relative; }
  .slide { display: none; flex-direction: column; justify-content: center; min-height: 100vh; padding: 56px 64px; }
  .slide.active { display: flex; }
  .slide.title-slide, .slide.closing-slide { align-items: center; text-align: center; }
  .slide h1 { font-size: 36px; font-weight: 800; color: var(--primary); margin-bottom: 12px; }
  .slide .meta { font-size: 13px; color: var(--muted); }
  .kpi-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 32px; }
  .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .kpi-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }
  .kpi-value { font-size: 28px; font-weight: 800; margin: 4px 0; }
  .kpi-sub { font-size: 11px; color: var(--muted); }
  .section h2 { font-size: 22px; font-weight: 700; color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: var(--surface); padding: 8px 12px; text-align: left; font-weight: 600; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 10px; font-weight: 700; }
  .critical { background: #ef444433; color: #ef4444; }
  .high { background: #f9731633; color: #f97316; }
  .medium { background: #eab30833; color: #eab308; }
  .low { background: #22c55e33; color: #22c55e; }
  .nav-bar { position: fixed; bottom: 0; left: 0; right: 0; display: flex; align-items: center; justify-content: center; gap: 16px; padding: 14px; background: var(--surface); border-top: 1px solid var(--border); font-size: 13px; }
  .nav-bar button { background: var(--primary); color: #fff; border: none; border-radius: 6px; padding: 6px 16px; font-size: 13px; cursor: pointer; }
  .nav-bar button:disabled { opacity: .4; cursor: default; }
  .slide-counter { color: var(--muted); }
  .footer-note { font-size: 11px; color: var(--muted); margin-top: 24px; }
  @media print {
    body { background: white; color: black; }
    .nav-bar { display: none; }
    .slide { display: flex !important; page-break-after: always; }
    .slide h1 { color: var(--primary); }
  }
</style>
</head>
<body>
<div class="deck">
  <section class="slide title-slide active">
    <h1>${brandName}</h1>
    <div class="meta">${metaLine}</div>
  </section>
  ${slides}
  <section class="slide closing-slide">
    <h1>${brandName}</h1>
    <div class="footer-note">${footerNote || `${brandName} · Confidential · CYBERDUDEBIVASH® Platform v33.0`}</div>
  </section>
</div>
<div class="nav-bar">
  <button id="rdPrev" onclick="rdNav(-1)">&larr; Prev</button>
  <span class="slide-counter"><span id="rdNum">1</span> / <span id="rdTotal"></span></span>
  <button id="rdNext" onclick="rdNav(1)">Next &rarr;</button>
</div>
<script>
(function () {
  var slides = document.querySelectorAll('.slide');
  var i = 0;
  document.getElementById('rdTotal').textContent = slides.length;
  function render() {
    slides.forEach(function (s, idx) { s.classList.toggle('active', idx === i); });
    document.getElementById('rdNum').textContent = i + 1;
    document.getElementById('rdPrev').disabled = i === 0;
    document.getElementById('rdNext').disabled = i === slides.length - 1;
  }
  window.rdNav = function (delta) {
    i = Math.max(0, Math.min(slides.length - 1, i + delta));
    render();
  };
  document.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowRight') rdNav(1);
    if (e.key === 'ArrowLeft') rdNav(-1);
  });
  render();
})();
</script>
</body></html>`;
}

/**
 * Generate in-memory HTML report content from existing D1 data.
 */
async function generateReportHTML(type, orgId, config, env, actorUserId, format) {
  const db = env.DB;
  const ts = new Date().toLocaleString();

  // Common data gathering
  let riskScore = 50, criticalCount = 0, highCount = 0, totalScans = 0;
  try {
    const scanStats = await db.prepare(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical_ct,
              SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high_ct,
              AVG(risk_score) as avg_risk
       FROM scan_results WHERE org_id = ? AND created_at >= datetime('now','-30 days')`
    ).bind(orgId).first();
    totalScans = scanStats?.total ?? 0;
    criticalCount = scanStats?.critical_ct ?? 0;
    highCount = scanStats?.high_ct ?? 0;
    riskScore = Math.round(scanStats?.avg_risk ?? 50);
  } catch (_) {}

  const brandName = config?.brand_name || 'CYBERDUDEBIVASH® AI Security Hub';
  const primaryColor = config?.primary_color || '#6366f1';

  let bodyHTML = '';

  if (type === 'SECURITY_POSTURE') {
    const riskColor = riskScore >= 80 ? '#ef4444' : riskScore >= 60 ? '#f97316' : riskScore >= 40 ? '#eab308' : '#22c55e';
    bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Risk Score</div><div class="kpi-value" style="color:${riskColor}">${riskScore}/100</div><div class="kpi-sub">30-day average</div></div>
  <div class="kpi"><div class="kpi-label">Total Scans</div><div class="kpi-value">${totalScans}</div><div class="kpi-sub">Last 30 days</div></div>
  <div class="kpi"><div class="kpi-label">Critical Findings</div><div class="kpi-value" style="color:#ef4444">${criticalCount}</div><div class="kpi-sub">Risk score ≥ 80</div></div>
  <div class="kpi"><div class="kpi-label">High Findings</div><div class="kpi-value" style="color:#f97316">${highCount}</div><div class="kpi-sub">Risk score ≥ 60</div></div>
</div>
<div class="section">
  <h2>Executive Summary</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">
    Over the past 30 days, the platform completed <strong>${totalScans}</strong> security scans for organization <strong>${orgId}</strong>,
    yielding an average risk score of <strong>${riskScore}/100</strong>.
    ${criticalCount > 0 ? `<strong style="color:#ef4444">${criticalCount} critical findings</strong> require immediate attention.` : 'No critical findings were detected.'}
    ${highCount > 0 ? `Additionally, <strong style="color:#f97316">${highCount} high-severity findings</strong> should be addressed within 24 hours.` : ''}
  </p>
</div>
<div class="section">
  <h2>Recommendations</h2>
  <table><thead><tr><th>#</th><th>Priority</th><th>Recommendation</th></tr></thead><tbody>
    ${criticalCount > 0 ? '<tr><td>1</td><td><span class="badge critical">CRITICAL</span></td><td>Address all critical findings immediately — open SOC cases for each.</td></tr>' : ''}
    ${highCount > 0 ? '<tr><td>2</td><td><span class="badge high">HIGH</span></td><td>Remediate high-severity findings within 24 hours. Assign owners in SOC dashboard.</td></tr>' : ''}
    <tr><td>3</td><td><span class="badge medium">MEDIUM</span></td><td>Increase scan frequency to daily for highest-risk assets.</td></tr>
    <tr><td>4</td><td><span class="badge low">LOW</span></td><td>Enable continuous monitoring on all production domains.</td></tr>
  </tbody></table>
</div>`;
  } else if (type === 'BOARD') {
    bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Security Score</div><div class="kpi-value">${100 - riskScore}%</div><div class="kpi-sub">Platform health</div></div>
  <div class="kpi"><div class="kpi-label">Scans Completed</div><div class="kpi-value">${totalScans}</div><div class="kpi-sub">This month</div></div>
  <div class="kpi"><div class="kpi-label">Critical Incidents</div><div class="kpi-value" style="color:#ef4444">${criticalCount}</div><div class="kpi-sub">Requiring action</div></div>
  <div class="kpi"><div class="kpi-label">Platform Status</div><div class="kpi-value" style="color:#22c55e;font-size:18px;">OPERATIONAL</div><div class="kpi-sub">All systems</div></div>
</div>
<div class="section">
  <h2>Board Summary</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">
    The CYBERDUDEBIVASH® AI Security Hub platform is operating normally. Security posture score is <strong>${100 - riskScore}%</strong>, reflecting
    ${criticalCount === 0 ? 'no unresolved critical incidents' : `${criticalCount} open critical items under active remediation`}.
    The platform processed ${totalScans} security scans this period, maintaining continuous threat monitoring across all registered assets.
  </p>
</div>`;
  } else if (type === 'MSSP') {
    const customerId = config?.customer_id || null;
    let customer = null;
    if (customerId && actorUserId) {
      customer = await db.prepare(
        `SELECT * FROM mssp_customers WHERE (id = ? OR org_slug = ?) AND partner_id = ?`
      ).bind(customerId, customerId, actorUserId).first().catch(() => null);
    }

    if (!customer) {
      bodyHTML = `
<div class="section">
  <h2>MSSP Customer Report</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">
    No managed tenant specified. Provide <code>config.customer_id</code> (an MSSP-managed
    customer ID or org slug owned by this partner account) when creating this report to
    generate a per-tenant customer report.
  </p>
</div>`;
    } else {
      let scanMetrics = { total: 0, critical: 0, high: 0, avg_risk: 0 };
      try {
        const sQ = await db.prepare(`
          SELECT COUNT(*) as total,
                 SUM(CASE WHEN risk_level='critical' THEN 1 ELSE 0 END) as critical,
                 SUM(CASE WHEN risk_level='high' THEN 1 ELSE 0 END) as high,
                 AVG(risk_score) as avg_risk
          FROM scan_results WHERE org_id = ?
        `).bind(customer.id).first();
        if (sQ) scanMetrics = { total: sQ.total || 0, critical: sQ.critical || 0, high: sQ.high || 0, avg_risk: Math.round(sQ.avg_risk || 0) };
      } catch (_) {}

      let assetCount = 0;
      try {
        const aQ = await db.prepare(`SELECT COUNT(*) as cnt FROM customer_assets WHERE customer_id = ?`).bind(customer.id).first();
        assetCount = aQ?.cnt || 0;
      } catch (_) {}

      const actionItems = scanMetrics.critical > 0
        ? ['Open SOC cases for all critical findings', 'Notify customer security contact within SLA window', 'Schedule remediation review call']
        : scanMetrics.high > 0
        ? ['Assign owners to high-severity findings', 'Confirm remediation ETA with customer']
        : ['Maintain current monitoring cadence', 'Continue scheduled quarterly review'];

      bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Risk Score</div><div class="kpi-value">${customer.risk_score || 0}/100</div><div class="kpi-sub">Current</div></div>
  <div class="kpi"><div class="kpi-label">Compliance Score</div><div class="kpi-value">${customer.compliance_score || 0}%</div><div class="kpi-sub">Benchmark</div></div>
  <div class="kpi"><div class="kpi-label">Assets Monitored</div><div class="kpi-value">${assetCount}</div><div class="kpi-sub">Active</div></div>
  <div class="kpi"><div class="kpi-label">MRR</div><div class="kpi-value">$${((customer.mrr_cents || 0) / 100).toLocaleString()}</div><div class="kpi-sub">Monthly</div></div>
</div>
<div class="section">
  <h2>Customer Overview</h2>
  <table><tbody>
    <tr><td>Organization</td><td>${escHTML(customer.org_name || customer.id)}</td></tr>
    <tr><td>Tier</td><td>${escHTML(customer.tier || 'N/A')}</td></tr>
    <tr><td>Status</td><td>${escHTML(customer.status || 'N/A')}</td></tr>
    <tr><td>Customer Since</td><td>${escHTML(customer.created_at || 'N/A')}</td></tr>
  </tbody></table>
</div>
<div class="section">
  <h2>Risk Dashboard</h2>
  <table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>
    <tr><td>Total Scans</td><td>${scanMetrics.total}</td></tr>
    <tr><td>Critical Findings</td><td>${scanMetrics.critical}</td></tr>
    <tr><td>High Findings</td><td>${scanMetrics.high}</td></tr>
    <tr><td>Average Risk Score</td><td>${scanMetrics.avg_risk}/100</td></tr>
  </tbody></table>
</div>
<div class="section">
  <h2>Open Cases &amp; SLA Compliance</h2>
  <p style="font-size:12px;color:#64748b;">SOC case-management integration is not yet enabled for this tenant — case and SLA metrics will appear here once ticketing is connected.</p>
</div>
<div class="section">
  <h2>Action Items</h2>
  <table><thead><tr><th>#</th><th>Action</th></tr></thead><tbody>
    ${actionItems.map((a, i) => `<tr><td>${i + 1}</td><td>${escHTML(a)}</td></tr>`).join('')}
  </tbody></table>
</div>`;
    }
  } else if (type === 'COMPLIANCE') {
    const frameworks = [['soc2', 'SOC 2'], ['iso27001', 'ISO 27001'], ['pcidss', 'PCI-DSS'], ['hipaa', 'HIPAA']];
    const assessments = frameworks.map(([key, label]) => ({ label, result: complianceEngine(orgId, key) }));
    const avgScore = Math.round(assessments.reduce((a, x) => a + (x.result.compliance_score || 0), 0) / assessments.length);
    const totalCritical = assessments.reduce((a, x) => a + (x.result.critical_gaps_total || 0), 0);
    const roadmap = [...new Set(assessments.flatMap(x => x.result.remediation_roadmap || []))].slice(0, 6);

    bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Compliance Score</div><div class="kpi-value">${avgScore}%</div><div class="kpi-sub">Avg across frameworks</div></div>
  <div class="kpi"><div class="kpi-label">Frameworks Assessed</div><div class="kpi-value">${assessments.length}</div><div class="kpi-sub">SOC2, ISO27001, PCI-DSS, HIPAA</div></div>
  <div class="kpi"><div class="kpi-label">Critical Gaps</div><div class="kpi-value" style="color:#ef4444">${totalCritical}</div><div class="kpi-sub">Across all frameworks</div></div>
  <div class="kpi"><div class="kpi-label">Org</div><div class="kpi-value" style="font-size:16px;">${escHTML(orgId)}</div><div class="kpi-sub">Assessed entity</div></div>
</div>
${assessments.map(({ label, result }) => `
<div class="section">
  <h2>${escHTML(label)} Controls</h2>
  <p style="font-size:12px;color:#94a3b8;margin-bottom:8px;">${escHTML(result.summary)}</p>
  <table><thead><tr><th>Domain</th><th>Benchmark</th><th>Controls</th><th>Critical Gaps</th></tr></thead><tbody>
    ${(result.domain_assessments || []).map(d => `<tr><td>${escHTML(d.domain)}</td><td>${d.compliance_percent}%</td><td>${d.controls_assessed}</td><td>${d.critical_gaps}</td></tr>`).join('')}
  </tbody></table>
</div>`).join('')}
<div class="section">
  <h2>Gap Analysis &amp; Remediation Roadmap</h2>
  <table><thead><tr><th>#</th><th>Action</th></tr></thead><tbody>
    ${roadmap.map((r, i) => `<tr><td>${i + 1}</td><td>${escHTML(r)}</td></tr>`).join('')}
  </tbody></table>
  <p style="font-size:11px;color:#64748b;margin-top:8px;">Compliance percentages reflect industry-benchmark readiness (Gartner/ISACA 2024 methodology) per framework and require a completed assessment questionnaire to certify actual organizational scores.</p>
</div>`;
  } else if (type === 'CTI') {
    // Threat Intelligence report — real data from the threat_intel ingestion
    // pipeline (NVD/CISA KEV) and apt_profiles. Columns queried here are the
    // ones threatIngestion.js storeInD1() actually writes — do not "improve"
    // them to is_kev/mitre_tactics, which do not exist on this table.
    let cves = [], aptGroups = [], sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    let totalCves = 0, kevCount = 0, exploitedCount = 0;
    try {
      const [top, stats, apts] = await Promise.all([
        db.prepare(
          `SELECT id, title, severity, cvss, epss_score, exploit_status, known_ransomware,
                  actively_exploited, published_at, iocs
           FROM threat_intel
           WHERE ingested_at >= datetime('now','-30 days')
           ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END,
                    COALESCE(cvss, 0) DESC
           LIMIT 15`
        ).all().catch(() => ({ results: [] })),
        db.prepare(
          `SELECT severity, COUNT(*) as ct,
                  SUM(COALESCE(actively_exploited,0)) as exploited,
                  SUM(CASE WHEN exploit_status='confirmed' THEN 1 ELSE 0 END) as confirmed
           FROM threat_intel
           WHERE ingested_at >= datetime('now','-30 days')
           GROUP BY severity`
        ).all().catch(() => ({ results: [] })),
        db.prepare(
          `SELECT group_name, origin_country, target_sectors, typical_cves, mitre_ttps, activity_level, last_seen
           FROM apt_profiles WHERE activity_level = 'ACTIVE'
           ORDER BY last_seen DESC LIMIT 8`
        ).all().catch(() => ({ results: [] })),
      ]);
      cves = top?.results || [];
      aptGroups = apts?.results || [];
      for (const row of (stats?.results || [])) {
        const sev = String(row.severity || '').toUpperCase();
        if (sevCounts[sev] !== undefined) sevCounts[sev] = row.ct || 0;
        totalCves += row.ct || 0;
        exploitedCount += row.exploited || 0;
        kevCount += row.confirmed || 0;
      }
    } catch (_) {}

    const iocRows = [];
    for (const c of cves) {
      let parsed = [];
      try { parsed = JSON.parse(c.iocs || '[]'); } catch {}
      for (const ioc of parsed.slice(0, 3)) iocRows.push({ cve: c.id, ioc, severity: c.severity });
      if (iocRows.length >= 10) break;
    }

    const ttpSet = new Map();
    for (const g of aptGroups) {
      let ttps = [];
      try { ttps = JSON.parse(g.mitre_ttps || '[]'); } catch {}
      for (const t of ttps) {
        if (!ttpSet.has(t)) ttpSet.set(t, []);
        ttpSet.get(t).push(g.group_name);
      }
    }

    const sevBadge = s => `<span class="badge ${String(s || '').toLowerCase()}">${escHTML(String(s || 'N/A').toUpperCase())}</span>`;

    bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">CVEs Ingested (30d)</div><div class="kpi-value">${totalCves}</div><div class="kpi-sub">NVD + CISA KEV pipeline</div></div>
  <div class="kpi"><div class="kpi-label">Critical</div><div class="kpi-value" style="color:#ef4444">${sevCounts.CRITICAL}</div><div class="kpi-sub">Severity CRITICAL</div></div>
  <div class="kpi"><div class="kpi-label">Actively Exploited</div><div class="kpi-value" style="color:#f97316">${exploitedCount}</div><div class="kpi-sub">EPSS/KEV-derived</div></div>
  <div class="kpi"><div class="kpi-label">Active APT Groups</div><div class="kpi-value">${aptGroups.length}</div><div class="kpi-sub">Tracked profiles</div></div>
</div>
<div class="section">
  <h2>Threat Landscape (Last 30 Days)</h2>
  ${totalCves === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No CVEs have been ingested in the last 30 days. The threat-intel ingestion pipeline runs hourly — this report will populate automatically after the next ingestion cycle.</p>`
    : `<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>
        ${Object.entries(sevCounts).map(([s, ct]) => `<tr><td>${sevBadge(s)}</td><td>${ct}</td></tr>`).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>CVE Summary — Top Threats</h2>
  ${cves.length === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No CVE records available for this period.</p>`
    : `<table><thead><tr><th>CVE</th><th>Title</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Exploited</th></tr></thead><tbody>
        ${cves.map(c => `<tr>
          <td>${escHTML(c.id)}</td>
          <td>${escHTML(String(c.title || '').slice(0, 90))}</td>
          <td>${sevBadge(c.severity)}</td>
          <td>${c.cvss != null ? Number(c.cvss).toFixed(1) : '—'}</td>
          <td>${c.epss_score != null ? (Number(c.epss_score) * 100).toFixed(1) + '%' : '—'}</td>
          <td>${c.actively_exploited ? 'YES' : c.exploit_status === 'confirmed' ? 'CONFIRMED' : '—'}</td>
        </tr>`).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>Top IOCs</h2>
  ${iocRows.length === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No extracted IOCs are associated with this period's CVE records. IOC extraction depends on source advisories publishing indicators.</p>`
    : `<table><thead><tr><th>Indicator</th><th>Source CVE</th><th>Severity</th></tr></thead><tbody>
        ${iocRows.map(r => `<tr><td style="font-family:monospace">${escHTML(String(r.ioc).slice(0, 80))}</td><td>${escHTML(r.cve)}</td><td>${sevBadge(r.severity)}</td></tr>`).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>Threat Actors</h2>
  ${aptGroups.length === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No active APT group profiles are currently tracked. Profiles populate from the APT intelligence engine as attribution data becomes available.</p>`
    : `<table><thead><tr><th>Group</th><th>Origin</th><th>Target Sectors</th><th>Activity</th><th>Last Seen</th></tr></thead><tbody>
        ${aptGroups.map(g => {
          let sectors = []; try { sectors = JSON.parse(g.target_sectors || '[]'); } catch {}
          return `<tr><td>${escHTML(g.group_name)}</td><td>${escHTML(g.origin_country || '—')}</td><td>${escHTML(sectors.slice(0, 4).join(', ') || '—')}</td><td>${escHTML(g.activity_level)}</td><td>${escHTML(g.last_seen || '—')}</td></tr>`;
        }).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>MITRE ATT&amp;CK Coverage</h2>
  ${ttpSet.size === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No MITRE TTP mappings available — TTP coverage derives from tracked APT group profiles, which are not yet populated for this period.</p>`
    : `<table><thead><tr><th>Technique</th><th>Used By</th></tr></thead><tbody>
        ${[...ttpSet.entries()].slice(0, 12).map(([t, groups]) => `<tr><td>${escHTML(t)}</td><td>${escHTML(groups.join(', '))}</td></tr>`).join('')}
      </tbody></table>`}
</div>`;
  } else if (type === 'AI_SECURITY') {
    // AI Security report — real data from the AI SPM tables (ai_assets,
    // ai_findings, ai_redteam_attempts, ai_governance_assessments).
    let assets = [], findingsBySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    let openFindings = [], redteam = { total: 0, successful: 0 }, governance = [];
    let totalAssets = 0, publicAssets = 0;
    try {
      const [assetRows, findingStats, findingRows, rtRow, govRows] = await Promise.all([
        db.prepare(
          `SELECT name, asset_type, provider, exposure, risk_score, security_score, status
           FROM ai_assets WHERE org_id = ? AND status = 'active'
           ORDER BY risk_score DESC LIMIT 12`
        ).bind(orgId).all().catch(() => ({ results: [] })),
        db.prepare(
          `SELECT f.severity, COUNT(*) as ct
           FROM ai_findings f JOIN ai_assets a ON f.asset_id = a.id
           WHERE a.org_id = ? AND f.status = 'open' GROUP BY f.severity`
        ).bind(orgId).all().catch(() => ({ results: [] })),
        db.prepare(
          `SELECT f.category, f.title, f.severity, f.owasp_ref, a.name as asset_name
           FROM ai_findings f JOIN ai_assets a ON f.asset_id = a.id
           WHERE a.org_id = ? AND f.status = 'open'
           ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END
           LIMIT 12`
        ).bind(orgId).all().catch(() => ({ results: [] })),
        db.prepare(
          `SELECT COUNT(*) as total, SUM(success) as successful
           FROM ai_redteam_attempts rt JOIN ai_redteam_engagements e ON rt.engagement_id = e.id
           WHERE e.org_id = ?`
        ).bind(orgId).first().catch(() => null),
        db.prepare(
          `SELECT framework, overall_score, risk_tier, status
           FROM ai_governance_assessments WHERE org_id = ?
           ORDER BY created_at DESC LIMIT 6`
        ).bind(orgId).all().catch(() => ({ results: [] })),
      ]);
      assets = assetRows?.results || [];
      openFindings = findingRows?.results || [];
      governance = govRows?.results || [];
      for (const r of (findingStats?.results || [])) {
        const sev = String(r.severity || '').toUpperCase();
        if (findingsBySev[sev] !== undefined) findingsBySev[sev] = r.ct || 0;
      }
      if (rtRow) redteam = { total: rtRow.total || 0, successful: rtRow.successful || 0 };
      totalAssets = assets.length;
      publicAssets = assets.filter(a => a.exposure === 'public').length;
    } catch (_) {}

    const totalOpen = Object.values(findingsBySev).reduce((a, b) => a + b, 0);
    const sevBadge = s => `<span class="badge ${String(s || '').toLowerCase()}">${escHTML(String(s || 'N/A').toUpperCase())}</span>`;

    bodyHTML = `
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">AI Assets</div><div class="kpi-value">${totalAssets}</div><div class="kpi-sub">${publicAssets} publicly exposed</div></div>
  <div class="kpi"><div class="kpi-label">Open Findings</div><div class="kpi-value" style="color:${totalOpen > 0 ? '#f97316' : '#22c55e'}">${totalOpen}</div><div class="kpi-sub">${findingsBySev.CRITICAL} critical</div></div>
  <div class="kpi"><div class="kpi-label">Red Team Attempts</div><div class="kpi-value">${redteam.total}</div><div class="kpi-sub">${redteam.successful} successful breaches</div></div>
  <div class="kpi"><div class="kpi-label">Governance Assessments</div><div class="kpi-value">${governance.length}</div><div class="kpi-sub">NIST AI RMF · ISO 42001 · EU AI Act</div></div>
</div>
<div class="section">
  <h2>AI Asset Inventory</h2>
  ${assets.length === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No AI assets registered for this organization yet. Register assets via the AI SPM dashboard or POST /api/aispm/assets — this report populates from the live asset inventory.</p>`
    : `<table><thead><tr><th>Asset</th><th>Type</th><th>Provider</th><th>Exposure</th><th>Risk</th><th>Security Score</th></tr></thead><tbody>
        ${assets.map(a => `<tr>
          <td>${escHTML(a.name)}</td><td>${escHTML(a.asset_type)}</td><td>${escHTML(a.provider || '—')}</td>
          <td>${escHTML(a.exposure)}</td><td>${a.risk_score}/100</td><td>${a.security_score}/100</td>
        </tr>`).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>OWASP LLM Top 10 Findings</h2>
  ${openFindings.length === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No open AI security findings. Findings appear here after AI security scans detect OWASP LLM Top 10 or governance-framework issues.</p>`
    : `<table><thead><tr><th>Category</th><th>Finding</th><th>Asset</th><th>Severity</th></tr></thead><tbody>
        ${openFindings.map(f => `<tr>
          <td>${escHTML(f.owasp_ref || f.category)}</td><td>${escHTML(String(f.title).slice(0, 80))}</td>
          <td>${escHTML(f.asset_name || '—')}</td><td>${sevBadge(f.severity)}</td>
        </tr>`).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>Red Team Findings</h2>
  ${redteam.total === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No AI red team engagements recorded yet. Run an engagement from the AI Red Team platform to populate adversarial-testing results here.</p>`
    : `<p style="font-size:13px;color:#94a3b8;line-height:1.6;">
        <strong>${redteam.total}</strong> adversarial attempts executed across this organization's engagements;
        <strong style="color:${redteam.successful > 0 ? '#ef4444' : '#22c55e'}">${redteam.successful}</strong> succeeded.
        ${redteam.successful > 0 ? 'Successful attempts indicate exploitable weaknesses — review the engagement detail view and prioritize the mapped remediations.' : 'No successful breaches — current guardrails withstood all attempted attacks.'}
      </p>`}
</div>
<div class="section">
  <h2>Governance Posture</h2>
  ${governance.length === 0
    ? `<p style="font-size:13px;color:#94a3b8;">No governance assessments completed yet. Run a NIST AI RMF, ISO 42001, or EU AI Act assessment from the AI Governance Center to populate this section.</p>`
    : `<table><thead><tr><th>Framework</th><th>Score</th><th>Risk Tier</th><th>Status</th></tr></thead><tbody>
        ${governance.map(g => `<tr><td>${escHTML(g.framework)}</td><td>${g.overall_score}/100</td><td>${escHTML(g.risk_tier)}</td><td>${escHTML(g.status)}</td></tr>`).join('')}
      </tbody></table>`}
</div>
<div class="section">
  <h2>Remediation Plan</h2>
  <table><thead><tr><th>#</th><th>Priority</th><th>Action</th></tr></thead><tbody>
    ${findingsBySev.CRITICAL > 0 ? `<tr><td>1</td><td>${sevBadge('CRITICAL')}</td><td>Remediate ${findingsBySev.CRITICAL} critical AI finding(s) immediately — these represent actively exploitable AI attack surface.</td></tr>` : ''}
    ${findingsBySev.HIGH > 0 ? `<tr><td>2</td><td>${sevBadge('HIGH')}</td><td>Address ${findingsBySev.HIGH} high-severity finding(s) within 7 days.</td></tr>` : ''}
    ${publicAssets > 0 ? `<tr><td>3</td><td>${sevBadge('MEDIUM')}</td><td>Review the ${publicAssets} publicly exposed AI asset(s) — confirm authentication, rate limiting, and prompt-injection guardrails.</td></tr>` : ''}
    ${totalOpen === 0 && publicAssets === 0 ? `<tr><td>1</td><td>${sevBadge('LOW')}</td><td>No open findings — maintain scan cadence and re-assess governance quarterly.</td></tr>` : ''}
  </tbody></table>
</div>`;
  } else {
    bodyHTML = `
<div class="section">
  <h2>${type.replace(/_/g,' ')} Report</h2>
  <p style="font-size:13px;color:#94a3b8;line-height:1.6;">
    Report generated for organization: <strong>${orgId}</strong>.
    Total scans (30d): ${totalScans}. Risk score: ${riskScore}/100.
    Critical findings: ${criticalCount}. High findings: ${highCount}.
  </p>
</div>`;
  }

  const isSlideDeck = /^(pptx|ppt|slides?|deck)$/i.test(format || '');
  const shell = isSlideDeck ? buildSlideDeckShell : buildReportShell;

  return shell({
    brandName,
    primaryColor,
    title: `${brandName} — ${type} Report`,
    metaLine: `Report Type: ${type.replace(/_/g,' ')} · Generated: ${ts} · Org: ${orgId}`,
    bodyHTML,
    footerNote: `${brandName} · Confidential · Generated ${ts} · CYBERDUDEBIVASH® Platform v33.0`,
  });
}

export async function handleListReports(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = req.user.org_id || 'default';
  const rows = await env.DB.prepare(
    `SELECT id, report_type, format, status, created_by, created_at, completed_at, last_run_at
     FROM report_jobs WHERE org_id = ? ORDER BY created_at DESC LIMIT 25`
  ).bind(orgId).all().catch(() => ({ results: [] }));

  return Response.json({ reports: rows.results || [] });
}

export async function handleCreateReport(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { type = 'SECURITY_POSTURE', format = 'HTML', config = {} } = body;
  if (!canAccessReportType(type, req)) {
    return Response.json({ error: 'Report type not available for your plan' }, { status: 403 });
  }

  const jobId = genJobId();
  const orgId = req.user.org_id || 'default';

  await env.DB.prepare(
    `INSERT INTO report_jobs (id, report_type, format, status, org_id, created_by, config_json, created_at)
     VALUES (?,?,?,'GENERATING',?,?,?,datetime('now'))`
  ).bind(jobId, type, format, orgId, req.user.id || 'unknown', JSON.stringify(config)).run().catch(() => null);

  // Generate immediately (synchronous for Workers runtime)
  try {
    // Partner scoping for per-tenant (MSSP) reports — same resolution rule as
    // msspTenantPlatform.js's partnerScope(): userId/user_id, never client-supplied.
    const actorUserId = req.user.userId ?? req.user.user_id ?? null;
    const html = await generateReportHTML(type, orgId, config, env, actorUserId, format);
    const token = genToken();
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();

    await env.KV?.put(`report_token_${token}`, JSON.stringify({ jobId, orgId }), { expirationTtl: 3600 }).catch(() => null);
    await env.DB.prepare(
      `UPDATE report_jobs SET status='READY', download_token=?, download_expires_at=?, completed_at=datetime('now') WHERE id=?`
    ).bind(token, expiresAt, jobId).run().catch(() => null);

    // Cache the HTML in KV (1 hour TTL)
    await env.KV?.put(`report_html_${jobId}`, html, { expirationTtl: 3600 }).catch(() => null);

    return Response.json({ success: true, job_id: jobId, status: 'READY', download_token: token, expires_at: expiresAt });
  } catch (e) {
    await env.DB.prepare(
      `UPDATE report_jobs SET status='FAILED', error_message=? WHERE id=?`
    ).bind(e.message, jobId).run().catch(() => null);
    return Response.json({ error: 'Report generation failed', detail: e.message }, { status: 500 });
  }
}

export async function handleGetReport(req, env, jobId) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const orgId = req.user.org_id || 'default';
  const job = await env.DB.prepare(
    `SELECT * FROM report_jobs WHERE id = ? AND org_id = ?`
  ).bind(jobId, orgId).first().catch(() => null);

  if (!job) return Response.json({ error: 'Report not found' }, { status: 404 });

  return Response.json({ report: job });
}

export async function handleDownloadReport(req, env, jobId) {
  const url = new URL(req.url);
  const token = url.searchParams.get('token');

  // Job row is the durable record (KV html/token expire after 1h; the pricing
  // page advertises 7-day to 1-year report retention, so downloads must not
  // die with the cache).
  const job = await env.DB.prepare(
    `SELECT * FROM report_jobs WHERE id = ?`
  ).bind(jobId).first().catch(() => null);

  // Two authorization paths:
  //  1. Fresh download token (shareable link, 1h TTL) — original flow.
  //  2. Authenticated member of the owning org — lets customers revisit and
  //     re-download reports after the token has expired.
  let authorized = false;
  if (token) {
    const tokenData = await env.KV?.get(`report_token_${token}`, 'json').catch(() => null);
    if (tokenData && tokenData.jobId === jobId) authorized = true;
  }
  if (!authorized && job && req.user && (req.user.id || req.user.user_id || req.user.userId)) {
    const orgId = req.user.org_id || 'default';
    if (job.org_id === orgId) authorized = true;
  }
  if (!authorized) {
    return Response.json({ error: 'Valid download token required, or sign in to the organization that owns this report' }, { status: 401 });
  }

  let html = await env.KV?.get(`report_html_${jobId}`).catch(() => null);
  if (!html) {
    // Cache expired — regenerate from the persisted job definition
    if (!job || job.status === 'FAILED') {
      return Response.json({ error: 'Report not found' }, { status: 404 });
    }
    try {
      const config = JSON.parse(job.config_json || '{}');
      const actorUserId = req.user?.userId ?? req.user?.user_id ?? null;
      html = await generateReportHTML(job.report_type, job.org_id, config, env, actorUserId, job.format);
      await env.KV?.put(`report_html_${jobId}`, html, { expirationTtl: 3600 }).catch(() => null);
    } catch (e) {
      return Response.json({ error: 'Report regeneration failed', detail: e?.message }, { status: 500 });
    }
  }

  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Content-Disposition': `inline; filename="report-${jobId}.html"` },
  });
}

export async function handleReportTemplates(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const available = REPORT_TEMPLATES.filter(t => hasAccess(t.available_to, req));

  return Response.json({ templates: available, total: available.length });
}

export async function handleScheduleReport(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!hasAccess(['admin', 'mssp_admin', 'enterprise'], req)) {
    return Response.json({ error: 'Enterprise plan required for scheduled reports' }, { status: 403 });
  }

  let body;
  try { body = await req.json(); } catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }

  const { type, cron, format = 'HTML', deliver_to = [], config = {} } = body;
  if (!canAccessReportType(type, req)) {
    return Response.json({ error: 'Report type not available for your plan' }, { status: 403 });
  }

  const jobId = genJobId();
  const orgId = req.user.org_id || 'default';

  await env.DB.prepare(
    `INSERT INTO report_jobs
       (id, report_type, format, status, org_id, created_by, config_json, scheduled_cron, delivered_to, created_at)
     VALUES (?,?,?,'QUEUED',?,?,?,?,?,datetime('now'))`
  ).bind(jobId, type, format, orgId, req.user.id || 'unknown',
    JSON.stringify(config), cron || null, JSON.stringify(deliver_to)).run().catch(() => null);

  return Response.json({ success: true, job_id: jobId, message: 'Scheduled report created', cron });
}
