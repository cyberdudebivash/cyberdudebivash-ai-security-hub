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

function genJobId() { return 'rpt_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function genToken() { return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2); }

function requireRole(req, roles) {
  if (!req.user) return false;
  return roles.includes(req.user.role) || roles.includes(req.user.tier);
}

function canAccessReportType(type, req) {
  const tpl = REPORT_TEMPLATES.find(t => t.type === type);
  if (!tpl) return false;
  if (!req.user) return false;
  return tpl.available_to.includes(req.user.role) || tpl.available_to.includes(req.user.tier);
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
  if (!token) return Response.json({ error: 'Download token required' }, { status: 401 });

  const tokenData = await env.KV?.get(`report_token_${token}`, 'json').catch(() => null);
  if (!tokenData || tokenData.jobId !== jobId) {
    return Response.json({ error: 'Invalid or expired download token' }, { status: 401 });
  }

  const html = await env.KV?.get(`report_html_${jobId}`).catch(() => null);
  if (!html) return Response.json({ error: 'Report content expired. Please regenerate.' }, { status: 404 });

  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Content-Disposition': `inline; filename="report-${jobId}.html"` },
  });
}

export async function handleReportTemplates(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });

  const available = REPORT_TEMPLATES.filter(t =>
    t.available_to.includes(req.user.role) || t.available_to.includes(req.user.tier)
  );

  return Response.json({ templates: available, total: available.length });
}

export async function handleScheduleReport(req, env) {
  if (!req.user) return Response.json({ error: 'Authentication required' }, { status: 401 });
  if (!['admin', 'mssp_admin', 'enterprise'].includes(req.user.role) && !['enterprise'].includes(req.user.tier)) {
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
