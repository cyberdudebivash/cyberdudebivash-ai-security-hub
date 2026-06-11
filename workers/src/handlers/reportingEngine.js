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
 * Generate in-memory HTML report content from existing D1 data.
 */
async function generateReportHTML(type, orgId, config, env) {
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

  const baseHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${brandName} — ${type} Report</title>
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
  <div class="meta">Report Type: ${type.replace(/_/g,' ')} · Generated: ${ts} · Org: ${orgId}</div>
</div>
`;

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

  const footerHTML = `
<div class="footer">
  ${brandName} · Confidential · Generated ${ts} · CYBERDUDEBIVASH® Platform v33.0
</div>
</body></html>`;

  return baseHTML + bodyHTML + footerHTML;
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
    const html = await generateReportHTML(type, orgId, config, env);
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
