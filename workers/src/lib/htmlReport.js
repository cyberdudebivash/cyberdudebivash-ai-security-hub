/**
 * CYBERDUDEBIVASH AI Security Hub — HTML Report Generator v1.0
 * Produces a professional, print-optimized, self-contained HTML security report
 * Designed to be saved as PDF via File → Print → Save as PDF in any browser
 * Stored in Cloudflare R2, served via token-gated download endpoint
 */

const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const SEV_COLOR = {
  CRITICAL: { bg: '#ef4444', light: 'rgba(239,68,68,.12)', border: '#ef4444', text: '#fca5a5' },
  HIGH:     { bg: '#f59e0b', light: 'rgba(245,158,11,.12)', border: '#f59e0b', text: '#fcd34d' },
  MEDIUM:   { bg: '#3b82f6', light: 'rgba(59,130,246,.12)',  border: '#3b82f6', text: '#93c5fd' },
  LOW:      { bg: '#10b981', light: 'rgba(16,185,129,.12)',  border: '#10b981', text: '#6ee7b7' },
  INFO:     { bg: '#6b7280', light: 'rgba(107,114,128,.12)', border: '#6b7280', text: '#9ca3af' },
};

const MODULE_LABELS = {
  domain_scanner: 'Domain Security Assessment',
  ai_security:    'AI System Security Assessment',
  redteam:        'Automated Red Team Assessment',
  identity:       'Identity & Access Security Assessment',
  compliance:     'Compliance Gap Analysis',
  domain:         'Domain Security Assessment',
  ai:             'AI System Security Assessment',
};

// ─── Framework mappings per module ───────────────────────────────────────────
const FRAMEWORK_TAGS = {
  domain_scanner: ['ISO 27001:2022 A.8.23', 'PCI-DSS v4.0 Req 4.2.1', 'SOC 2 CC6.6', 'DPDP Act Sec.8'],
  ai_security:    ['OWASP LLM Top 10 2025', 'NIST AI RMF 1.0', 'ISO 27001:2022 A.8.28', 'MITRE ATLAS'],
  redteam:        ['MITRE ATT&CK v15', 'NIST SP 800-115', 'ISO 27001:2022 A.8.8', 'PTES Standard'],
  identity:       ['NIST SP 800-207 Zero Trust', 'ISO 27001:2022 A.5.16', 'SOC 2 CC6.1', 'FIDO2/WebAuthn'],
  compliance:     ['ISO 27001:2022', 'SOC 2 Type II', 'GDPR 2016/679', 'PCI-DSS v4.0', 'DPDP Act 2023'],
};

// ─── CVSS to Severity ─────────────────────────────────────────────────────────
function cvssToSev(score) {
  if (!score) return 'MEDIUM';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

// ─── Sort findings by severity ────────────────────────────────────────────────
function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) =>
    (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0)
  );
}

// ─── Count findings by severity ──────────────────────────────────────────────
function countSev(findings) {
  return {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH:     findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM:   findings.filter(f => f.severity === 'MEDIUM').length,
    LOW:      findings.filter(f => f.severity === 'LOW').length,
  };
}

// ─── Risk color gradient ──────────────────────────────────────────────────────
function riskGradient(score) {
  if (score >= 80) return 'linear-gradient(135deg, #ef4444, #dc2626)';
  if (score >= 60) return 'linear-gradient(135deg, #f59e0b, #d97706)';
  if (score >= 35) return 'linear-gradient(135deg, #3b82f6, #2563eb)';
  return 'linear-gradient(135deg, #10b981, #059669)';
}

// ─── Finding card HTML ────────────────────────────────────────────────────────
function findingCardHTML(f, idx) {
  const sev    = f.severity || 'MEDIUM';
  const colors = SEV_COLOR[sev] || SEV_COLOR.MEDIUM;
  const cvss   = f.cvss_base ? `<span class="cvss-tag">CVSS ${f.cvss_base}</span>` : '';
  const mitreTag = f.mitre_tactic ? `<span class="fw-tag">${f.mitre_tactic}</span>` : '';
  const owaspTag = f.owasp_id     ? `<span class="fw-tag">${f.owasp_id}</span>` : '';

  return `
  <div class="finding-card" style="border-left-color:${colors.border};background:${colors.light}">
    <div class="finding-header">
      <span class="finding-num">#${idx + 1}</span>
      <span class="sev-badge" style="background:${colors.bg}">${sev}</span>
      ${f.id ? `<span class="finding-id">${f.id}</span>` : ''}
      <span class="finding-title">${escapeHtml(f.title || 'Finding')}</span>
      ${cvss}
    </div>
    <div class="finding-tags">${mitreTag}${owaspTag}</div>
    <div class="finding-desc">${escapeHtml(f.description || '')}</div>
    ${f.evidence   ? `<div class="finding-section"><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</div>` : ''}
    ${f.impact     ? `<div class="finding-section"><strong>Impact:</strong> ${escapeHtml(f.impact)}</div>` : ''}
    ${f.recommendation ? `
    <div class="finding-rec">
      <strong>Remediation:</strong> ${escapeHtml(f.recommendation)}
    </div>` : ''}
  </div>`;
}

// ─── Remediation table row ────────────────────────────────────────────────────
function remediationRowHTML(f, idx) {
  const sev    = f.severity || 'MEDIUM';
  const colors = SEV_COLOR[sev] || SEV_COLOR.MEDIUM;
  const effort = f.effort ?? 'MEDIUM';
  const effortColor = effort === 'HIGH' ? '#ef4444' : effort === 'MEDIUM' ? '#f59e0b' : '#10b981';
  return `<tr>
    <td class="td-center">${idx + 1}</td>
    <td>${f.id ? `<code>${f.id}</code> ` : ''}${escapeHtml(f.title || '')}</td>
    <td class="td-center"><span class="sev-badge" style="background:${colors.bg}">${sev}</span></td>
    <td class="td-center" style="color:${effortColor};font-weight:700">${effort}</td>
    <td>${escapeHtml(f.estimated_time || f.timeline || '1 week')}</td>
    <td>${escapeHtml(f.owner || 'Security Team')}</td>
  </tr>`;
}

// ─── Escape HTML entities ─────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Build complete remediation plan entries from findings ────────────────────
function buildRemediationFromFindings(findings) {
  const EFFORT_MAP = {
    CRITICAL: { effort: 'HIGH',   timeline: '24-48 hours', owner: 'Security Team' },
    HIGH:     { effort: 'HIGH',   timeline: '1 week',      owner: 'Security Team' },
    MEDIUM:   { effort: 'MEDIUM', timeline: '2-4 weeks',   owner: 'DevOps / SRE'  },
    LOW:      { effort: 'LOW',    timeline: '1-2 months',  owner: 'Dev Team'      },
  };
  return sortFindings(findings).map((f, idx) => {
    const m = EFFORT_MAP[f.severity] || EFFORT_MAP.MEDIUM;
    return {
      priority:       idx + 1,
      id:             f.id,
      title:          f.title,
      severity:       f.severity,
      effort:         f.effort         || m.effort,
      estimated_time: f.estimated_time || m.timeline,
      owner:          f.owner          || m.owner,
    };
  });
}

// ─── Infrastructure section HTML ──────────────────────────────────────────────
function infrastructureHTML(scanResult) {
  const infra = [];
  if (scanResult.ipv4?.length)       infra.push(`<div class="infra-row"><strong>IPv4:</strong> ${scanResult.ipv4.join(', ')}</div>`);
  if (scanResult.ipv6?.length)       infra.push(`<div class="infra-row"><strong>IPv6:</strong> ${scanResult.ipv6.join(', ')}</div>`);
  if (scanResult.nameservers?.length) infra.push(`<div class="infra-row"><strong>Nameservers:</strong> ${scanResult.nameservers.join(', ')}</div>`);
  if (scanResult.mx_records?.length)  infra.push(`<div class="infra-row"><strong>MX Records:</strong> ${scanResult.mx_records.join(', ')}</div>`);

  const email = scanResult.email_security;
  if (email) {
    const yes = '✅', no = '❌';
    infra.push(`<div class="infra-row"><strong>SPF:</strong> ${email.spf?.valid ? yes : no} ${email.spf?.record ? `<code>${escapeHtml(email.spf.record)}</code>` : ''}</div>`);
    infra.push(`<div class="infra-row"><strong>DMARC:</strong> ${email.dmarc?.valid ? yes : no} ${email.dmarc?.policy ? `(policy: ${email.dmarc.policy})` : ''}</div>`);
    infra.push(`<div class="infra-row"><strong>DKIM:</strong> ${email.dkim?.found ? yes : no} ${email.dkim?.selectors?.length ? `(selectors: ${email.dkim.selectors.join(', ')})` : ''}</div>`);
  }

  const ti = scanResult.threat_intelligence;
  if (ti && ti.any_blacklisted !== undefined) {
    infra.push(`<div class="infra-row"><strong>Blacklist Status:</strong> ${ti.any_blacklisted ? '🚨 LISTED' : '✅ Clean'} (score: ${ti.combined_threat_score ?? 0}/100)</div>`);
  }

  if (scanResult.tls_grade) {
    infra.push(`<div class="infra-row"><strong>TLS Grade:</strong> ${scanResult.tls_grade}</div>`);
  }

  return infra.length ? infra.join('\n') : '<p style="color:#9ca3af">No infrastructure data available.</p>';
}

// ─── MAIN: Generate complete HTML report ──────────────────────────────────────
export function generateHTMLReport(scanResult, reportMeta = {}) {
  const allFindings  = sortFindings([
    ...(scanResult.findings        || []),
    ...(scanResult.locked_findings || []),
  ]);
  const counts       = countSev(allFindings);
  const score        = scanResult.risk_score ?? 0;
  const level        = scanResult.risk_level ?? 'MEDIUM';
  const grade        = scanResult.grade ?? 'N/A';
  const target       = scanResult.target ?? 'Unknown Target';
  const moduleKey    = scanResult.module ?? 'domain';
  const moduleLabel  = MODULE_LABELS[moduleKey] || 'Security Assessment';
  const generatedAt  = new Date().toLocaleString('en-IN', { dateStyle: 'long', timeStyle: 'short' });
  const reportId     = reportMeta.report_id || crypto.randomUUID?.() || Date.now().toString(36);
  const fwTags       = (FRAMEWORK_TAGS[moduleKey] || FRAMEWORK_TAGS.domain_scanner)
                         .map(t => `<span class="fw-chip">${t}</span>`).join('');

  const summary      = scanResult.executive_summary || {};
  const narrative    = summary.narrative
    || (score >= 80  ? `This assessment reveals a CRITICAL security posture. ${counts.CRITICAL} critical vulnerabilities require emergency remediation within 24 hours.`
       : score >= 60 ? `HIGH-severity risks identified. ${counts.HIGH + counts.CRITICAL} high/critical findings indicate significant security control gaps requiring immediate attention.`
       : score >= 35 ? `MEDIUM risk posture detected. ${counts.MEDIUM} medium-severity findings represent meaningful attack surface requiring remediation within 30 days.`
       :               `LOW risk posture. Most controls correctly configured. ${counts.LOW} low-severity findings are security hygiene improvements.`);

  const remPlan       = buildRemediationFromFindings(allFindings);
  const findingsHTML  = allFindings.map((f, i) => findingCardHTML(f, i)).join('\n');
  const remTableRows  = remPlan.map((r, i) => remediationRowHTML(r, i)).join('\n');
  const infraHTML     = infrastructureHTML(scanResult);

  // Compliance impact from executive_summary if available
  const compImpacts = summary.compliance_impact || [];
  const compImpactRows = compImpacts.map(c => `
    <tr>
      <td>${c.framework}</td>
      <td><code>${c.article || c.control || c.criteria || '—'}</code></td>
      <td style="color:${c.impact === 'HIGH' ? '#ef4444' : c.impact === 'MEDIUM' ? '#f59e0b' : '#10b981'};font-weight:700">${c.impact}</td>
      <td>${escapeHtml(c.note || '')}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(moduleLabel)} — ${escapeHtml(target)} | CYBERDUDEBIVASH AI Security Hub</title>
<style>
/* ── Reset ──────────────────────────────────────────────────────────────── */
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px}
body{background:#0a0a1a;color:#e2e8f0;font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;line-height:1.6;padding:0 0 40px}
a{color:#00d4ff;text-decoration:none}
code{font-family:'Courier New',monospace;font-size:12px;background:rgba(255,255,255,.08);padding:1px 6px;border-radius:4px}

/* ── Print optimisation ─────────────────────────────────────────────────── */
@media print{
  body{background:#fff!important;color:#111!important;font-size:12px}
  .letterhead{background:linear-gradient(135deg,#0a0a1a,#0f0f2e)!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .page-break{page-break-before:always}
  .finding-card{break-inside:avoid}
  .no-print{display:none!important}
  table{break-inside:avoid}
  a{color:#00d4ff!important}
}

/* ── Letterhead ──────────────────────────────────────────────────────────── */
.letterhead{background:linear-gradient(135deg,#0a0a1a 0%,#0f0f2e 100%);border-bottom:3px solid #00d4ff;padding:32px 48px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.lh-brand{font-size:22px;font-weight:900;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.lh-sub{font-size:11px;color:#94a3b8;margin-top:2px;letter-spacing:.5px;text-transform:uppercase}
.lh-right{text-align:right;font-size:11px;color:#94a3b8;line-height:1.8}
.lh-right strong{color:#e2e8f0}

/* ── Confidential Banner ─────────────────────────────────────────────────── */
.conf-banner{background:rgba(239,68,68,.1);border-bottom:1px solid rgba(239,68,68,.3);padding:6px 48px;font-size:11px;font-weight:700;color:#fca5a5;letter-spacing:2px;text-transform:uppercase;text-align:center}

/* ── Content Wrapper ─────────────────────────────────────────────────────── */
.content{max-width:1000px;margin:0 auto;padding:0 40px}

/* ── Cover Block ─────────────────────────────────────────────────────────── */
.cover{text-align:center;padding:56px 0 48px;border-bottom:1px solid rgba(255,255,255,.08)}
.cover-badge{display:inline-block;background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);border-radius:20px;padding:5px 18px;font-size:11px;font-weight:700;color:#00d4ff;letter-spacing:1px;text-transform:uppercase;margin-bottom:20px}
.cover-title{font-size:28px;font-weight:900;color:#fff;margin-bottom:8px}
.cover-target{font-size:18px;color:#00d4ff;font-weight:700;margin-bottom:24px}
.cover-meta{display:flex;flex-wrap:wrap;justify-content:center;gap:24px;margin-bottom:28px}
.cover-meta-item{text-align:center}
.cover-meta-label{font-size:10px;font-weight:700;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}
.cover-meta-value{font-size:14px;font-weight:700;color:#e2e8f0}
.fw-chips{display:flex;flex-wrap:wrap;justify-content:center;gap:8px}
.fw-chip{background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.3);border-radius:14px;padding:3px 12px;font-size:10px;font-weight:700;color:#a78bfa;letter-spacing:.3px}

/* ── Score Ring Block ────────────────────────────────────────────────────── */
.score-block{display:flex;align-items:center;gap:40px;flex-wrap:wrap;padding:32px 0}
.score-ring-wrap{position:relative;width:130px;height:130px;flex-shrink:0}
.score-ring-wrap svg{width:130px;height:130px;transform:rotate(-90deg)}
.score-ring-wrap circle{fill:none;stroke-width:10;stroke-linecap:round}
.ring-bg{stroke:rgba(255,255,255,.08)}
.ring-fill{stroke:url(#sg);stroke-dasharray:345;transition:stroke-dashoffset 1.2s ease}
.score-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px}
.score-num{font-size:30px;font-weight:900;color:#fff}
.score-lbl{font-size:9px;font-weight:700;color:#94a3b8;letter-spacing:.5px;text-transform:uppercase}
.score-details{flex:1;min-width:220px}
.score-level{font-size:24px;font-weight:900;margin-bottom:4px}
.score-narrative{font-size:13px;color:#94a3b8;line-height:1.65;margin-bottom:16px}
.sev-counts{display:flex;gap:16px;flex-wrap:wrap}
.sev-count{text-align:center;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:10px 16px}
.sev-count-num{font-size:22px;font-weight:900}
.sev-count-lbl{font-size:9px;font-weight:700;color:#94a3b8;letter-spacing:.5px;text-transform:uppercase;margin-top:2px}

/* ── Section ──────────────────────────────────────────────────────────────── */
.section{padding:32px 0;border-bottom:1px solid rgba(255,255,255,.06)}
.section:last-child{border-bottom:none}
.section-heading{font-size:11px;font-weight:800;color:#00d4ff;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:8px}
.section-heading::after{content:'';flex:1;height:1px;background:rgba(0,212,255,.2)}
.section-title{font-size:20px;font-weight:900;color:#fff;margin-bottom:20px}

/* ── Finding Card ────────────────────────────────────────────────────────── */
.finding-card{border-left:4px solid;border-radius:8px;padding:16px;margin-bottom:14px}
.finding-header{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.finding-num{font-size:11px;font-weight:800;color:#64748b;font-family:monospace}
.sev-badge{font-size:10px;font-weight:800;color:#fff;padding:2px 10px;border-radius:4px;letter-spacing:.5px}
.finding-id{font-size:11px;font-family:monospace;color:#00d4ff;font-weight:700}
.finding-title{font-size:15px;font-weight:800;color:#fff;flex:1;min-width:160px}
.cvss-tag{font-size:10px;font-weight:700;color:#94a3b8;background:rgba(255,255,255,.06);border-radius:4px;padding:2px 8px;font-family:monospace}
.finding-tags{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}
.fw-tag{font-size:10px;font-weight:700;color:#a78bfa;background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.2);border-radius:4px;padding:1px 8px}
.finding-desc{font-size:13px;color:#94a3b8;line-height:1.6;margin-bottom:8px}
.finding-section{font-size:12px;color:#94a3b8;margin-bottom:6px}
.finding-rec{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2);border-radius:6px;padding:10px 14px;font-size:12px;color:#6ee7b7;line-height:1.55}
.finding-rec strong{color:#34d399}

/* ── Table ───────────────────────────────────────────────────────────────── */
.report-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}
.report-table th{background:rgba(255,255,255,.06);padding:10px 14px;text-align:left;font-size:10px;font-weight:800;color:#94a3b8;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid rgba(255,255,255,.1)}
.report-table td{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}
.report-table tr:last-child td{border-bottom:none}
.report-table tr:hover td{background:rgba(255,255,255,.02)}
.td-center{text-align:center}

/* ── Infra Block ──────────────────────────────────────────────────────────── */
.infra-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px;margin-top:8px}
.infra-row{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:6px;padding:10px 14px;font-size:12px;color:#94a3b8;line-height:1.5}
.infra-row strong{color:#e2e8f0;display:block;margin-bottom:2px}

/* ── Footer ──────────────────────────────────────────────────────────────── */
.report-footer{background:rgba(255,255,255,.03);border-top:1px solid rgba(255,255,255,.08);padding:20px 48px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:40px;font-size:11px;color:#64748b}
.report-footer a{color:#00d4ff}

/* ── Disclaimer ───────────────────────────────────────────────────────────── */
.disclaimer{background:rgba(245,158,11,.04);border:1px solid rgba(245,158,11,.15);border-radius:8px;padding:14px 18px;font-size:11px;color:#94a3b8;line-height:1.65;margin-top:20px}
.disclaimer strong{color:#fcd34d}
</style>
</head>
<body>

<!-- ── Letterhead ─────────────────────────────────────────────────────────── -->
<div class="letterhead">
  <div>
    <div class="lh-brand">⚔️ CYBERDUDEBIVASH®</div>
    <div class="lh-sub">AI Security Intelligence Platform — CyberDudeBivash Pvt. Ltd.</div>
  </div>
  <div class="lh-right">
    <strong>Report Ref:</strong> ${escapeHtml(reportId.slice(0,20).toUpperCase())}<br>
    <strong>Generated:</strong> ${generatedAt}<br>
    <strong>Platform:</strong> v7.0.0<br>
    <strong>Contact:</strong> <a href="mailto:bivash@cyberdudebivash.com">bivash@cyberdudebivash.com</a>
  </div>
</div>

<!-- ── Confidential Banner ────────────────────────────────────────────────── -->
<div class="conf-banner">🔒 Confidential — Prepared exclusively for authorized recipient — Do not distribute</div>

<div class="content">

<!-- ── Cover ──────────────────────────────────────────────────────────────── -->
<div class="cover">
  <div class="cover-badge">${escapeHtml(moduleLabel)}</div>
  <div class="cover-title">Security Assessment Report</div>
  <div class="cover-target">${escapeHtml(target)}</div>
  <div class="cover-meta">
    <div class="cover-meta-item"><div class="cover-meta-label">Assessment Date</div><div class="cover-meta-value">${generatedAt}</div></div>
    <div class="cover-meta-item"><div class="cover-meta-label">Risk Score</div><div class="cover-meta-value" style="font-size:20px;color:${score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 35 ? '#3b82f6' : '#10b981'}">${score}/100</div></div>
    <div class="cover-meta-item"><div class="cover-meta-label">Risk Level</div><div class="cover-meta-value">${escapeHtml(level)}</div></div>
    ${grade !== 'N/A' ? `<div class="cover-meta-item"><div class="cover-meta-label">Security Grade</div><div class="cover-meta-value">${escapeHtml(grade)}</div></div>` : ''}
    <div class="cover-meta-item"><div class="cover-meta-label">Total Findings</div><div class="cover-meta-value">${allFindings.length}</div></div>
  </div>
  <div class="fw-chips">${fwTags}</div>
</div>

<!-- ── Executive Summary ──────────────────────────────────────────────────── -->
<div class="section">
  <div class="section-heading">01</div>
  <div class="section-title">Executive Summary</div>

  <div class="score-block">
    <!-- SVG Ring -->
    <div class="score-ring-wrap">
      <svg viewBox="0 0 130 130">
        <defs>
          <linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style="stop-color:${score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 35 ? '#3b82f6' : '#10b981'}"/>
            <stop offset="100%" style="stop-color:${score >= 80 ? '#dc2626' : score >= 60 ? '#d97706' : score >= 35 ? '#2563eb' : '#059669'}"/>
          </linearGradient>
        </defs>
        <circle class="ring-bg" cx="65" cy="65" r="55"/>
        <circle class="ring-fill" cx="65" cy="65" r="55"
          style="stroke-dashoffset:${345 - (score / 100) * 345}"/>
      </svg>
      <div class="score-text">
        <div class="score-num">${score}</div>
        <div class="score-lbl">/ 100</div>
      </div>
    </div>
    <!-- Details -->
    <div class="score-details">
      <div class="score-level" style="color:${score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : score >= 35 ? '#3b82f6' : '#10b981'}">${escapeHtml(level)} RISK</div>
      <div class="score-narrative">${escapeHtml(narrative)}</div>
      <div class="sev-counts">
        <div class="sev-count"><div class="sev-count-num" style="color:#ef4444">${counts.CRITICAL}</div><div class="sev-count-lbl">Critical</div></div>
        <div class="sev-count"><div class="sev-count-num" style="color:#f59e0b">${counts.HIGH}</div><div class="sev-count-lbl">High</div></div>
        <div class="sev-count"><div class="sev-count-num" style="color:#3b82f6">${counts.MEDIUM}</div><div class="sev-count-lbl">Medium</div></div>
        <div class="sev-count"><div class="sev-count-num" style="color:#10b981">${counts.LOW}</div><div class="sev-count-lbl">Low</div></div>
      </div>
    </div>
  </div>

  ${compImpacts.length ? `
  <div style="margin-top:20px">
    <div style="font-size:12px;font-weight:800;color:#94a3b8;letter-spacing:.5px;text-transform:uppercase;margin-bottom:10px">Compliance Impact</div>
    <table class="report-table">
      <thead><tr><th>Framework</th><th>Control/Article</th><th>Impact</th><th>Notes</th></tr></thead>
      <tbody>${compImpactRows}</tbody>
    </table>
  </div>` : ''}
</div>

<!-- ── Detailed Findings ───────────────────────────────────────────────────── -->
<div class="section page-break">
  <div class="section-heading">02</div>
  <div class="section-title">Detailed Findings (${allFindings.length})</div>
  ${findingsHTML || '<p style="color:#64748b">No findings recorded for this assessment.</p>'}
</div>

<!-- ── Remediation Roadmap ────────────────────────────────────────────────── -->
<div class="section page-break">
  <div class="section-heading">03</div>
  <div class="section-title">Remediation Roadmap</div>
  ${remPlan.length ? `
  <table class="report-table">
    <thead>
      <tr>
        <th class="td-center">#</th>
        <th>Finding</th>
        <th class="td-center">Severity</th>
        <th class="td-center">Effort</th>
        <th>Timeline</th>
        <th>Owner</th>
      </tr>
    </thead>
    <tbody>${remTableRows}</tbody>
  </table>` : '<p style="color:#64748b">No remediation items identified.</p>'}
</div>

<!-- ── Technical Details ──────────────────────────────────────────────────── -->
<div class="section page-break">
  <div class="section-heading">04</div>
  <div class="section-title">Technical Details</div>
  <div class="infra-grid">
    ${infraHTML}
  </div>
  <div style="margin-top:16px;font-size:11px;color:#64748b">
    <strong style="color:#94a3b8">Scan ID:</strong> ${escapeHtml(scanResult.scan_metadata?.scan_id || reportId)} ·
    <strong style="color:#94a3b8">Data Source:</strong> ${escapeHtml(scanResult.data_source || 'live_dns')} ·
    <strong style="color:#94a3b8">Engine Version:</strong> 7.0.0
  </div>
</div>

<!-- ── Disclaimer ──────────────────────────────────────────────────────────── -->
<div class="disclaimer">
  <strong>Disclaimer:</strong> This report was generated automatically by the CYBERDUDEBIVASH AI Security Hub platform. Findings are based on passive assessment techniques and publicly observable data. This report does not constitute a penetration test and should not be used as the sole basis for compliance certification. For comprehensive security assessment, please contact our team at <a href="mailto:bivash@cyberdudebivash.com">bivash@cyberdudebivash.com</a>. All findings should be independently verified before remediation. CyberDudeBivash Pvt. Ltd. assumes no liability for actions taken based on this report.
</div>

</div><!-- /content -->

<!-- ── Footer ─────────────────────────────────────────────────────────────── -->
<div class="report-footer">
  <div>⚔️ <strong>CYBERDUDEBIVASH AI Security Hub</strong> — CyberDudeBivash Pvt. Ltd., Hyderabad, India</div>
  <div>
    📧 <a href="mailto:bivash@cyberdudebivash.com">bivash@cyberdudebivash.com</a> ·
    📞 +91 8179881447 ·
    🌐 <a href="https://cyberdudebivash.in">cyberdudebivash.in</a> ·
    Ref: ${escapeHtml(reportId.slice(0,16).toUpperCase())}
  </div>
</div>

<div style="text-align:center;margin:20px;font-size:11px;color:#374151" class="no-print">
  <button onclick="window.print()" style="background:linear-gradient(135deg,#7c3aed,#4f46e5);color:#fff;border:none;padding:10px 28px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer">
    🖨️ Save as PDF (Print → Save as PDF)
  </button>
</div>

</body>
</html>`;
}
