/**
 * CYBERDUDEBIVASH AI Security Hub — Report Engine v1.0
 * Generates structured security reports from scan results
 * Stores in Cloudflare KV with UUID-based download tokens
 * Supports: executive summary, technical findings, remediation plan
 */

const REPORT_TTL_SECONDS = 86400 * 7; // 7 days
const TOKEN_TTL_SECONDS  = 86400 * 7;

// ─── UUID-like token generator (crypto.randomUUID if available) ───────────────
function generateToken() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback for older runtimes
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  arr[6] = (arr[6] & 0x0f) | 0x40;
  arr[8] = (arr[8] & 0x3f) | 0x80;
  return [...arr].map((b, i) =>
    ([4,6,8,10].includes(i) ? '-' : '') + b.toString(16).padStart(2,'0')
  ).join('');
}

// ─── Severity ranking ─────────────────────────────────────────────────────────
const SEV_ORDER = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFO:0 };
function sortBySeverity(findings) {
  return [...(findings || [])].sort((a,b) => (SEV_ORDER[b.severity]||0) - (SEV_ORDER[a.severity]||0));
}

// ─── Remediation priority matrix ─────────────────────────────────────────────
const REMEDIATION_EFFORT = {
  'DOM-001': { effort:'LOW',   timeline:'1 day',    owner:'DevOps/SRE'        },
  'DOM-002': { effort:'MEDIUM',timeline:'1 week',   owner:'DNS Admin'         },
  'DOM-003': { effort:'LOW',   timeline:'2 hours',  owner:'DevOps/SRE'        },
  'DOM-004': { effort:'LOW',   timeline:'1 day',    owner:'Email Admin'       },
  'DOM-005': { effort:'LOW',   timeline:'1 day',    owner:'Email Admin'       },
  'DOM-006': { effort:'MEDIUM',timeline:'2 days',   owner:'Email Admin'       },
  'DOM-007': { effort:'LOW',   timeline:'30 min',   owner:'DNS Admin'         },
  'DOM-008': { effort:'HIGH',  timeline:'1-2 weeks',owner:'Security Team'     },
  'AI-001':  { effort:'HIGH',  timeline:'2-4 weeks',owner:'AI/ML Team'        },
  'AI-002':  { effort:'MEDIUM',timeline:'1 week',   owner:'AI/ML Team'        },
  'ID-001':  { effort:'HIGH',  timeline:'2 weeks',  owner:'Identity Team'     },
  'RT-001':  { effort:'HIGH',  timeline:'4+ weeks', owner:'Security Team'     },
};

// ─── Executive Summary Generator ─────────────────────────────────────────────
function buildExecutiveSummary(scanResult) {
  const findings     = scanResult.findings || [];
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount     = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount   = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount      = findings.filter(f => f.severity === 'LOW').length;

  const riskScore = scanResult.risk_score ?? 0;
  const riskLevel = scanResult.risk_level ?? 'UNKNOWN';
  const grade     = scanResult.grade ?? 'N/A';

  // Business risk narrative
  let narrative = '';
  if (riskScore >= 80) {
    narrative = `This assessment reveals a CRITICAL security posture that poses immediate business risk. ${criticalCount} critical vulnerabilities require emergency remediation within 24 hours. Continued operation without remediation exposes the organization to data breaches, regulatory penalties, and reputational damage.`;
  } else if (riskScore >= 60) {
    narrative = `The security assessment identifies HIGH-severity risks that should be addressed within this sprint cycle. ${highCount + criticalCount} high/critical findings indicate significant gaps in security controls that could be exploited by both opportunistic and targeted attackers.`;
  } else if (riskScore >= 35) {
    narrative = `A MEDIUM risk posture was identified. While no immediately critical vulnerabilities are present, ${mediumCount} medium-severity findings represent meaningful attack surface that should be addressed in the next 30 days.`;
  } else {
    narrative = `The security posture is at LOW risk. Most controls are correctly configured. ${lowCount} low-severity findings represent security hygiene improvements that will further harden the attack surface.`;
  }

  return {
    risk_score:      riskScore,
    risk_level:      riskLevel,
    grade:           grade,
    critical_count:  criticalCount,
    high_count:      highCount,
    medium_count:    mediumCount,
    low_count:       lowCount,
    total_findings:  findings.length,
    narrative,
    key_risks:       sortBySeverity(findings).slice(0, 3).map(f => ({
      id: f.id, title: f.title, severity: f.severity,
      brief: (f.description || '').slice(0, 120) + '...',
    })),
    compliance_impact: buildComplianceImpact(findings),
  };
}

// ─── Compliance Impact Map ────────────────────────────────────────────────────
function buildComplianceImpact(findings) {
  const impacts = [];
  const critHigh = findings.filter(f => ['CRITICAL','HIGH'].includes(f.severity));

  if (critHigh.length > 0) {
    if (findings.some(f => ['DOM-004','DOM-005','DOM-006'].includes(f.id) && ['CRITICAL','HIGH'].includes(f.severity))) {
      impacts.push({ framework:'DPDP Act 2023', article:'Section 4 / 8', impact:'HIGH', note:'Email security gaps may expose personal data to spoofing attacks' });
      impacts.push({ framework:'ISO 27001:2022', control:'A.8.23', impact:'HIGH', note:'Web filtering and email security controls potentially deficient' });
    }
    if (findings.some(f => f.id === 'DOM-001' && f.severity !== 'LOW')) {
      impacts.push({ framework:'PCI-DSS v4.0', requirement:'Req 4.2.1', impact:'HIGH', note:'Strong cryptography required for cardholder data in transit' });
      impacts.push({ framework:'SOC 2 Type II', criteria:'CC6.1', impact:'MEDIUM', note:'Logical and physical access controls — encryption in transit' });
    }
    if (findings.some(f => f.id === 'DOM-008' && (f.blacklisted || f.threat_score > 0))) {
      impacts.push({ framework:'SEBI CSCRF', control:'5.4', impact:'HIGH', note:'Domain blacklisting indicates potential compromise — incident response required' });
    }
  }

  if (impacts.length === 0) {
    impacts.push({ framework:'All checked', control:'N/A', impact:'LOW', note:'No high-severity compliance violations detected' });
  }

  return impacts;
}

// ─── Remediation Plan ────────────────────────────────────────────────────────
function buildRemediationPlan(findings) {
  const sorted = sortBySeverity(findings);
  return sorted.map((f, idx) => {
    const effort = REMEDIATION_EFFORT[f.id] || { effort:'MEDIUM', timeline:'1 week', owner:'Security Team' };
    return {
      priority:     idx + 1,
      finding_id:   f.id,
      finding_title: f.title,
      severity:     f.severity,
      effort:       effort.effort,
      estimated_time: effort.timeline,
      owner:        effort.owner,
      recommendation: f.recommendation || 'Review and remediate per security best practices.',
      cvss_base:    f.cvss_base ?? null,
    };
  });
}

// ─── Technical Detail Section ────────────────────────────────────────────────
function buildTechnicalDetail(scanResult) {
  return {
    scan_metadata: scanResult.scan_metadata,
    data_source:   scanResult.data_source,
    raw_scores: {
      risk_score:   scanResult.risk_score,
      threat_score: scanResult.threat_score ?? null,
    },
    infrastructure: {
      ipv4:        scanResult.ipv4          ?? [],
      ipv6:        scanResult.ipv6          ?? [],
      nameservers: scanResult.nameservers   ?? [],
      mx_records:  scanResult.mx_records    ?? [],
      resolves:    scanResult.resolves      ?? null,
    },
    email_security:      scanResult.email_security      ?? null,
    threat_intelligence: scanResult.threat_intelligence ?? null,
    all_findings:        sortBySeverity(scanResult.findings || []),
  };
}

// ─── Build Full Report ────────────────────────────────────────────────────────
export function buildReport(scanResult, meta = {}) {
  const reportId = generateToken();
  const now      = new Date().toISOString();

  return {
    report_id:      reportId,
    report_version: '1.0',
    generated_at:   now,
    expires_at:     new Date(Date.now() + REPORT_TTL_SECONDS * 1000).toISOString(),
    report_type:    `${scanResult.module ?? 'security'}_assessment`,
    target:         scanResult.target ?? meta.target ?? 'unknown',
    branding: {
      powered_by:  'CYBERDUDEBIVASH AI Security Hub',
      website:     'https://cyberdudebivash.in',
      contact:     'cyberdudebivash@gmail.com',
      report_tool: 'https://tools.cyberdudebivash.com',
    },
    requester: {
      email: meta.email || null,
      tier:  meta.tier  || 'FREE',
    },
    executive_summary: buildExecutiveSummary(scanResult),
    remediation_plan:  buildRemediationPlan(scanResult.findings || []),
    technical_detail:  buildTechnicalDetail(scanResult),
  };
}

// ─── Store Report in KV ───────────────────────────────────────────────────────
export async function storeReport(env, report) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const downloadToken = generateToken();
    await Promise.all([
      // Store full report
      env.SECURITY_HUB_KV.put(
        `report:${report.report_id}`,
        JSON.stringify(report),
        { expirationTtl: REPORT_TTL_SECONDS }
      ),
      // Store lookup by download token
      env.SECURITY_HUB_KV.put(
        `report_token:${downloadToken}`,
        report.report_id,
        { expirationTtl: TOKEN_TTL_SECONDS }
      ),
    ]);
    return { download_token: downloadToken, report_id: report.report_id, expires_at: report.expires_at };
  } catch { return null; }
}

// ─── Retrieve Report by Token ─────────────────────────────────────────────────
export async function getReportByToken(env, token) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const reportId = await env.SECURITY_HUB_KV.get(`report_token:${token}`);
    if (!reportId) return null;
    const raw = await env.SECURITY_HUB_KV.get(`report:${reportId}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

// ─── Retrieve Report by ID ────────────────────────────────────────────────────
export async function getReportById(env, reportId) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const raw = await env.SECURITY_HUB_KV.get(`report:${reportId}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

// ─── Store Scan in History ─────────────────────────────────────────────────────
export async function storeScanHistory(env, scanResult, authCtx = {}) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const identity = authCtx.identity || 'anonymous';
    const entry = {
      scan_id:    scanResult.scan_metadata?.scan_id || 'unknown',
      target:     scanResult.target,
      module:     scanResult.module,
      risk_score: scanResult.risk_score,
      risk_level: scanResult.risk_level,
      grade:      scanResult.grade,
      scanned_at: new Date().toISOString(),
      data_source: scanResult.data_source || 'unknown',
    };
    // Push to list for this identity (last 50 scans)
    const key = `history:${identity}`;
    const existing = await env.SECURITY_HUB_KV.get(key);
    const list = existing ? JSON.parse(existing) : [];
    list.unshift(entry);
    if (list.length > 50) list.length = 50;
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(list), { expirationTtl: 86400 * 30 });
  } catch {}
}

// ─── Get Scan History ─────────────────────────────────────────────────────────
export async function getScanHistory(env, authCtx = {}, limit = 20) {
  if (!env?.SECURITY_HUB_KV) return [];
  try {
    const identity = authCtx.identity || 'anonymous';
    const raw = await env.SECURITY_HUB_KV.get(`history:${identity}`);
    if (!raw) return [];
    const list = JSON.parse(raw);
    return list.slice(0, Math.min(limit, 50));
  } catch { return []; }
}
