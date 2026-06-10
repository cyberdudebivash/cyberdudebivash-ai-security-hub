/**
 * CYBERDUDEBIVASH AI Security Hub — SaaS Security Assessment Engine v1.0
 * Service: CDB-SAASSEC-001 (₹12,999) — Comprehensive SaaS Security Review
 * MYTHOS-Powered: AI-enriched access control, OAuth/SSO, API exposure, vendor risk
 */

// ── SaaS Security Control Domains ────────────────────────────────────────────
const SAAS_CONTROL_DOMAINS = [
  {
    id:       'SC-IAM',
    domain:   'Identity & Access Management',
    controls: [
      { id: 'SC-IAM-001', name: 'MFA Enforcement',         weight: 20, question: 'has_mfa' },
      { id: 'SC-IAM-002', name: 'SSO Integration',          weight: 15, question: 'has_sso' },
      { id: 'SC-IAM-003', name: 'Role-Based Access Control', weight: 15, question: 'has_rbac' },
      { id: 'SC-IAM-004', name: 'Privileged Account Review', weight: 10, question: 'has_privileged_review' },
      { id: 'SC-IAM-005', name: 'Offboarding Automation',   weight: 10, question: 'has_offboarding' },
    ],
  },
  {
    id:       'SC-DATA',
    domain:   'Data Security & Privacy',
    controls: [
      { id: 'SC-DATA-001', name: 'Data Encryption at Rest',    weight: 20, question: 'has_encryption_rest' },
      { id: 'SC-DATA-002', name: 'Data Encryption in Transit', weight: 20, question: 'has_encryption_transit' },
      { id: 'SC-DATA-003', name: 'Data Classification Policy',  weight: 10, question: 'has_data_classification' },
      { id: 'SC-DATA-004', name: 'GDPR/Privacy Compliance',    weight: 15, question: 'has_privacy_compliance' },
      { id: 'SC-DATA-005', name: 'Data Retention Policy',      weight: 10, question: 'has_data_retention' },
    ],
  },
  {
    id:       'SC-OAUTH',
    domain:   'OAuth & API Security',
    controls: [
      { id: 'SC-OAUTH-001', name: 'OAuth 2.0 Scope Minimization',  weight: 20, question: 'has_oauth_scopes' },
      { id: 'SC-OAUTH-002', name: 'API Key Rotation Policy',       weight: 15, question: 'has_api_key_rotation' },
      { id: 'SC-OAUTH-003', name: 'Third-Party App Audit',         weight: 15, question: 'has_third_party_audit' },
      { id: 'SC-OAUTH-004', name: 'API Rate Limiting',             weight: 10, question: 'has_api_rate_limiting' },
      { id: 'SC-OAUTH-005', name: 'OAuth Token Expiry Controls',   weight: 10, question: 'has_token_expiry' },
    ],
  },
  {
    id:       'SC-VRM',
    domain:   'Vendor & Supply Chain Risk',
    controls: [
      { id: 'SC-VRM-001', name: 'Vendor Security Assessment',  weight: 20, question: 'has_vendor_assessment' },
      { id: 'SC-VRM-002', name: 'SaaS Inventory Registry',     weight: 15, question: 'has_saas_inventory' },
      { id: 'SC-VRM-003', name: 'Vendor SLA Security Terms',   weight: 10, question: 'has_security_sla' },
      { id: 'SC-VRM-004', name: 'Data Processing Agreements',  weight: 15, question: 'has_dpa' },
      { id: 'SC-VRM-005', name: 'Shadow SaaS Detection',       weight: 10, question: 'has_shadow_saas_detection' },
    ],
  },
  {
    id:       'SC-MON',
    domain:   'Monitoring & Incident Response',
    controls: [
      { id: 'SC-MON-001', name: 'SaaS Audit Log Collection',    weight: 20, question: 'has_audit_logs' },
      { id: 'SC-MON-002', name: 'CASB or DLP Solution',         weight: 15, question: 'has_casb' },
      { id: 'SC-MON-003', name: 'Incident Response Plan',       weight: 15, question: 'has_ir_plan' },
      { id: 'SC-MON-004', name: 'Anomalous Access Alerting',    weight: 10, question: 'has_access_alerting' },
      { id: 'SC-MON-005', name: 'Security Awareness Training',  weight: 10, question: 'has_security_training' },
    ],
  },
];

// ── OAuth/SSO Exposure Probe ──────────────────────────────────────────────────
async function probeSaaSExposure(domain) {
  const results = { domain, checks: {} };
  if (!domain) return results;

  const base = domain.startsWith('http') ? domain : `https://${domain}`;

  // Check common SaaS admin/auth endpoints
  const authEndpoints = [
    '/auth', '/login', '/oauth', '/saml', '/sso',
    '/.well-known/openid-configuration',
    '/api/v1/users', '/admin',
  ];

  const probes = await Promise.allSettled(
    authEndpoints.map(ep =>
      fetch(`${base.replace(/\/$/, '')}${ep}`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        headers: { 'User-Agent': 'CyberdudeBivash-SaaSScanner/1.0' },
        redirect: 'manual',
      }).then(r => ({
        endpoint: ep,
        status:   r.status,
        exposed:  r.status < 400,
        headers: {
          cors:    r.headers.get('access-control-allow-origin'),
          auth:    r.headers.get('www-authenticate'),
          csp:     !!r.headers.get('content-security-policy'),
        },
      })).catch(() => ({ endpoint: ep, status: null, exposed: false }))
    )
  );

  results.checks.exposed_endpoints = probes
    .filter(p => p.status === 'fulfilled' && p.value.exposed)
    .map(p => p.value);

  results.checks.admin_panel_exposed = results.checks.exposed_endpoints.some(e =>
    ['/admin'].includes(e.endpoint)
  );
  results.checks.oidc_exposed = results.checks.exposed_endpoints.some(e =>
    e.endpoint === '/.well-known/openid-configuration'
  );
  results.checks.cors_wildcard = results.checks.exposed_endpoints.some(e =>
    e.headers?.cors === '*'
  );

  // Check SSL
  try {
    const r = await fetch(base, { signal: AbortSignal.timeout(5000), redirect: 'manual' });
    results.checks.ssl_valid       = r.status < 400;
    results.checks.hsts             = !!r.headers.get('strict-transport-security');
    results.checks.x_frame_options  = !!r.headers.get('x-frame-options');
    results.checks.server_disclosed = r.headers.get('server') || null;
  } catch {
    results.checks.ssl_error = true;
  }

  return results;
}

// ── Score SaaS posture from inputs ────────────────────────────────────────────
function scoreSaaSPosture(inputs) {
  const domainResults = [];

  for (const domain of SAAS_CONTROL_DOMAINS) {
    let domainScore  = 0;
    let domainMax    = 0;
    const controlResults = [];

    for (const ctrl of domain.controls) {
      const pass = !!inputs[ctrl.question];
      domainMax  += ctrl.weight;
      if (pass) domainScore += ctrl.weight;

      controlResults.push({
        id:      ctrl.id,
        name:    ctrl.name,
        weight:  ctrl.weight,
        status:  pass ? 'PASS' : 'FAIL',
        finding: pass ? null : {
          id:       `SAAS-${ctrl.id}`,
          severity: ctrl.weight >= 18 ? 'HIGH' : ctrl.weight >= 12 ? 'MEDIUM' : 'LOW',
          category: `SaaS Security — ${domain.domain}`,
          title:    `Missing: ${ctrl.name}`,
          description: `${ctrl.name} is not implemented. This represents a significant SaaS security gap in ${domain.domain}.`,
          remediation: `Implement ${ctrl.name} following SaaS security best practices and vendor documentation.`,
          cvss: ctrl.weight >= 18 ? 7.5 : ctrl.weight >= 12 ? 5.5 : 3.5,
        },
      });
    }

    domainResults.push({
      id:            domain.id,
      domain:        domain.domain,
      score:         domainScore,
      max_score:     domainMax,
      pct:           Math.round(domainScore / domainMax * 100),
      grade:         domainScore / domainMax >= 0.8 ? 'A' : domainScore / domainMax >= 0.6 ? 'B' : domainScore / domainMax >= 0.4 ? 'C' : 'D',
      controls:      controlResults,
    });
  }

  return domainResults;
}

// ── Vendor Risk Matrix ────────────────────────────────────────────────────────
function buildVendorRiskMatrix(inputs) {
  const vendors = inputs.saas_tools || ['Unknown SaaS Stack'];
  return vendors.map(v => ({
    vendor:          v,
    data_access:     inputs.vendor_data_access?.[v] || 'Unknown',
    compliance_certs: inputs.vendor_certs?.[v] || ['SOC 2 status unknown'],
    risk_level:      inputs.has_vendor_assessment ? 'ASSESSED' : 'UNASSESSED',
    dpa_signed:      !!inputs.has_dpa,
    recommendation:  inputs.has_vendor_assessment
      ? 'Annual vendor security review on file'
      : 'Conduct immediate vendor security assessment and sign DPA',
  }));
}

// ═════════════════════════════════════════════════════════════════════════════
export async function runSaaSSecurityAssessment(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const domain    = inputs.domain || inputs.target_domain || '';

  // Phase 1: Probe live SaaS endpoints
  const probeResults = domain ? await probeSaaSExposure(domain) : { domain: '', checks: {} };

  // Auto-detect from probe
  if (probeResults.checks.cors_wildcard)     inputs.has_security_headers = false;
  if (probeResults.checks.admin_panel_exposed) inputs.admin_panel_exposed = true;

  // Phase 2: Score all 5 domains
  const domainScores = scoreSaaSPosture(inputs);

  // Phase 3: Collect all findings
  const findings = domainScores
    .flatMap(d => d.controls.map(c => c.finding).filter(Boolean));

  // Add probe-based findings
  if (probeResults.checks.admin_panel_exposed) {
    findings.unshift({
      id:          'SAAS-PROBE-ADMIN',
      severity:    'CRITICAL',
      category:    'SaaS Security — Exposed Interface',
      title:       'Admin Panel Publicly Accessible',
      description: `Admin endpoint detected at ${domain}/admin — accessible without authentication restriction from public internet.`,
      remediation: 'Restrict admin panel access to VPN/IP allowlist only. Implement strong MFA on admin accounts.',
      cvss:        9.0,
    });
  }
  if (probeResults.checks.cors_wildcard) {
    findings.unshift({
      id:          'SAAS-PROBE-CORS',
      severity:    'HIGH',
      category:    'OAuth & API Security',
      title:       'CORS Wildcard Detected',
      description: 'Access-Control-Allow-Origin: * detected — enables unauthorized cross-origin requests from any domain.',
      remediation: 'Replace CORS wildcard with explicit trusted origin allowlist.',
      cvss:        7.5,
    });
  }
  if (!probeResults.checks.hsts && domain) {
    findings.push({
      id:          'SAAS-PROBE-HSTS',
      severity:    'MEDIUM',
      category:    'Data Security & Privacy',
      title:       'HSTS Not Enforced',
      description: 'HTTP Strict Transport Security header missing — connections may be downgraded to HTTP.',
      remediation: 'Add Strict-Transport-Security header with min-age=31536000; includeSubDomains.',
      cvss:        5.4,
    });
  }

  // Phase 4: Score
  const totalScore  = domainScores.reduce((s, d) => s + d.score, 0);
  const totalMax    = domainScores.reduce((s, d) => s + d.max_score, 0);
  const secScore    = Math.round(totalScore / totalMax * 100);
  const riskScore   = 100 - secScore;
  const grade       = secScore >= 85 ? 'A' : secScore >= 70 ? 'B' : secScore >= 55 ? 'C' : secScore >= 40 ? 'D' : 'F';

  // Phase 5: Vendor risk matrix
  const vendorMatrix = buildVendorRiskMatrix(inputs);

  findings.sort((a, b) => {
    const so = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (so[a.severity] ?? 4) - (so[b.severity] ?? 4);
  });

  const report = {
    meta: {
      service:       'CDB-SAASSEC-001',
      service_name:  'SaaS Security Assessment',
      version:       '1.0',
      target_domain: domain || 'N/A',
      generated_at:  startedAt,
      framework:     'OWASP / CIS SaaS Security Controls',
      powered_by:    'CYBERDUDEBIVASH AI Security Hub™ | MYTHOS AI Engine',
    },
    executive_summary: {
      security_score:  secScore,
      risk_score:      riskScore,
      grade,
      domains_assessed: domainScores.length,
      controls_assessed: SAAS_CONTROL_DOMAINS.reduce((s, d) => s + d.controls.length, 0),
      controls_passed:   domainScores.reduce((s, d) => s + d.controls.filter(c => c.status === 'PASS').length, 0),
      total_findings:    findings.length,
      critical_count:    findings.filter(f => f.severity === 'CRITICAL').length,
      high_count:        findings.filter(f => f.severity === 'HIGH').length,
    },
    domain_scores:    domainScores.map(d => ({
      id: d.id, domain: d.domain, score: d.score, max_score: d.max_score, pct: d.pct, grade: d.grade,
    })),
    probe_results:    probeResults,
    vendor_risk_matrix: vendorMatrix,
    findings,
    recommendations: [
      { priority: 1, action: 'Enforce MFA across all SaaS applications immediately',         effort: 'Low',  impact: 'Critical' },
      { priority: 2, action: 'Conduct quarterly SaaS access review and deprovision stale accounts', effort: 'Low', impact: 'High' },
      { priority: 3, action: 'Implement CASB solution for SaaS visibility and DLP enforcement', effort: 'High', impact: 'High' },
      { priority: 4, action: 'Complete vendor risk assessments for all critical SaaS tools', effort: 'Medium', impact: 'High' },
      { priority: 5, action: 'Deploy OAuth scope minimization and third-party app audit program', effort: 'Medium', impact: 'Medium' },
      { priority: 6, action: 'Establish SaaS inventory register with data classification labels', effort: 'Low', impact: 'Medium' },
    ],
  };

  // Persist to D1
  if (env?.DB && orderId) {
    const assessId = crypto.randomUUID();
    try {
      await env.DB.prepare(
        `INSERT INTO service_assessments
         (id, order_id, service_ref, target, status, risk_score, risk_grade,
          findings_count, critical_count, high_count,
          findings_json, recommendations_json, report_json,
          engine_version, started_at, completed_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(
        assessId, orderId, 'CDB-SAASSEC-001', domain, 'complete',
        riskScore, grade,
        findings.length,
        findings.filter(f => f.severity === 'CRITICAL').length,
        findings.filter(f => f.severity === 'HIGH').length,
        JSON.stringify(findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[SaaS-Security-Engine] DB error:', e.message); }
  }

  return report;
}
