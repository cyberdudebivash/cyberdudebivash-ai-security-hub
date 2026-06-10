/**
 * CYBERDUDEBIVASH AI Security Hub — DevSecOps Security Optimization Engine v1.0
 * Service: CDB-DSO-001 (₹59,999) — End-to-End DevSecOps Security Assessment
 * MYTHOS-Powered: CI/CD, Secrets, SAST/DAST, IaC, Container Security
 */

// ── DevSecOps Control Domains ─────────────────────────────────────────────────
const DEVSECOPS_DOMAINS = [
  {
    id:      'DSO-CICD',
    domain:  'CI/CD Pipeline Security',
    weight_total: 100,
    controls: [
      { id: 'DSO-CICD-001', name: 'Pipeline as Code (version-controlled)',       weight: 15, q: 'has_pipeline_as_code' },
      { id: 'DSO-CICD-002', name: 'Build Artifact Signing & Verification',       weight: 20, q: 'has_artifact_signing' },
      { id: 'DSO-CICD-003', name: 'Dependency Vulnerability Scanning (SCA)',     weight: 20, q: 'has_sca_scanning' },
      { id: 'DSO-CICD-004', name: 'SAST Integration in Pipeline',               weight: 20, q: 'has_sast' },
      { id: 'DSO-CICD-005', name: 'Pipeline Branch Protection Rules',            weight: 15, q: 'has_branch_protection' },
      { id: 'DSO-CICD-006', name: 'Security Gate Enforcement (block on fail)',   weight: 10, q: 'has_security_gates' },
    ],
  },
  {
    id:      'DSO-SECRETS',
    domain:  'Secrets Management',
    weight_total: 100,
    controls: [
      { id: 'DSO-SEC-001', name: 'Centralized Secrets Vault (Vault/AWS SM)',     weight: 25, q: 'has_secrets_vault' },
      { id: 'DSO-SEC-002', name: 'No Hardcoded Secrets in Code',                weight: 30, q: 'no_hardcoded_secrets' },
      { id: 'DSO-SEC-003', name: 'Pre-commit Secret Scanning Hooks',            weight: 20, q: 'has_secret_scanning' },
      { id: 'DSO-SEC-004', name: 'Secret Rotation Policy & Automation',         weight: 15, q: 'has_secret_rotation' },
      { id: 'DSO-SEC-005', name: 'Environment-Specific Secrets Segregation',    weight: 10, q: 'has_secret_segregation' },
    ],
  },
  {
    id:      'DSO-CONTAINER',
    domain:  'Container & Image Security',
    weight_total: 100,
    controls: [
      { id: 'DSO-CTR-001', name: 'Base Image Vulnerability Scanning',           weight: 25, q: 'has_image_scanning' },
      { id: 'DSO-CTR-002', name: 'Non-Root Container Execution',               weight: 20, q: 'runs_non_root' },
      { id: 'DSO-CTR-003', name: 'Immutable Container Tags (no :latest)',       weight: 15, q: 'uses_immutable_tags' },
      { id: 'DSO-CTR-004', name: 'Container Registry Vulnerability Policy',    weight: 15, q: 'has_registry_policy' },
      { id: 'DSO-CTR-005', name: 'Runtime Container Security (Falco/gVisor)',   weight: 15, q: 'has_runtime_security' },
      { id: 'DSO-CTR-006', name: 'Dockerfile Security Best Practices',          weight: 10, q: 'has_dockerfile_security' },
    ],
  },
  {
    id:      'DSO-IAC',
    domain:  'Infrastructure as Code Security',
    weight_total: 100,
    controls: [
      { id: 'DSO-IAC-001', name: 'IaC Security Scanning (Checkov/tfsec)',       weight: 25, q: 'has_iac_scanning' },
      { id: 'DSO-IAC-002', name: 'IaC in Version Control with Code Review',     weight: 20, q: 'has_iac_vcs' },
      { id: 'DSO-IAC-003', name: 'Least Privilege IaC Role Assignment',         weight: 20, q: 'has_iac_least_privilege' },
      { id: 'DSO-IAC-004', name: 'IaC Drift Detection & Prevention',           weight: 15, q: 'has_drift_detection' },
      { id: 'DSO-IAC-005', name: 'Terraform/CloudFormation Security Templates', weight: 20, q: 'has_secure_iac_templates' },
    ],
  },
  {
    id:      'DSO-TESTING',
    domain:  'Security Testing Integration',
    weight_total: 100,
    controls: [
      { id: 'DSO-TEST-001', name: 'DAST Integration (OWASP ZAP/Burp)',          weight: 25, q: 'has_dast' },
      { id: 'DSO-TEST-002', name: 'Security Unit Test Coverage',                weight: 15, q: 'has_security_unit_tests' },
      { id: 'DSO-TEST-003', name: 'Penetration Testing Program (Annual)',       weight: 20, q: 'has_pentest_program' },
      { id: 'DSO-TEST-004', name: 'Security Regression Testing on Releases',   weight: 15, q: 'has_security_regression' },
      { id: 'DSO-TEST-005', name: 'Bug Bounty / Responsible Disclosure',       weight: 15, q: 'has_bug_bounty' },
      { id: 'DSO-TEST-006', name: 'Threat Modeling (STRIDE/PASTA)',             weight: 10, q: 'has_threat_modeling' },
    ],
  },
  {
    id:      'DSO-MONITOR',
    domain:  'Security Monitoring & Response',
    weight_total: 100,
    controls: [
      { id: 'DSO-MON-001', name: 'Production Security Event Logging',           weight: 20, q: 'has_prod_logging' },
      { id: 'DSO-MON-002', name: 'Security Incident Response Runbooks',        weight: 20, q: 'has_ir_runbooks' },
      { id: 'DSO-MON-003', name: 'SBOM Generation (Software Bill of Materials)',weight: 20, q: 'has_sbom' },
      { id: 'DSO-MON-004', name: 'CVE Monitoring for Dependencies',            weight: 20, q: 'has_dependency_monitoring' },
      { id: 'DSO-MON-005', name: 'Security Alerting & On-Call Rotation',       weight: 20, q: 'has_security_alerting' },
    ],
  },
];

// ── Score DevSecOps domains ───────────────────────────────────────────────────
function scoreDevSecOps(inputs) {
  return DEVSECOPS_DOMAINS.map(domain => {
    let score = 0, max = 0;
    const controls = domain.controls.map(ctrl => {
      const pass = !!inputs[ctrl.q];
      max += ctrl.weight;
      if (pass) score += ctrl.weight;

      const sev = ctrl.weight >= 24 ? 'CRITICAL'
                : ctrl.weight >= 18 ? 'HIGH'
                : ctrl.weight >= 13 ? 'MEDIUM' : 'LOW';

      return {
        id:      ctrl.id,
        name:    ctrl.name,
        weight:  ctrl.weight,
        status:  pass ? 'IMPLEMENTED' : 'GAP',
        finding: pass ? null : {
          id:          `DSO-${ctrl.id}`,
          severity:    sev,
          category:    `DevSecOps — ${domain.domain}`,
          title:       `DevSecOps Gap: ${ctrl.name}`,
          description: `${ctrl.name} is not implemented. This creates a significant security vulnerability in your ${domain.domain} pipeline.`,
          remediation: `Implement ${ctrl.name} immediately. Follow OWASP DevSecOps guidelines and vendor documentation for your CI/CD platform.`,
          cvss:        sev === 'CRITICAL' ? 8.5 : sev === 'HIGH' ? 7.0 : sev === 'MEDIUM' ? 5.5 : 3.5,
        },
      };
    });

    return {
      id:     domain.id,
      domain: domain.domain,
      score, max,
      pct:    Math.round(score / max * 100),
      grade:  score/max >= 0.85 ? 'A' : score/max >= 0.70 ? 'B' : score/max >= 0.55 ? 'C' : score/max >= 0.35 ? 'D' : 'F',
      controls,
    };
  });
}

// ── Maturity Level ────────────────────────────────────────────────────────────
function computeDevSecOpsMaturity(overallScore) {
  if (overallScore >= 85) return { level: 5, name: 'OPTIMIZING',  description: 'Proactive security culture; continuous improvement and innovation' };
  if (overallScore >= 70) return { level: 4, name: 'MANAGED',     description: 'Security is measured, controlled, and predictable' };
  if (overallScore >= 55) return { level: 3, name: 'DEFINED',     description: 'Security processes are documented, standardized, and integrated' };
  if (overallScore >= 35) return { level: 2, name: 'DEVELOPING',  description: 'Some security practices exist but inconsistent across teams' };
  return                         { level: 1, name: 'INITIAL',     description: 'Security is ad-hoc, reactive, and largely absent from dev pipeline' };
}

// ── Implementation Playbook ───────────────────────────────────────────────────
function buildImplementationPlaybook(domainResults) {
  const allGaps = domainResults.flatMap(d =>
    d.controls.filter(c => c.status === 'GAP').map(c => ({
      domain:   d.domain,
      ...c.finding,
    }))
  );

  const critical = allGaps.filter(g => g.severity === 'CRITICAL');
  const high     = allGaps.filter(g => g.severity === 'HIGH');

  return {
    sprint_1: {
      name:    'Security Foundations',
      duration: '2 weeks',
      items:   critical.slice(0, 5).map(g => g.title),
    },
    sprint_2: {
      name:    'Pipeline Hardening',
      duration: '4 weeks',
      items:   high.slice(0, 8).map(g => g.title),
    },
    sprint_3: {
      name:    'Advanced Controls',
      duration: '8 weeks',
      items:   allGaps.filter(g => g.severity === 'MEDIUM').slice(0, 10).map(g => g.title),
    },
    tools_recommended: [
      { category: 'SAST',          tools: ['SonarQube', 'Semgrep', 'Checkmarx'] },
      { category: 'SCA',           tools: ['Snyk', 'Dependabot', 'WhiteSource'] },
      { category: 'Secrets',       tools: ['HashiCorp Vault', 'AWS Secrets Manager', 'GitLeaks'] },
      { category: 'Container',     tools: ['Trivy', 'Falco', 'Clair'] },
      { category: 'IaC',           tools: ['Checkov', 'tfsec', 'Terrascan'] },
      { category: 'DAST',          tools: ['OWASP ZAP', 'Burp Suite', 'Nuclei'] },
    ],
  };
}

// ═════════════════════════════════════════════════════════════════════════════
export async function runDevSecOpsAssessment(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const org       = inputs.company || inputs.organization || 'Your Organization';

  const domainResults = scoreDevSecOps(inputs);
  const findings      = domainResults.flatMap(d =>
    d.controls.map(c => c.finding).filter(Boolean)
  );

  findings.sort((a, b) => {
    const so = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (so[a.severity] ?? 4) - (so[b.severity] ?? 4);
  });

  const totalScore  = domainResults.reduce((s, d) => s + d.score, 0);
  const totalMax    = domainResults.reduce((s, d) => s + d.max, 0);
  const secScore    = Math.round(totalScore / totalMax * 100);
  const riskScore   = 100 - secScore;
  const grade       = secScore >= 85 ? 'A' : secScore >= 70 ? 'B' : secScore >= 55 ? 'C' : secScore >= 40 ? 'D' : 'F';
  const maturity    = computeDevSecOpsMaturity(secScore);
  const playbook    = buildImplementationPlaybook(domainResults);

  const report = {
    meta: {
      service:       'CDB-DSO-001',
      service_name:  'DevSecOps Security Optimization',
      version:       '1.0',
      organization:  org,
      generated_at:  startedAt,
      framework:     'OWASP DevSecOps / NIST SSDF / CIS DevSecOps',
      powered_by:    'CYBERDUDEBIVASH AI Security Hub™ | MYTHOS AI Engine',
    },
    executive_summary: {
      security_score:       secScore,
      risk_score:           riskScore,
      grade,
      maturity_level:       maturity.level,
      maturity_name:        maturity.name,
      maturity_description: maturity.description,
      domains_assessed:     domainResults.length,
      controls_assessed:    DEVSECOPS_DOMAINS.reduce((s, d) => s + d.controls.length, 0),
      controls_implemented: domainResults.reduce((s, d) =>
        s + d.controls.filter(c => c.status === 'IMPLEMENTED').length, 0),
      total_gaps:           findings.length,
      critical_gaps:        findings.filter(f => f.severity === 'CRITICAL').length,
      high_gaps:            findings.filter(f => f.severity === 'HIGH').length,
    },
    maturity_model:    maturity,
    domain_scores: domainResults.map(d => ({
      id: d.id, domain: d.domain, score: d.score, max: d.max, pct: d.pct, grade: d.grade,
    })),
    findings,
    implementation_playbook: playbook,
    recommendations: [
      { priority: 1, action: 'Eliminate all hardcoded secrets — scan entire codebase immediately',       effort: 'Medium', impact: 'Critical' },
      { priority: 2, action: 'Integrate SAST and SCA into all CI/CD pipelines with security gates',     effort: 'Medium', impact: 'Critical' },
      { priority: 3, action: 'Deploy centralized secrets vault (HashiCorp Vault or cloud-native)',       effort: 'Medium', impact: 'High' },
      { priority: 4, action: 'Enable branch protection and require security review on all merges',       effort: 'Low',    impact: 'High' },
      { priority: 5, action: 'Scan all container images in CI/CD and block HIGH+ vulnerabilities',       effort: 'Low',    impact: 'High' },
      { priority: 6, action: 'Generate SBOM for all production releases to enable supply chain tracking',effort: 'Medium', impact: 'High' },
      { priority: 7, action: 'Implement IaC security scanning with Checkov or tfsec',                   effort: 'Low',    impact: 'Medium' },
      { priority: 8, action: 'Establish annual penetration testing program and bug bounty program',      effort: 'High',   impact: 'High' },
    ],
  };

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
        assessId, orderId, 'CDB-DSO-001', org, 'complete',
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
    } catch (e) { console.error('[DevSecOps-Engine] DB error:', e.message); }
  }

  return report;
}
