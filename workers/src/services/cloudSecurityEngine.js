/**
 * CYBERDUDEBIVASH AI Security Hub — Cloud Security Audit Engine v1.0
 * Service: CDB-CSAU-001 (₹9,999) — Cloud security controls, IAM, exposure analysis
 */

// ── Cloud Security Checks (CIS-aligned) ──────────────────────────────────────
const CLOUD_CONTROLS = {
  IAM: [
    { id: 'IAM-001', title: 'MFA on Root/Admin Accounts',           severity: 'CRITICAL', weight: 20, key: 'has_root_mfa' },
    { id: 'IAM-002', title: 'Least Privilege Access Policy',        severity: 'HIGH',     weight: 15, key: 'has_least_privilege' },
    { id: 'IAM-003', title: 'No Long-Lived Access Keys',            severity: 'HIGH',     weight: 12, key: 'rotates_keys' },
    { id: 'IAM-004', title: 'Privileged Account Review (90-day)',   severity: 'MEDIUM',   weight: 10, key: 'reviews_access' },
    { id: 'IAM-005', title: 'Service Account Permissions Scoped',   severity: 'HIGH',     weight: 12, key: 'scoped_service_accounts' },
    { id: 'IAM-006', title: 'Federated Identity (SSO) Configured',  severity: 'MEDIUM',   weight: 8,  key: 'has_sso' },
  ],
  NETWORK: [
    { id: 'NET-001', title: 'Security Groups Follow Least Privilege', severity: 'HIGH',   weight: 15, key: 'least_priv_sg' },
    { id: 'NET-002', title: 'No Open Inbound 0.0.0.0/0 on DB Ports', severity: 'CRITICAL', weight: 20, key: 'no_open_db_ports' },
    { id: 'NET-003', title: 'VPC Flow Logs Enabled',                  severity: 'HIGH',   weight: 10, key: 'has_flow_logs' },
    { id: 'NET-004', title: 'Private Subnets for Databases',          severity: 'HIGH',   weight: 12, key: 'private_db_subnets' },
    { id: 'NET-005', title: 'WAF Deployed on Public Endpoints',       severity: 'MEDIUM', weight: 8,  key: 'has_waf' },
    { id: 'NET-006', title: 'DDoS Protection Enabled',                severity: 'MEDIUM', weight: 5,  key: 'has_ddos_protection' },
  ],
  DATA: [
    { id: 'DATA-001', title: 'Encryption at Rest (All Storage)',      severity: 'HIGH',   weight: 15, key: 'encrypt_at_rest' },
    { id: 'DATA-002', title: 'Encryption in Transit (TLS Everywhere)', severity: 'HIGH',  weight: 12, key: 'encrypt_in_transit' },
    { id: 'DATA-003', title: 'S3/Blob Buckets Not Publicly Accessible', severity: 'CRITICAL', weight: 20, key: 'no_public_buckets' },
    { id: 'DATA-004', title: 'Customer-Managed Encryption Keys (CMEK)', severity: 'MEDIUM', weight: 8, key: 'has_cmek' },
    { id: 'DATA-005', title: 'Data Classification Policy Implemented',  severity: 'MEDIUM', weight: 6, key: 'has_data_classification' },
  ],
  LOGGING: [
    { id: 'LOG-001', title: 'CloudTrail/Audit Logging Enabled',       severity: 'HIGH',   weight: 15, key: 'has_audit_logging' },
    { id: 'LOG-002', title: 'Log Retention ≥ 12 Months',              severity: 'MEDIUM', weight: 8,  key: 'adequate_log_retention' },
    { id: 'LOG-003', title: 'Alerting on Privileged Actions',         severity: 'HIGH',   weight: 10, key: 'alerts_on_priv_actions' },
    { id: 'LOG-004', title: 'SIEM Integration for Cloud Logs',        severity: 'MEDIUM', weight: 7,  key: 'has_cloud_siem' },
    { id: 'LOG-005', title: 'Log Integrity Validation',               severity: 'MEDIUM', weight: 5,  key: 'validates_log_integrity' },
  ],
  COMPUTE: [
    { id: 'COMP-001', title: 'Vulnerability Scanning on VMs/Containers', severity: 'HIGH', weight: 12, key: 'has_vm_scanning' },
    { id: 'COMP-002', title: 'Automated Patch Management',              severity: 'HIGH',  weight: 12, key: 'has_auto_patching' },
    { id: 'COMP-003', title: 'Container Images Scanned Pre-Deploy',     severity: 'HIGH',  weight: 10, key: 'scans_container_images' },
    { id: 'COMP-004', title: 'No Privileged Containers in Production',  severity: 'HIGH',  weight: 10, key: 'no_privileged_containers' },
    { id: 'COMP-005', title: 'Instance Metadata Service Protection',    severity: 'MEDIUM', weight: 8, key: 'has_imds_protection' },
  ],
};

// ── Cloud exposure check via public indicators ────────────────────────────────
async function checkPublicCloudExposure(domain) {
  const results = { public_buckets: [], exposed_services: [], cloud_provider: null };
  if (!domain) return results;

  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  // Common public S3/storage patterns
  const bucketCandidates = [
    `${cleanDomain}`,
    `${cleanDomain.split('.')[0]}`,
    `${cleanDomain.split('.')[0]}-backup`,
    `${cleanDomain.split('.')[0]}-assets`,
    `${cleanDomain.split('.')[0]}-data`,
    `${cleanDomain.split('.')[0]}-prod`,
    `${cleanDomain.split('.')[0]}-dev`,
    `${cleanDomain.split('.')[0]}-staging`,
  ];

  const bucketChecks = await Promise.allSettled(
    bucketCandidates.slice(0, 4).map(name =>
      fetch(`https://${name}.s3.amazonaws.com`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(4000),
      }).then(r => ({ bucket: name, url: `https://${name}.s3.amazonaws.com`, status: r.status, public: r.status !== 403 && r.status !== 404 }))
        .catch(() => ({ bucket: name, public: false }))
    )
  );

  for (const r of bucketChecks) {
    if (r.status === 'fulfilled' && r.value.public && r.value.status && r.value.status !== 404) {
      if (r.value.status === 200) {
        results.public_buckets.push({
          name:   r.value.bucket,
          url:    r.value.url,
          status: r.value.status,
          risk:   'CRITICAL — Publicly accessible storage bucket',
        });
      }
    }
  }

  // Detect cloud provider via DNS
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=CNAME`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) }
    );
    if (r.ok) {
      const d = await r.json();
      const cname = d.Answer?.find(a => a.type === 5)?.data || '';
      if (cname.includes('aws') || cname.includes('amazonaws')) results.cloud_provider = 'AWS';
      else if (cname.includes('azure') || cname.includes('windows.net')) results.cloud_provider = 'Azure';
      else if (cname.includes('google') || cname.includes('appspot') || cname.includes('cloudfunctions')) results.cloud_provider = 'GCP';
      else if (cname.includes('cloudflare') || cname.includes('workers.dev')) results.cloud_provider = 'Cloudflare';
      else if (cname.includes('herokuapp')) results.cloud_provider = 'Heroku';
    }
  } catch {}

  return results;
}

// ── Score cloud posture from inputs ──────────────────────────────────────────
function scoreCloudPosture(inputs) {
  const allControls = Object.values(CLOUD_CONTROLS).flat();
  let score     = 0;
  const maxScore = allControls.reduce((s, c) => s + c.weight, 0);
  const findings = [];
  const passed   = [];

  for (const ctrl of allControls) {
    const pass = inputs[ctrl.key] === true || inputs[ctrl.key] === 'true' || inputs[ctrl.key] === 1;
    if (pass) {
      score += ctrl.weight;
      passed.push(ctrl.id);
    } else {
      findings.push({
        id:          `CLOUD-${ctrl.id}`,
        severity:    ctrl.severity,
        category:    Object.entries(CLOUD_CONTROLS).find(([, ctrls]) => ctrls.includes(ctrl))?.[0] || 'General',
        title:       `Missing: ${ctrl.title}`,
        description: `Cloud control ${ctrl.id} is not implemented: ${ctrl.title}`,
        control_id:  ctrl.id,
        remediation: getCloudControlRemediation(ctrl.id),
      });
    }
  }

  return {
    score: Math.round((score / maxScore) * 100),
    findings,
    passed,
    maxScore,
    earnedScore: score,
  };
}

function getCloudControlRemediation(id) {
  const map = {
    'IAM-001': 'Enable MFA on all root/admin/break-glass accounts immediately. Use hardware MFA tokens for privileged accounts.',
    'IAM-002': 'Audit all IAM roles/policies. Remove wildcard (*) permissions. Apply least privilege using IAM access analyzer.',
    'IAM-003': 'Rotate all IAM access keys. Enable key age alerting. Consider IAM roles over long-lived keys.',
    'IAM-004': 'Conduct quarterly access reviews. Remove stale accounts within 30 days of role changes.',
    'IAM-005': 'Scope all service account permissions to minimum required. Prefer Workload Identity over service account keys.',
    'NET-001': 'Review all security groups/NSGs. Remove any rule with 0.0.0.0/0 on non-public ports.',
    'NET-002': 'Immediately remove 0.0.0.0/0 inbound rules on ports 3306, 5432, 6379, 27017. Use VPC peering or Private Link.',
    'NET-003': 'Enable VPC Flow Logs on all VPCs. Retain for minimum 90 days. Send to centralized logging.',
    'NET-004': 'Move all databases to private subnets. Use VPC endpoints for managed services.',
    'NET-005': 'Deploy WAF on all public-facing applications. Use AWS WAF, Azure WAF, or Cloudflare WAF.',
    'DATA-001': 'Enable encryption at rest on all storage (S3, RDS, EBS, Azure Disk, GCS). Use managed keys minimum.',
    'DATA-002': 'Enforce TLS 1.2+ on all internal and external traffic. Use strict transport security.',
    'DATA-003': 'Immediately audit all S3/Blob/GCS buckets. Enable Block Public Access. Review bucket policies.',
    'LOG-001': 'Enable CloudTrail/Activity Log/Cloud Audit Log with multi-region coverage. Protect log files from deletion.',
    'LOG-003': 'Configure alerts for: root login, MFA disable, security group changes, IAM policy changes.',
    'COMP-001': 'Enable native vulnerability assessment (AWS Inspector, GCP Security Command Center, Defender for Cloud).',
    'COMP-002': 'Enable auto-patching for OS and middleware. Enforce patching SLA: Critical=24h, High=7d.',
    'COMP-003': 'Integrate container image scanning in CI/CD (Trivy, Snyk, AWS ECR scan, GCP Artifact Registry).',
  };
  return map[id] || 'Review and implement this cloud security control per CIS Cloud Security Benchmarks.';
}

export async function runCloudSecurityAudit(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const domain    = (inputs.domain || inputs.target_domain || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  const cloudProvider = inputs.cloud_provider || 'Multi-Cloud';

  // Run posture scoring + public exposure check in parallel
  const [postureScore, publicExposure] = await Promise.all([
    Promise.resolve(scoreCloudPosture(inputs)),
    domain ? checkPublicCloudExposure(domain) : Promise.resolve({ public_buckets: [], exposed_services: [], cloud_provider: null }),
  ]);

  // Add public bucket findings
  for (const bucket of publicExposure.public_buckets) {
    postureScore.findings.unshift({
      id:          `CLOUD-PUBLIC-BUCKET-${bucket.name}`,
      severity:    'CRITICAL',
      category:    'DATA',
      title:       `Public Storage Bucket: ${bucket.url}`,
      description: bucket.risk,
      url:         bucket.url,
      remediation: 'Immediately enable Block Public Access on this bucket. Review all bucket policies and ACLs.',
    });
  }

  const riskScore = Math.max(0, 100 - postureScore.score);
  const grade     = postureScore.score >= 85 ? 'A' : postureScore.score >= 70 ? 'B' : postureScore.score >= 55 ? 'C' : postureScore.score >= 40 ? 'D' : 'F';

  postureScore.findings.sort((a, b) => {
    const so = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (so[a.severity] ?? 4) - (so[b.severity] ?? 4);
  });

  // Domain-based scores
  const domainScores = Object.entries(CLOUD_CONTROLS).map(([domain_, controls]) => {
    const domainControls = controls;
    const passed = domainControls.filter(c => inputs[c.key] === true || inputs[c.key] === 'true').length;
    return {
      domain: domain_,
      score:  Math.round((passed / domainControls.length) * 100),
      passed,
      total:  domainControls.length,
      status: passed === domainControls.length ? 'COMPLIANT' : passed > domainControls.length / 2 ? 'PARTIAL' : 'NON_COMPLIANT',
    };
  });

  const report = {
    meta: {
      service:        'CDB-CSAU-001',
      service_name:   'Cloud Security Audit',
      version:        '1.0',
      domain:         domain || 'N/A',
      cloud_provider: publicExposure.cloud_provider || cloudProvider,
      generated_at:   startedAt,
      framework:      'CIS Cloud Security Benchmarks v1.5 / CSA CCM v4',
      powered_by:     'CYBERDUDEBIVASH AI Security Hub™',
    },
    executive_summary: {
      security_score:    postureScore.score,
      risk_score:        riskScore,
      grade,
      verdict:           postureScore.score >= 75 ? 'SECURE' : postureScore.score >= 55 ? 'MODERATE' : 'HIGH_RISK',
      total_controls:    Object.values(CLOUD_CONTROLS).flat().length,
      controls_passing:  postureScore.passed.length,
      controls_failing:  postureScore.findings.length,
      critical_findings: postureScore.findings.filter(f => f.severity === 'CRITICAL').length,
      high_findings:     postureScore.findings.filter(f => f.severity === 'HIGH').length,
      public_buckets:    publicExposure.public_buckets.length,
      cloud_provider:    publicExposure.cloud_provider || cloudProvider,
    },
    control_domain_scores: domainScores,
    public_exposure:       publicExposure,
    findings:              postureScore.findings,
    cloud_security_roadmap: [
      { phase: 'Immediate (Week 1)', actions: postureScore.findings.filter(f => f.severity === 'CRITICAL').map(f => f.title) },
      { phase: 'Short-term (Month 1)', actions: postureScore.findings.filter(f => f.severity === 'HIGH').map(f => f.title) },
      { phase: 'Medium-term (Quarter)', actions: postureScore.findings.filter(f => f.severity === 'MEDIUM').map(f => f.title) },
    ],
    recommendations: [
      ...(publicExposure.public_buckets.length > 0 ? [{
        priority: 1, action: `Secure ${publicExposure.public_buckets.length} publicly accessible storage bucket(s) immediately`,
        effort: 'Low', impact: 'Critical',
      }] : []),
      { priority: 2, action: 'Enable MFA on all privileged cloud accounts', effort: 'Low', impact: 'Critical' },
      { priority: 3, action: 'Enable audit logging across all cloud services with 12-month retention', effort: 'Low', impact: 'High' },
      { priority: 4, action: 'Implement least privilege IAM and quarterly access reviews', effort: 'Medium', impact: 'High' },
      { priority: 5, action: 'Deploy CSPM (Cloud Security Posture Management) for continuous monitoring', effort: 'Medium', impact: 'High' },
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
        assessId, orderId, 'CDB-CSAU-001', domain || cloudProvider, 'complete',
        riskScore, grade,
        postureScore.findings.length,
        postureScore.findings.filter(f => f.severity === 'CRITICAL').length,
        postureScore.findings.filter(f => f.severity === 'HIGH').length,
        JSON.stringify(postureScore.findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[Cloud-Security-Engine] DB error:', e.message); }
  }

  return report;
}
