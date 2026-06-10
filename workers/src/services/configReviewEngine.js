/**
 * CYBERDUDEBIVASH AI Security Hub — Security Configuration Review Engine v1.0
 * Service: CDB-SCRA-001 (₹4,999) — CIS Benchmark-Based Configuration Audit
 * MYTHOS-Powered: Automated CIS controls scoring + hardening roadmap
 */

// ── CIS Benchmark Control Domains ─────────────────────────────────────────────
const CIS_DOMAINS = [
  {
    id:       'CIS-AM',
    domain:   'Asset Management',
    cis_ref:  'CIS Control 1-2',
    controls: [
      { id: 'CIS-AM-001', name: 'Hardware Asset Inventory',        weight: 15, q: 'has_asset_inventory' },
      { id: 'CIS-AM-002', name: 'Software Asset Inventory',        weight: 15, q: 'has_software_inventory' },
      { id: 'CIS-AM-003', name: 'Unauthorized Device Detection',   weight: 20, q: 'has_unauthorized_device_detection' },
      { id: 'CIS-AM-004', name: 'DHCP Log Management',             weight: 10, q: 'has_dhcp_logging' },
    ],
  },
  {
    id:       'CIS-AC',
    domain:   'Access Control',
    cis_ref:  'CIS Control 5-6',
    controls: [
      { id: 'CIS-AC-001', name: 'Account Management Policy',        weight: 20, q: 'has_account_policy' },
      { id: 'CIS-AC-002', name: 'Multi-Factor Authentication',      weight: 25, q: 'has_mfa' },
      { id: 'CIS-AC-003', name: 'Privileged Access Management',     weight: 20, q: 'has_pam' },
      { id: 'CIS-AC-004', name: 'Password Policy Enforcement',      weight: 15, q: 'has_password_policy' },
      { id: 'CIS-AC-005', name: 'Default Password Remediation',     weight: 20, q: 'no_default_passwords' },
    ],
  },
  {
    id:       'CIS-CD',
    domain:   'Continuous Configuration Management',
    cis_ref:  'CIS Control 4',
    controls: [
      { id: 'CIS-CD-001', name: 'Secure Configuration Baseline',    weight: 20, q: 'has_config_baseline' },
      { id: 'CIS-CD-002', name: 'Configuration Change Management',  weight: 15, q: 'has_change_management' },
      { id: 'CIS-CD-003', name: 'CIS Benchmark Hardening Applied',  weight: 25, q: 'has_cis_hardening' },
      { id: 'CIS-CD-004', name: 'Infrastructure as Code Security',  weight: 15, q: 'has_iac_security' },
    ],
  },
  {
    id:       'CIS-VM',
    domain:   'Vulnerability Management',
    cis_ref:  'CIS Control 7',
    controls: [
      { id: 'CIS-VM-001', name: 'Patch Management Program',         weight: 25, q: 'has_patch_management' },
      { id: 'CIS-VM-002', name: 'Vulnerability Scanning Cadence',   weight: 20, q: 'has_vuln_scanning' },
      { id: 'CIS-VM-003', name: 'Critical Patch SLA (<30 days)',    weight: 20, q: 'has_critical_patch_sla' },
      { id: 'CIS-VM-004', name: 'End-of-Life System Tracking',      weight: 15, q: 'tracks_eol_systems' },
    ],
  },
  {
    id:       'CIS-LOG',
    domain:   'Audit Log Management',
    cis_ref:  'CIS Control 8',
    controls: [
      { id: 'CIS-LOG-001', name: 'Centralized Log Collection',      weight: 20, q: 'has_centralized_logging' },
      { id: 'CIS-LOG-002', name: 'Log Retention Policy (≥90 days)', weight: 15, q: 'has_log_retention' },
      { id: 'CIS-LOG-003', name: 'SIEM or Log Analysis Platform',   weight: 20, q: 'has_siem' },
      { id: 'CIS-LOG-004', name: 'Privileged Command Logging',      weight: 15, q: 'has_privileged_cmd_logging' },
      { id: 'CIS-LOG-005', name: 'Log Integrity Protection',        weight: 10, q: 'has_log_integrity' },
    ],
  },
  {
    id:       'CIS-NET',
    domain:   'Network Security',
    cis_ref:  'CIS Control 12-13',
    controls: [
      { id: 'CIS-NET-001', name: 'Network Segmentation',            weight: 20, q: 'has_network_segmentation' },
      { id: 'CIS-NET-002', name: 'Firewall Rule Management',        weight: 20, q: 'has_firewall_management' },
      { id: 'CIS-NET-003', name: 'DNS Filtering',                   weight: 10, q: 'has_dns_filtering' },
      { id: 'CIS-NET-004', name: 'IDS/IPS Deployment',             weight: 15, q: 'has_ids_ips' },
      { id: 'CIS-NET-005', name: 'Remote Access VPN Security',      weight: 15, q: 'has_vpn_security' },
    ],
  },
];

// ── Score CIS controls from inputs ────────────────────────────────────────────
function scoreCISControls(inputs) {
  const domainResults = [];

  for (const domain of CIS_DOMAINS) {
    let score = 0, max = 0;
    const controls = [];

    for (const ctrl of domain.controls) {
      const pass = !!inputs[ctrl.q];
      max += ctrl.weight;
      if (pass) score += ctrl.weight;

      controls.push({
        id:      ctrl.id,
        name:    ctrl.name,
        cis_ref: domain.cis_ref,
        weight:  ctrl.weight,
        status:  pass ? 'COMPLIANT' : 'GAP',
        finding: pass ? null : {
          id:          `CONFIG-${ctrl.id}`,
          severity:    ctrl.weight >= 20 ? 'HIGH' : ctrl.weight >= 14 ? 'MEDIUM' : 'LOW',
          category:    `Configuration — ${domain.domain}`,
          title:       `CIS Gap: ${ctrl.name} (${ctrl.id})`,
          description: `${ctrl.name} does not meet CIS benchmark requirements in ${domain.domain}. Reference: ${domain.cis_ref}.`,
          remediation: `Implement ${ctrl.name} per CIS Benchmarks ${domain.cis_ref}. Establish policy, deploy tool, verify coverage.`,
          cvss:        ctrl.weight >= 20 ? 6.5 : ctrl.weight >= 14 ? 4.5 : 2.5,
          cis_control: domain.cis_ref,
        },
      });
    }

    domainResults.push({
      id:        domain.id,
      domain:    domain.domain,
      cis_ref:   domain.cis_ref,
      score, max,
      pct:       Math.round(score / max * 100),
      grade:     score/max >= 0.85 ? 'A' : score/max >= 0.70 ? 'B' : score/max >= 0.50 ? 'C' : 'D',
      controls,
    });
  }

  return domainResults;
}

// ── Hardening Recommendations ─────────────────────────────────────────────────
function generateHardeningRoadmap(domainResults) {
  const phases = [
    { phase: 1, name: 'Critical Hardening',   timeline: '0-30 days',   actions: [] },
    { phase: 2, name: 'Core Controls',        timeline: '30-90 days',  actions: [] },
    { phase: 3, name: 'Advanced Hardening',   timeline: '90-180 days', actions: [] },
  ];

  for (const d of domainResults) {
    for (const ctrl of d.controls) {
      if (ctrl.status === 'COMPLIANT') continue;
      const action = `[${d.cis_ref}] Implement ${ctrl.name}`;
      if (ctrl.finding?.severity === 'HIGH')   phases[0].actions.push(action);
      else if (ctrl.finding?.severity === 'MEDIUM') phases[1].actions.push(action);
      else                                          phases[2].actions.push(action);
    }
  }

  return phases.filter(p => p.actions.length > 0);
}

// ── Benchmark comparison table ─────────────────────────────────────────────────
function buildBenchmarkComparison(domainResults) {
  return domainResults.map(d => ({
    domain:          d.domain,
    your_score:      `${d.pct}%`,
    industry_avg:    '62%',
    best_practice:   '85%',
    gap:             `${Math.max(0, 85 - d.pct)}%`,
    priority:        d.pct < 50 ? 'CRITICAL' : d.pct < 70 ? 'HIGH' : 'MEDIUM',
  }));
}

// ═════════════════════════════════════════════════════════════════════════════
export async function runConfigReviewAssessment(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const org       = inputs.company || inputs.organization || 'Your Organization';

  // Score all CIS domains
  const domainResults  = scoreCISControls(inputs);
  const findings       = domainResults.flatMap(d =>
    d.controls.map(c => c.finding).filter(Boolean)
  );

  findings.sort((a, b) => {
    const so = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return (so[a.severity] ?? 3) - (so[b.severity] ?? 3);
  });

  const totalScore  = domainResults.reduce((s, d) => s + d.score, 0);
  const totalMax    = domainResults.reduce((s, d) => s + d.max, 0);
  const secScore    = Math.round(totalScore / totalMax * 100);
  const riskScore   = 100 - secScore;
  const grade       = secScore >= 85 ? 'A' : secScore >= 70 ? 'B' : secScore >= 55 ? 'C' : secScore >= 40 ? 'D' : 'F';

  const hardeningRoadmap    = generateHardeningRoadmap(domainResults);
  const benchmarkComparison = buildBenchmarkComparison(domainResults);

  const report = {
    meta: {
      service:       'CDB-SCRA-001',
      service_name:  'Security Configuration Review & Audit',
      version:       '1.0',
      organization:  org,
      generated_at:  startedAt,
      framework:     'CIS Controls v8 / CIS Benchmarks',
      powered_by:    'CYBERDUDEBIVASH AI Security Hub™ | MYTHOS AI Engine',
    },
    executive_summary: {
      security_score:      secScore,
      risk_score:          riskScore,
      grade,
      organization:        org,
      cis_domains_assessed: domainResults.length,
      controls_assessed:    CIS_DOMAINS.reduce((s, d) => s + d.controls.length, 0),
      controls_compliant:   domainResults.reduce((s, d) =>
        s + d.controls.filter(c => c.status === 'COMPLIANT').length, 0),
      total_gaps:           findings.length,
      high_gaps:            findings.filter(f => f.severity === 'HIGH').length,
      medium_gaps:          findings.filter(f => f.severity === 'MEDIUM').length,
    },
    domain_scores: domainResults.map(d => ({
      id: d.id, domain: d.domain, cis_ref: d.cis_ref,
      score: d.score, max: d.max, pct: d.pct, grade: d.grade,
    })),
    benchmark_comparison:  benchmarkComparison,
    findings,
    hardening_roadmap:     hardeningRoadmap,
    recommendations: [
      { priority: 1, action: 'Implement MFA and Privileged Access Management immediately',        effort: 'Medium', impact: 'Critical' },
      { priority: 2, action: 'Establish centralized logging with 90-day retention policy',         effort: 'Medium', impact: 'High' },
      { priority: 3, action: 'Apply CIS Benchmark hardening baseline to all systems',              effort: 'High',   impact: 'High' },
      { priority: 4, action: 'Deploy vulnerability scanning with monthly cadence and patch SLA',   effort: 'Medium', impact: 'High' },
      { priority: 5, action: 'Implement network segmentation and firewall rule review program',    effort: 'High',   impact: 'Medium' },
      { priority: 6, action: 'Establish complete asset inventory covering hardware and software',  effort: 'Low',    impact: 'Medium' },
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
        assessId, orderId, 'CDB-SCRA-001', org, 'complete',
        riskScore, grade,
        findings.length, 0,
        findings.filter(f => f.severity === 'HIGH').length,
        JSON.stringify(findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[ConfigReview-Engine] DB error:', e.message); }
  }

  return report;
}
