/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Hunting Readiness Engine v1.0
 * Service: CDB-THR-001 (₹14,999) — MITRE ATT&CK-based readiness assessment
 */

// ── MITRE ATT&CK v15 key techniques ──────────────────────────────────────────
const MITRE_TACTICS = [
  {
    id: 'TA0001', name: 'Initial Access', color: '#e74c3c',
    key_techniques: [
      { id: 'T1566', name: 'Phishing', sub: 'T1566.001/002/004' },
      { id: 'T1190', name: 'Exploit Public-Facing Application' },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1195', name: 'Supply Chain Compromise' },
    ],
  },
  {
    id: 'TA0002', name: 'Execution', color: '#e67e22',
    key_techniques: [
      { id: 'T1059', name: 'Command & Scripting Interpreter' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1204', name: 'User Execution' },
    ],
  },
  {
    id: 'TA0003', name: 'Persistence', color: '#f39c12',
    key_techniques: [
      { id: 'T1053', name: 'Scheduled Task' },
      { id: 'T1098', name: 'Account Manipulation' },
      { id: 'T1543', name: 'Create/Modify System Process' },
    ],
  },
  {
    id: 'TA0004', name: 'Privilege Escalation', color: '#27ae60',
    key_techniques: [
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
      { id: 'T1134', name: 'Access Token Manipulation' },
    ],
  },
  {
    id: 'TA0005', name: 'Defense Evasion', color: '#16a085',
    key_techniques: [
      { id: 'T1027', name: 'Obfuscated Files/Information' },
      { id: 'T1070', name: 'Indicator Removal' },
      { id: 'T1562', name: 'Impair Defenses' },
    ],
  },
  {
    id: 'TA0006', name: 'Credential Access', color: '#2980b9',
    key_techniques: [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1539', name: 'Steal Web Session Cookie' },
    ],
  },
  {
    id: 'TA0007', name: 'Discovery', color: '#8e44ad',
    key_techniques: [
      { id: 'T1018', name: 'Remote System Discovery' },
      { id: 'T1083', name: 'File and Directory Discovery' },
      { id: 'T1046', name: 'Network Service Scanning' },
    ],
  },
  {
    id: 'TA0008', name: 'Lateral Movement', color: '#c0392b',
    key_techniques: [
      { id: 'T1021', name: 'Remote Services' },
      { id: 'T1550', name: 'Use Alternate Auth Material' },
    ],
  },
  {
    id: 'TA0009', name: 'Collection', color: '#e74c3c',
    key_techniques: [
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1074', name: 'Data Staged' },
      { id: 'T1560', name: 'Archive Collected Data' },
    ],
  },
  {
    id: 'TA0010', name: 'Exfiltration', color: '#95a5a6',
    key_techniques: [
      { id: 'T1048', name: 'Exfiltration Over Alt Protocol' },
      { id: 'T1567', name: 'Exfiltration Over Web Services' },
    ],
  },
  {
    id: 'TA0040', name: 'Impact', color: '#2c3e50',
    key_techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact (Ransomware)' },
      { id: 'T1490', name: 'Inhibit System Recovery' },
      { id: 'T1485', name: 'Data Destruction' },
    ],
  },
];

// ── Hunting playbooks ─────────────────────────────────────────────────────────
const HUNTING_PLAYBOOKS = [
  {
    id:         'PB-001',
    name:       'Credential Dumping Detection',
    tactic:     'Credential Access',
    technique:  'T1003',
    hypothesis: 'An attacker may have used LSASS dumping tools to harvest credentials',
    data_sources: ['Windows Security Event Log (4688)', 'Process creation events', 'EDR telemetry'],
    hunt_queries: [
      'Look for processes accessing lsass.exe (EventID 4656/4663)',
      'Search for known dumping tool hashes: mimikatz, procdump, comsvcs.dll',
      'Hunt for LSASS memory read events from non-system processes',
    ],
    indicators: ['procdump.exe', 'mimikatz.exe', 'sekurlsa', 'comsvcs.dll LoadLibrary from cmd'],
    mitre_ref:  'https://attack.mitre.org/techniques/T1003/',
    priority:   'HIGH',
  },
  {
    id:         'PB-002',
    name:       'Lateral Movement via Remote Services',
    tactic:     'Lateral Movement',
    technique:  'T1021',
    hypothesis: 'An attacker may be using RDP/WMI/PSRemoting to move laterally',
    data_sources: ['Network flow logs', 'Windows Event Log 4624 (Logon)', 'EDR telemetry'],
    hunt_queries: [
      'Identify unusual RDP sessions (non-standard hours, new source IPs)',
      'Correlate WMI exec events across multiple hosts in short windows',
      'Hunt for pass-the-hash indicators: NTLM auth from non-standard tools',
    ],
    indicators: ['wmic.exe /node', 'Invoke-WMIMethod', 'net use \\\\', 'psexec'],
    mitre_ref:  'https://attack.mitre.org/techniques/T1021/',
    priority:   'HIGH',
  },
  {
    id:         'PB-003',
    name:       'Ransomware Pre-Deployment Hunt',
    tactic:     'Impact',
    technique:  'T1486',
    hypothesis: 'Pre-ransomware indicators: mass file staging, shadow copy deletion, backup enumeration',
    data_sources: ['File system events', 'VSS events', 'Process creation', 'Network logs'],
    hunt_queries: [
      'Search for shadow copy deletion: vssadmin delete shadows',
      'Hunt for mass file rename events or unusual encryption extensions',
      'Look for backup service disabling: net stop vss, bcdedit /set recoveryenabled no',
      'Detect cobalt strike beacons via JA3/JA3S fingerprinting',
    ],
    indicators: ['vssadmin.exe', 'bcdedit.exe', 'wbadmin.exe delete', 'mass file changes'],
    mitre_ref:  'https://attack.mitre.org/techniques/T1486/',
    priority:   'CRITICAL',
  },
  {
    id:         'PB-004',
    name:       'Phishing & Initial Access Hunt',
    tactic:     'Initial Access',
    technique:  'T1566',
    hypothesis: 'Phishing email delivered malicious document executing macro or URL',
    data_sources: ['Email gateway logs', 'Proxy logs', 'Process creation (parent: outlook.exe/winword.exe)'],
    hunt_queries: [
      'Hunt for office spawning cmd/powershell/wscript (parent-child anomaly)',
      'Search for macro-enabled document downloads from email',
      'Look for PowerShell web downloads shortly after email receipt',
    ],
    indicators: ['winword.exe spawning powershell', 'outlook.exe spawning cmd', 'mshta.exe from office'],
    mitre_ref:  'https://attack.mitre.org/techniques/T1566/',
    priority:   'HIGH',
  },
  {
    id:         'PB-005',
    name:       'C2 Beaconing Detection',
    tactic:     'Command and Control',
    technique:  'T1071',
    hypothesis: 'Attacker is using HTTP/DNS/HTTPS beaconing for C2 communications',
    data_sources: ['DNS logs', 'Proxy/web gateway logs', 'NetFlow/NDR'],
    hunt_queries: [
      'Identify hosts with periodic beaconing (jitter-based pattern analysis)',
      'Hunt for DNS TXT record queries with encoded data',
      'Search for long connection durations to newly seen domains',
      'Look for domain generation algorithm (DGA) domains',
    ],
    indicators: ['High DNS query rates to new domains', 'Periodic same-sized HTTP POSTs', 'HTTPS to IP addresses'],
    mitre_ref:  'https://attack.mitre.org/techniques/T1071/',
    priority:   'HIGH',
  },
];

// ── Score readiness based on inputs ──────────────────────────────────────────
function scoreReadiness(inputs) {
  const checks = [
    { key: 'has_siem',           weight: 20, label: 'SIEM/Log Aggregation' },
    { key: 'has_edr',            weight: 18, label: 'EDR Solution' },
    { key: 'has_centralized_logging', weight: 15, label: 'Centralized Logging' },
    { key: 'has_dns_logging',    weight: 10, label: 'DNS Query Logging' },
    { key: 'has_network_monitoring', weight: 10, label: 'Network Flow Monitoring (NDR)' },
    { key: 'has_threat_intel',   weight: 8,  label: 'Threat Intelligence Feed' },
    { key: 'has_ir_team',        weight: 8,  label: 'Incident Response Team' },
    { key: 'has_playbooks',      weight: 6,  label: 'Documented IR Playbooks' },
    { key: 'has_red_team',       weight: 5,  label: 'Red Team / Purple Team Exercises' },
  ];

  let score = 0;
  const gaps = [];
  const passed = [];

  for (const c of checks) {
    const pass = inputs[c.key] === true || inputs[c.key] === 'true' || inputs[c.key] === 1;
    if (pass) {
      score += c.weight;
      passed.push(c.label);
    } else {
      gaps.push({ label: c.label, key: c.key, weight: c.weight, severity: c.weight >= 15 ? 'HIGH' : c.weight >= 8 ? 'MEDIUM' : 'LOW' });
    }
  }

  return { score, gaps, passed };
}

function getMITRECoverageFromInputs(inputs) {
  return MITRE_TACTICS.map(tactic => {
    // Score coverage per tactic based on available tooling
    let coverage = 10; // minimum awareness
    if (inputs.has_siem)               coverage += 15;
    if (inputs.has_edr)                coverage += 20;
    if (inputs.has_centralized_logging) coverage += 10;
    if (inputs.has_dns_logging && tactic.id === 'TA0011') coverage += 15;
    if (inputs.has_network_monitoring) coverage += 10;
    if (inputs.has_threat_intel)       coverage += 5;

    // Some tactics get less coverage without specific tools
    if (['TA0003', 'TA0004', 'TA0005'].includes(tactic.id) && !inputs.has_edr) coverage -= 15;
    if (tactic.id === 'TA0010' && !inputs.has_network_monitoring) coverage -= 20;

    coverage = Math.max(5, Math.min(95, coverage));

    return {
      ...tactic,
      coverage,
      coverage_status: coverage >= 70 ? 'GOOD' : coverage >= 45 ? 'PARTIAL' : 'GAP',
      detection_rules: coverage >= 60 ? 'EXISTS' : coverage >= 35 ? 'PARTIAL' : 'MISSING',
    };
  });
}

export async function runThreatHuntingReview(env, inputs, orderId = null) {
  const startedAt = new Date().toISOString();
  const domain     = (inputs.domain || inputs.target_domain || '').trim();
  const industry   = inputs.industry || inputs.target_industry || 'General';

  const readiness    = scoreReadiness(inputs);
  const mitreCoverage = getMITRECoverageFromInputs(inputs);

  const overallCoverage = Math.round(mitreCoverage.reduce((s, t) => s + t.coverage, 0) / mitreCoverage.length);
  const grade = overallCoverage >= 80 ? 'A' : overallCoverage >= 65 ? 'B' : overallCoverage >= 50 ? 'C' : overallCoverage >= 35 ? 'D' : 'F';

  const findings = readiness.gaps.map((gap, i) => ({
    id:          `TH-GAP-${i + 1}`,
    severity:    gap.severity,
    category:    'Detection Gap',
    title:       `Missing: ${gap.label}`,
    description: `Without ${gap.label}, threat hunting capability in multiple MITRE tactics is severely limited.`,
    remediation: getToolRemediation(gap.key),
  }));

  // Gap tactics
  const gapTactics = mitreCoverage.filter(t => t.coverage < 45);

  const detectionRules = [
    { rule_id: 'DR-001', technique: 'T1003', title: 'LSASS Memory Access Detection', sigma_ready: true, priority: 'HIGH' },
    { rule_id: 'DR-002', technique: 'T1566', title: 'Office Spawning Scripting Interpreter', sigma_ready: true, priority: 'HIGH' },
    { rule_id: 'DR-003', technique: 'T1486', title: 'Shadow Copy Deletion', sigma_ready: true, priority: 'CRITICAL' },
    { rule_id: 'DR-004', technique: 'T1071', title: 'HTTP Beaconing Pattern Detection', sigma_ready: false, priority: 'HIGH' },
    { rule_id: 'DR-005', technique: 'T1078', title: 'Abnormal Authentication Patterns', sigma_ready: true, priority: 'HIGH' },
    { rule_id: 'DR-006', technique: 'T1021', title: 'Lateral Movement via SMB/RDP', sigma_ready: true, priority: 'HIGH' },
    { rule_id: 'DR-007', technique: 'T1027', title: 'PowerShell Obfuscation Detection', sigma_ready: true, priority: 'MEDIUM' },
    { rule_id: 'DR-008', technique: 'T1190', title: 'Web Application Exploit Indicators', sigma_ready: false, priority: 'HIGH' },
  ];

  const report = {
    meta: {
      service:      'CDB-THR-001',
      service_name: 'Threat Hunting Readiness Review',
      version:      '1.0',
      domain:       domain || 'N/A',
      industry,
      generated_at: startedAt,
      powered_by:   'CYBERDUDEBIVASH AI Security Hub™',
      framework:    'MITRE ATT&CK v15',
    },
    executive_summary: {
      readiness_score:        readiness.score,
      mitre_coverage:         overallCoverage,
      grade,
      hunting_maturity:       overallCoverage >= 70 ? 'Advanced' : overallCoverage >= 50 ? 'Intermediate' : overallCoverage >= 30 ? 'Basic' : 'Minimal',
      critical_gaps:          findings.filter(f => f.severity === 'HIGH').length,
      tactics_with_good_coverage: mitreCoverage.filter(t => t.coverage >= 70).length,
      tactics_with_gaps:          gapTactics.length,
      detection_rules_needed: detectionRules.filter(r => !inputs.has_siem).length,
      recommendation:         overallCoverage < 50
        ? 'CRITICAL: Organization lacks foundational threat hunting capabilities. Deploy SIEM/EDR as immediate priority.'
        : overallCoverage < 70
        ? 'Threat hunting program is developing. Focus on filling detection gaps in key tactics.'
        : 'Good threat hunting foundation. Optimize with purple team exercises and advanced detection rules.',
    },
    readiness_assessment: {
      score:    readiness.score,
      passed:   readiness.passed,
      gaps:     readiness.gaps,
      capabilities_present: readiness.passed,
    },
    mitre_attack_coverage: {
      tactics:           mitreCoverage,
      overall_coverage:  overallCoverage,
      coverage_heatmap:  mitreCoverage.map(t => ({ tactic: t.name, coverage: t.coverage, status: t.coverage_status })),
      critical_gaps:     gapTactics.map(t => t.name),
    },
    hunting_playbooks: HUNTING_PLAYBOOKS,
    detection_rules:   detectionRules,
    findings,
    '90_day_roadmap': [
      { month: 1, actions: ['Deploy/verify SIEM log aggregation', 'Enable key detection rules', 'Document initial hypothesis list'] },
      { month: 2, actions: ['Run first threat hunt using PB-003 (Ransomware)', 'Implement EDR on all endpoints', 'Enable DNS logging'] },
      { month: 3, actions: ['Complete MITRE ATT&CK coverage mapping', 'Conduct purple team exercise', 'Document all hunt findings'] },
    ],
    recommendations: [
      ...readiness.gaps.slice(0, 5).map((g, i) => ({
        priority: i + 1,
        action:   `Deploy ${g.label}`,
        impact:   g.severity,
        effort:   g.weight >= 15 ? 'High' : 'Medium',
      })),
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
        assessId, orderId, 'CDB-THR-001', domain || industry, 'complete',
        100 - overallCoverage, grade,
        findings.length,
        findings.filter(f => f.severity === 'HIGH').length, 0,
        JSON.stringify(findings),
        JSON.stringify(report.recommendations),
        JSON.stringify(report),
        '1.0', startedAt, new Date().toISOString()
      ).run();
      await env.DB.prepare(
        `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
      ).bind(orderId).run();
    } catch (e) { console.error('[TH-Engine] DB error:', e.message); }
  }

  return report;
}

function getToolRemediation(key) {
  const map = {
    has_siem:               'Deploy a SIEM solution (Splunk, Elastic/ELK, Microsoft Sentinel, or open-source Wazuh)',
    has_edr:                'Deploy EDR on all endpoints (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, or Wazuh)',
    has_centralized_logging: 'Centralize logs from all systems to a SIEM or log aggregator. Enable syslog/WEF forwarding.',
    has_dns_logging:        'Enable DNS query logging on all DNS servers. Forward to SIEM for DGA/beaconing detection.',
    has_network_monitoring: 'Deploy NDR/NSM (Zeek, Suricata, or commercial NDR) for network-level threat detection.',
    has_threat_intel:       'Subscribe to a threat intelligence feed (MISP, OpenCTI, or commercial TI platforms).',
    has_ir_team:            'Establish an incident response function — even a 2-person team with documented runbooks.',
    has_playbooks:          'Create documented response playbooks for top 5 threat scenarios (ransomware, phishing, BEC, insider, etc.)',
    has_red_team:           'Conduct quarterly purple team exercises with MITRE ATT&CK scenarios to validate detection coverage.',
  };
  return map[key] || 'Review and implement this security capability';
}
