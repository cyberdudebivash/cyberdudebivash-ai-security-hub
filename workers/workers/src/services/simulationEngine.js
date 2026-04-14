/**
 * CYBERDUDEBIVASH AI Security Hub — Attack Simulation Engine v1.0
 * service: services/simulationEngine.js
 * Plan gate: PRO | ENTERPRISE only
 *
 * Simulates a realistic attacker kill chain based on scan findings.
 * Uses MITRE ATT&CK framework + CVSS + exposure data.
 *
 * Outputs:
 *   entry_point            { type, vector, description }
 *   kill_chain             [ { phase, tactic, technique, action, tools, time, detection } ]
 *   lateral_movement_paths [ { from, to, method, likelihood } ]
 *   impact_analysis        { data_at_risk, systems_compromised, business_impact, ransomware_risk }
 *   attacker_profile       { type, motivation, sophistication, nation_state_likelihood }
 *   simulation_metadata    { duration_hours, confidence, phases_completed }
 */

import { correlateScanToCVEs } from './cveEngine.js';
import { computeRiskScore }     from './riskEngine.js';

// ─── MITRE ATT&CK Kill Chain phases (PICERL model + MITRE pre-ATT&CK) ────────
const KILL_CHAIN_PHASES = [
  'Reconnaissance',
  'Weaponization',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Exfiltration',
  'Impact',
];

// ─── Module-specific attack templates ────────────────────────────────────────
const MODULE_ATTACK_TEMPLATES = {
  domain: [
    {
      phase: 'Reconnaissance',
      tactic: 'TA0043',
      technique: { id: 'T1595.002', name: 'Vulnerability Scanning', url: 'https://attack.mitre.org/techniques/T1595/002/' },
      action: 'Attacker enumerates subdomains, identifies open ports, maps TLS configuration weaknesses.',
      tools: ['Shodan', 'Amass', 'Nmap', 'SSLScan'],
      time_hours: 0.5,
      detection_difficulty: 'LOW',
      mitigation: 'Implement port-based firewall rules; monitor for unusual DNS queries.',
    },
    {
      phase: 'Initial Access',
      tactic: 'TA0001',
      technique: { id: 'T1190', name: 'Exploit Public-Facing Application', url: 'https://attack.mitre.org/techniques/T1190/' },
      action: 'Attacker exploits TLS misconfiguration or missing security headers to intercept traffic.',
      tools: ['Burp Suite', 'testssl.sh', 'SSLstrip'],
      time_hours: 2.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Enforce TLS 1.3, enable HSTS preloading, implement CAA DNS records.',
    },
    {
      phase: 'Credential Access',
      tactic: 'TA0006',
      technique: { id: 'T1557.002', name: 'ARP Cache Poisoning / AitM', url: 'https://attack.mitre.org/techniques/T1557/' },
      action: 'Without DNSSEC, attacker performs DNS cache poisoning to redirect users to malicious servers.',
      tools: ['dnsspoof', 'Bettercap', 'Ettercap'],
      time_hours: 4.0,
      detection_difficulty: 'HARD',
      mitigation: 'Enable DNSSEC, implement DMARC enforcement, deploy email authentication monitoring.',
    },
    {
      phase: 'Exfiltration',
      tactic: 'TA0010',
      technique: { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', url: 'https://attack.mitre.org/techniques/T1048/' },
      action: 'Attacker uses DNS tunneling or HTTPS to exfiltrate collected credentials and session tokens.',
      tools: ['DNScat2', 'iodine', 'dns2tcp'],
      time_hours: 6.0,
      detection_difficulty: 'HARD',
      mitigation: 'Deploy DNS filtering, inspect DNS query volumes, implement DLP controls.',
    },
  ],

  ai: [
    {
      phase: 'Reconnaissance',
      tactic: 'TA0043',
      technique: { id: 'T1592', name: 'Gather Victim Host Information', url: 'https://attack.mitre.org/techniques/T1592/' },
      action: 'Attacker probes AI endpoints for model version disclosure, API key exposure, debug modes.',
      tools: ['Burp Suite', 'curl', 'LLM Fuzzer', 'garak'],
      time_hours: 0.5,
      detection_difficulty: 'LOW',
      mitigation: 'Disable debug endpoints, rate-limit AI API, sanitize error responses.',
    },
    {
      phase: 'Initial Access',
      tactic: 'TA0001',
      technique: { id: 'T1078', name: 'Valid Accounts (API Key Abuse)', url: 'https://attack.mitre.org/techniques/T1078/' },
      action: 'Attacker performs prompt injection to extract system prompts, bypass safety filters, or exfiltrate context.',
      tools: ['PromptInject', 'jailbreak templates', 'garak', 'PyRIT'],
      time_hours: 1.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Implement prompt validation layer, use structured output schemas, log all prompts.',
    },
    {
      phase: 'Collection',
      tactic: 'TA0009',
      technique: { id: 'T1530', name: 'Data from Cloud Storage (Training Data)', url: 'https://attack.mitre.org/techniques/T1530/' },
      action: 'Via prompt injection, attacker extracts training data, user PII, or confidential documents from RAG context.',
      tools: ['LangChain exploit', 'RAG poisoning', 'indirect prompt injection'],
      time_hours: 3.0,
      detection_difficulty: 'HARD',
      mitigation: 'Implement input/output guards, use separate context boundaries per user session.',
    },
    {
      phase: 'Impact',
      tactic: 'TA0040',
      technique: { id: 'T1565', name: 'Data Manipulation (Model Poisoning)', url: 'https://attack.mitre.org/techniques/T1565/' },
      action: 'Attacker poisons model fine-tuning pipeline via adversarial training samples — backdoor persists.',
      tools: ['BadNets', 'Trojaning Attack', 'data poisoning scripts'],
      time_hours: 48.0,
      detection_difficulty: 'HARD',
      mitigation: 'Audit training datasets, implement model integrity checks, use differential privacy.',
    },
  ],

  redteam: [
    {
      phase: 'Initial Access',
      tactic: 'TA0001',
      technique: { id: 'T1566.002', name: 'Spear Phishing Link', url: 'https://attack.mitre.org/techniques/T1566/002/' },
      action: 'Attacker crafts targeted spear-phishing email exploiting organization context from OSINT.',
      tools: ['GoPhish', 'Evilginx2', 'SET', 'King Phisher'],
      time_hours: 2.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Deploy anti-phishing email gateway, enforce DMARC, run security awareness training.',
    },
    {
      phase: 'Persistence',
      tactic: 'TA0003',
      technique: { id: 'T1053.005', name: 'Scheduled Task', url: 'https://attack.mitre.org/techniques/T1053/005/' },
      action: 'Attacker installs persistent backdoor via scheduled task or WMI subscription for long-term access.',
      tools: ['Cobalt Strike', 'Metasploit', 'Empire', 'Sliver'],
      time_hours: 1.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Monitor scheduled task creation events, implement application allowlisting.',
    },
    {
      phase: 'Privilege Escalation',
      tactic: 'TA0004',
      technique: { id: 'T1548.002', name: 'Bypass UAC', url: 'https://attack.mitre.org/techniques/T1548/002/' },
      action: 'Attacker escalates from standard user to SYSTEM/root using UAC bypass or kernel exploit.',
      tools: ['BeRoot', 'UACME', 'LinPEAS', 'WinPEAS'],
      time_hours: 2.0,
      detection_difficulty: 'HARD',
      mitigation: 'Enforce least privilege, apply patch management, monitor privilege escalation events.',
    },
    {
      phase: 'Lateral Movement',
      tactic: 'TA0008',
      technique: { id: 'T1021.002', name: 'SMB/Windows Admin Shares', url: 'https://attack.mitre.org/techniques/T1021/002/' },
      action: 'With elevated credentials, attacker moves laterally via pass-the-hash or remote service abuse.',
      tools: ['Mimikatz', 'CrackMapExec', 'Impacket', 'Bloodhound'],
      time_hours: 4.0,
      detection_difficulty: 'HARD',
      mitigation: 'Implement network segmentation, disable SMBv1, deploy Credential Guard.',
    },
    {
      phase: 'Impact',
      tactic: 'TA0040',
      technique: { id: 'T1486', name: 'Data Encrypted for Impact (Ransomware)', url: 'https://attack.mitre.org/techniques/T1486/' },
      action: 'Attacker deploys ransomware payload across all reachable systems — maximum business disruption.',
      tools: ['LockBit', 'custom ransomware', 'wiper malware'],
      time_hours: 0.5,
      detection_difficulty: 'LOW',
      mitigation: 'Immutable backups, offline backup copies, incident response plan, EDR with rollback.',
    },
  ],

  identity: [
    {
      phase: 'Credential Access',
      tactic: 'TA0006',
      technique: { id: 'T1110.003', name: 'Password Spraying', url: 'https://attack.mitre.org/techniques/T1110/003/' },
      action: 'Attacker runs password spraying attack against identity provider — low-and-slow to evade lockouts.',
      tools: ['Spray', 'MSOLSpray', 'kerbrute', 'Ruler'],
      time_hours: 2.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Enable MFA, implement impossible travel detection, use CAPTCHA on login pages.',
    },
    {
      phase: 'Initial Access',
      tactic: 'TA0001',
      technique: { id: 'T1621', name: 'MFA Request Generation (MFA Fatigue)', url: 'https://attack.mitre.org/techniques/T1621/' },
      action: 'With valid credentials, attacker bombards user with MFA push notifications until approved.',
      tools: ['custom Python', 'MFASweep', 'msspray'],
      time_hours: 1.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Implement number matching MFA, limit MFA push attempts, alert on unusual MFA activity.',
    },
    {
      phase: 'Privilege Escalation',
      tactic: 'TA0004',
      technique: { id: 'T1078.004', name: 'Cloud Accounts (IAM Escalation)', url: 'https://attack.mitre.org/techniques/T1078/004/' },
      action: 'Attacker abuses overprivileged IAM roles or misconfigured RBAC to escalate to admin.',
      tools: ['PMapper', 'Pacu', 'ScoutSuite', 'CloudFox'],
      time_hours: 3.0,
      detection_difficulty: 'HARD',
      mitigation: 'Audit IAM roles quarterly, enforce least privilege, implement Just-In-Time access.',
    },
    {
      phase: 'Exfiltration',
      tactic: 'TA0010',
      technique: { id: 'T1528', name: 'Steal Application Access Token', url: 'https://attack.mitre.org/techniques/T1528/' },
      action: 'Attacker steals OAuth tokens / session cookies to maintain persistent access across password resets.',
      tools: ['TokenTactics', 'AADInternals', 'GraphSpy', 'Evilginx2'],
      time_hours: 1.0,
      detection_difficulty: 'HARD',
      mitigation: 'Implement token binding, continuous access evaluation, short token lifetimes.',
    },
  ],

  compliance: [
    {
      phase: 'Reconnaissance',
      tactic: 'TA0043',
      technique: { id: 'T1595', name: 'Active Scanning for Misconfiguration', url: 'https://attack.mitre.org/techniques/T1595/' },
      action: 'Attacker identifies exposed configuration files, management interfaces, and data stores.',
      tools: ['Shodan', 'GrayhatWarfare', 'CloudEnum', 'Pacu'],
      time_hours: 1.0,
      detection_difficulty: 'LOW',
      mitigation: 'Remove public access to configuration endpoints, enable cloud security posture monitoring.',
    },
    {
      phase: 'Initial Access',
      tactic: 'TA0001',
      technique: { id: 'T1190', name: 'Exploit Public-Facing Application', url: 'https://attack.mitre.org/techniques/T1190/' },
      action: 'Attacker exploits unpatched vulnerability in compliance-scope systems (GDPR/PCI data stores).',
      tools: ['Metasploit', 'Nuclei', 'CVE-specific exploits'],
      time_hours: 3.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Apply patches within SLA, segment compliance-scope systems, implement WAF.',
    },
    {
      phase: 'Collection',
      tactic: 'TA0009',
      technique: { id: 'T1530', name: 'Data from Cloud Storage', url: 'https://attack.mitre.org/techniques/T1530/' },
      action: 'Attacker accesses misconfigured S3/GCS buckets or databases containing PII/financial data.',
      tools: ['AWSBucketDump', 'GrayhatWarfare', 'SQLMAP'],
      time_hours: 2.0,
      detection_difficulty: 'MEDIUM',
      mitigation: 'Enable object-level logging, enforce bucket policies, encrypt data at rest.',
    },
    {
      phase: 'Impact',
      tactic: 'TA0040',
      technique: { id: 'T1485', name: 'Data Destruction / Regulatory Violation', url: 'https://attack.mitre.org/techniques/T1485/' },
      action: 'Attacker destroys or leaks PII/financial data — triggering mandatory breach notifications and regulatory fines.',
      tools: ['custom data wipers', 'ransom demand scripts', 'dark web brokers'],
      time_hours: 0.5,
      detection_difficulty: 'LOW',
      mitigation: 'Implement DLP, data classification, incident response plan with breach notification workflow.',
    },
  ],
};

// ─── Lateral movement path templates per module ───────────────────────────────
const LATERAL_PATHS = {
  domain:     [{ from: 'Web Server', to: 'Database Server', method: 'SQL Injection via exposed endpoint', likelihood: 0.6 }],
  ai:         [{ from: 'AI API Server', to: 'Vector Database', method: 'RAG context injection', likelihood: 0.7 }],
  redteam:    [
    { from: 'Compromised Workstation', to: 'Domain Controller', method: 'Pass-the-Hash + SMB', likelihood: 0.8 },
    { from: 'Domain Controller', to: 'File Servers', method: 'GPO Abuse', likelihood: 0.9 },
  ],
  identity:   [{ from: 'Compromised User Account', to: 'Admin Console', method: 'Privilege Escalation via IAM misconfiguration', likelihood: 0.7 }],
  compliance: [{ from: 'Public Storage Bucket', to: 'Internal Database', method: 'Credential reuse from exposed config', likelihood: 0.5 }],
};

// ─── Attacker profile per module ──────────────────────────────────────────────
const ATTACKER_PROFILES = {
  domain:     { type: 'Cybercriminal / Hacktivist', motivation: 'Financial / Disruption', sophistication: 'MEDIUM', nation_state_likelihood: 0.15 },
  ai:         { type: 'APT / Cybercriminal', motivation: 'IP Theft / Model Abuse', sophistication: 'HIGH', nation_state_likelihood: 0.45 },
  redteam:    { type: 'APT Group / Ransomware Gang', motivation: 'Financial / Espionage', sophistication: 'HIGH', nation_state_likelihood: 0.35 },
  identity:   { type: 'Insider Threat / APT', motivation: 'Account Takeover / Espionage', sophistication: 'MEDIUM-HIGH', nation_state_likelihood: 0.30 },
  compliance: { type: 'Opportunistic Attacker / Competitor', motivation: 'Data Theft / Extortion', sophistication: 'MEDIUM', nation_state_likelihood: 0.10 },
};

// ─── Main simulation function (PRO+ gate enforced in handler) ────────────────
export function runAttackSimulation(scanResult, module, target) {
  const allFindings  = [...(scanResult.findings || []), ...(scanResult.locked_findings || [])];
  const riskData     = computeRiskScore(scanResult, module);
  const killChain    = MODULE_ATTACK_TEMPLATES[module] || MODULE_ATTACK_TEMPLATES.domain;
  const lateralPaths = LATERAL_PATHS[module] || [];
  const profile      = ATTACKER_PROFILES[module] || ATTACKER_PROFILES.domain;

  // Adjust kill chain based on severity
  const severity     = riskData.severity;
  const phasesActive = severity === 'CRITICAL' ? killChain.length
    : severity === 'HIGH'     ? Math.min(killChain.length, Math.ceil(killChain.length * 0.8))
    : severity === 'MEDIUM'   ? Math.min(killChain.length, Math.ceil(killChain.length * 0.6))
    : Math.min(killChain.length, Math.ceil(killChain.length * 0.4));

  const activeChain  = killChain.slice(0, phasesActive).map((step, i) => ({
    step: i + 1,
    ...step,
    // Adjust probability per step
    success_probability: Math.max(0.1, riskData.risk_score / 10 - i * 0.05),
  }));

  const totalHours = activeChain.reduce((sum, s) => sum + s.time_hours, 0);

  // Impact analysis
  const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount     = allFindings.filter(f => f.severity === 'HIGH').length;

  const systemsAtRisk  = Math.max(1, criticalCount * 3 + highCount * 1);
  const dataExposureGB = severity === 'CRITICAL' ? 250 : severity === 'HIGH' ? 80 : 20;
  const ransomwareRisk = riskData.exploit_probability === 'CRITICAL' || riskData.exploit_probability === 'HIGH'
    ? 'HIGH' : 'MEDIUM';

  const impactAnalysis = {
    systems_at_risk:        systemsAtRisk,
    data_exposure_gb:       dataExposureGB,
    user_accounts_at_risk:  systemsAtRisk * 12,
    ransomware_risk:        ransomwareRisk,
    business_impact:        severity === 'CRITICAL'
      ? 'Full operational disruption. Regulatory breach notification required.'
      : severity === 'HIGH'
        ? 'Significant service disruption. Data integrity at risk.'
        : 'Partial service degradation. Confidentiality risk.',
    recovery_time_hours:    severity === 'CRITICAL' ? 168 : severity === 'HIGH' ? 72 : 24,
  };

  return {
    simulation_id:  `SIM-${Date.now().toString(36).toUpperCase()}`,
    target,
    module,
    entry_point: {
      type:   killChain[0]?.phase || 'Initial Access',
      vector: killChain[0]?.technique?.name || 'Network',
      description: `Most likely entry via ${killChain[0]?.action?.slice(0, 80) || 'exposed service'}.`,
    },
    kill_chain:             activeChain,
    lateral_movement_paths: lateralPaths,
    impact_analysis:        impactAnalysis,
    attacker_profile:       profile,
    risk_context:           riskData,
    simulation_metadata: {
      phases_active:       phasesActive,
      phases_total:        killChain.length,
      total_duration_hours: Math.round(totalHours * 10) / 10,
      confidence:          riskData.confidence_score,
      simulation_basis:    'MITRE ATT&CK v14 + CVSS v3.1 + CISA KEV',
    },
  };
}
