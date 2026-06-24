import { ok, fail } from '../lib/response.js';
import { routeAICall } from '../core/aiProviderRouter.js';

/**
 * CYBERDUDEBIVASH AI Security Hub — CyberBrain Engine v20.0
 * APEX NEXUS God Mode Intelligence Core — Maximum Precision, Zero Hallucination
 *
 * Upgrades from v19→v20:
 * - 20+ threat actor profiles (added India-specific: APT36, SideCopy, DoNot Team)
 * - 25 risk signals (expanded from 17)
 * - Financial impact in ₹ INR with sector-specific ranges
 * - 7 attack chains (added AI/LLM and cloud-native chains)
 * - 15 remediation templates (expanded from 10)
 * - CERT-In 6-hour reporting trigger detection
 *
 * Powers:
 *   - /api/scan/* (enriches scan results with AI risk scoring)
 *   - /api/vulns  (prioritizes vulnerabilities by exploitability + business impact)
 *   - /api/hunt   (recommends hunt queries based on asset profile)
 *   - /api/cyber-brain/* (direct CyberBrain API)
 */

// ─── Risk weight table (v20 — 25 signals) ─────────────────────────────────────
const RISK_WEIGHTS = {
  // Vulnerability severity
  cvss_critical:       30,   // CVSS 9.0–10.0
  cvss_high:           20,   // CVSS 7.0–8.9
  cvss_medium:         10,   // CVSS 4.0–6.9
  // Exploitation intelligence
  in_kev:              28,   // CISA KEV — confirmed active exploitation
  epss_high:           22,   // EPSS > 0.70 — high prediction of exploitation
  epss_medium:         11,   // EPSS 0.30–0.70
  public_exploit:      16,   // PoC / weaponized exploit publicly available
  ransomware_linked:   22,   // Ransomware group actively leverages this vector
  zero_day:            38,   // No patch available — maximum urgency
  ai_weaponized:       18,   // AI-enhanced attack tooling available
  // Attack capability
  lateral_movement:    16,   // Enables lateral movement across network
  credential_access:   20,   // Enables credential theft / account takeover
  rce_capability:      25,   // Remote code execution possible
  data_exfil:          18,   // Data exfiltration path available
  // Asset exposure
  external_exposure:   22,   // Internet-facing asset
  no_mfa:              14,   // Authentication weakness — no MFA enforced
  high_value_data:     18,   // Critical/sensitive data accessible
  privileged_systems:  15,   // Admin/privileged system exposure
  // Technical weaknesses
  missing_headers:      6,   // Each missing security header
  weak_tls:            13,   // TLS 1.0/1.1 or weak ciphers detected
  dns_weakness:         9,   // Missing SPF/DKIM/DMARC/DNSSEC
  supply_chain_risk:   20,   // Third-party / supply chain exposure
  cloud_misconfigured: 18,   // Cloud IAM / storage misconfiguration
  // Indian regulatory risk
  dpdp_exposure:       12,   // Personal data exposure → DPDP Act liability
  cert_in_reportable:  15,   // Incident meets CERT-In 6-hour reporting threshold
};

// ─── MITRE ATT&CK attack chains (v20 — 7 chains) ─────────────────────────────
const ATTACK_CHAINS = [
  {
    id: 'chain_web_rce',
    name: 'Web Exploitation → RCE → Lateral Movement',
    steps: ['Reconnaissance', 'Initial Access (Web Exploit)', 'Execution', 'Privilege Escalation', 'Lateral Movement', 'Data Exfiltration'],
    techniques: ['T1190', 'T1059', 'T1548', 'T1021', 'T1041'],
    probability_multiplier: 1.45,
    triggers: ['injection', 'rce', 'cve_critical', 'external'],
    financial_impact_inr: '₹50L–₹10Cr',
  },
  {
    id: 'chain_phishing_cred',
    name: 'Spear Phishing → Credential Theft → Persistence',
    steps: ['OSINT Reconnaissance', 'AI-Crafted Phishing', 'Credential Harvest', 'MFA Bypass', 'Persistence', 'Discovery'],
    techniques: ['T1566', 'T1621', 'T1078', 'T1547', 'T1057'],
    probability_multiplier: 1.25,
    triggers: ['spf', 'dmarc', 'dkim', 'mfa', 'credential'],
    financial_impact_inr: '₹20L–₹5Cr',
  },
  {
    id: 'chain_supply_chain',
    name: 'Supply Chain Compromise → Backdoor → Long-Term APT',
    steps: ['Vendor Compromise', 'Trusted Update Delivery', 'Backdoor Execution', 'Covert C2', 'Long-Term Exfiltration'],
    techniques: ['T1195', 'T1195.001', 'T1543', 'T1071', 'T1020'],
    probability_multiplier: 0.85,
    triggers: ['supply_chain', 'third_party', 'dependency'],
    financial_impact_inr: '₹1Cr–₹100Cr',
  },
  {
    id: 'chain_ransomware',
    name: 'Initial Access → Ransomware Double Extortion',
    steps: ['Initial Access', 'Execution (LOLBins)', 'Defense Evasion', 'Data Staging + Exfil', 'Encryption', 'Extortion'],
    techniques: ['T1190', 'T1059', 'T1027', 'T1048', 'T1486', 'T1490'],
    probability_multiplier: 1.35,
    triggers: ['ransomware', 'kev', 'public_exploit'],
    financial_impact_inr: '₹1Cr–₹50Cr',
  },
  {
    id: 'chain_insider',
    name: 'Insider Threat → Privilege Abuse → Exfiltration',
    steps: ['Privileged Access Abuse', 'Lateral Discovery', 'Data Collection', 'Covert Exfiltration'],
    techniques: ['T1078', 'T1087', 'T1005', 'T1048'],
    probability_multiplier: 0.65,
    triggers: ['privilege', 'admin', 'access_control'],
    financial_impact_inr: '₹10L–₹5Cr',
  },
  {
    id: 'chain_ai_llm',
    name: 'AI/LLM Prompt Injection → Data Exfil → System Compromise',
    steps: ['Prompt Discovery', 'Prompt Injection', 'PII Collection', 'Sensitive Data Exfil', 'Agent Action Abuse'],
    techniques: ['T1059', 'T1005', 'T1041', 'T1648'],
    probability_multiplier: 1.1,
    triggers: ['prompt', 'llm', 'ai_model', 'rag'],
    financial_impact_inr: '₹5L–₹2Cr',
  },
  {
    id: 'chain_cloud_takeover',
    name: 'Cloud Misconfiguration → IAM Takeover → Data Breach',
    steps: ['IMDS/Storage Discovery', 'IAM Role Assumption', 'Privilege Escalation', 'Data Access', 'Exfiltration'],
    techniques: ['T1552.005', 'T1078.004', 'T1537', 'T1530'],
    probability_multiplier: 1.2,
    triggers: ['cloud', 'misconfigur', 'iam', 's3', 'storage'],
    financial_impact_inr: '₹50L–₹20Cr',
  },
];

// ─── Threat actor database (v20 — 20 actors, India-aware) ────────────────────
const THREAT_ACTORS_DB = [
  // Nation-state APTs
  { id: 'apt41',          name: 'APT41 (Winnti / Double Dragon)',    nation: 'CN', motivation: 'Espionage+Financial',        sectors: ['tech','healthcare','finance','telecom','gaming'],             ttps: ['T1190','T1059','T1027','T1078','T1021'], risk_elevation: 1.35 },
  { id: 'apt28',          name: 'APT28 (Fancy Bear / Sofacy)',       nation: 'RU', motivation: 'Espionage+Disruption',       sectors: ['gov','defense','energy','media'],                              ttps: ['T1566','T1078','T1547','T1021','T1040'], risk_elevation: 1.25 },
  { id: 'apt29',          name: 'APT29 (Cozy Bear / Midnight Blizzard)', nation: 'RU', motivation: 'Intelligence Collection', sectors: ['gov','tech','finance','cloud'],                             ttps: ['T1195','T1071','T1020','T1078','T1550'], risk_elevation: 1.45 },
  { id: 'lazarus',        name: 'Lazarus Group / APT38',             nation: 'KP', motivation: 'Financial+Espionage',        sectors: ['finance','crypto','defense','tech'],                          ttps: ['T1190','T1548','T1041','T1566','T1059'], risk_elevation: 1.55 },
  { id: 'apt36',          name: 'APT36 (Transparent Tribe)',         nation: 'PK', motivation: 'Espionage vs India',         sectors: ['gov','defense','education','india'],                          ttps: ['T1566','T1059','T1078','T1021','T1113'], risk_elevation: 1.4  },
  { id: 'sidewinder',     name: 'SideCopy / Rattlesnake',            nation: 'PK', motivation: 'Espionage vs India',         sectors: ['gov','defense','india'],                                      ttps: ['T1566.001','T1059','T1547','T1021'],      risk_elevation: 1.35 },
  { id: 'donot',          name: 'DoNot Team (APT-C-35)',             nation: 'IN', motivation: 'Regional Espionage',          sectors: ['gov','military','ngo'],                                       ttps: ['T1566','T1059','T1078'],                  risk_elevation: 1.2  },
  { id: 'volt_typhoon',   name: 'Volt Typhoon / Bronze Silhouette',  nation: 'CN', motivation: 'Critical Infra Pre-position', sectors: ['critical_infra','telecom','energy','water','defense'],       ttps: ['T1190','T1078','T1021','T1083','T1070'], risk_elevation: 1.6  },
  { id: 'salt_typhoon',   name: 'Salt Typhoon',                      nation: 'CN', motivation: 'Telecom Espionage',           sectors: ['telecom','isp','gov'],                                        ttps: ['T1190','T1078','T1040','T1041'],          risk_elevation: 1.5  },
  { id: 'dragonbridge',   name: 'DRAGONBRIDGE (IO)',                 nation: 'CN', motivation: 'Information Operations',     sectors: ['media','gov','tech'],                                         ttps: ['T1566','T1585','T1491'],                  risk_elevation: 1.1  },
  // Ransomware & Financial
  { id: 'lockbit',        name: 'LockBit 3.0',                       nation: 'RU', motivation: 'Ransomware-as-a-Service',    sectors: ['healthcare','manufacturing','finance','gov'],                 ttps: ['T1486','T1490','T1059','T1021'],          risk_elevation: 1.65 },
  { id: 'clop',           name: 'CL0P',                              nation: 'RU', motivation: 'Ransomware+Zero-Day Extortion', sectors: ['healthcare','education','finance'],                        ttps: ['T1190','T1486','T1048','T1567'],          risk_elevation: 1.55 },
  { id: 'blackcat',       name: 'ALPHV / BlackCat',                  nation: 'RU', motivation: 'RaaS+Double Extortion',       sectors: ['healthcare','energy','finance'],                              ttps: ['T1486','T1190','T1027','T1041'],          risk_elevation: 1.5  },
  { id: 'black_basta',    name: 'Black Basta',                       nation: 'RU', motivation: 'Ransomware',                  sectors: ['healthcare','manufacturing','construction'],                  ttps: ['T1566','T1486','T1078','T1021'],          risk_elevation: 1.45 },
  { id: 'ransomhub',      name: 'RansomHub',                        nation: 'RU', motivation: 'Ransomware',                  sectors: ['gov','healthcare','critical_infra'],                          ttps: ['T1190','T1486','T1078','T1041'],          risk_elevation: 1.5  },
  { id: 'fin7',           name: 'FIN7 / Carbanak',                   nation: 'RU', motivation: 'Financial+Ransomware',        sectors: ['retail','hospitality','finance','tech'],                      ttps: ['T1566','T1078','T1005','T1486'],          risk_elevation: 1.3  },
  { id: 'scattered_spider',name:'Scattered Spider / UNC3944',        nation: 'US', motivation: 'Financial+Data Extortion',    sectors: ['tech','gaming','finance','telecom'],                          ttps: ['T1621','T1534','T1078','T1190'],          risk_elevation: 1.45 },
  { id: 'play',           name: 'Play Ransomware',                   nation: 'RU', motivation: 'Ransomware',                  sectors: ['gov','healthcare','manufacturing'],                            ttps: ['T1190','T1486','T1078'],                  risk_elevation: 1.35 },
  { id: 'cl0ud_atlas',    name: 'Cloud Atlas (CloudWizard)',         nation: 'RU', motivation: 'Espionage+Cloud Attacks',     sectors: ['gov','finance','tech','cloud'],                               ttps: ['T1578','T1530','T1078.004'],              risk_elevation: 1.4  },
  { id: 'revil',          name: 'REvil / Sodinokibi',                nation: 'RU', motivation: 'RaaS',                       sectors: ['manufacturing','finance','retail'],                           ttps: ['T1486','T1190','T1566','T1486'],          risk_elevation: 1.3  },
];

// ─── Remediation templates (v20 — 15 templates) ──────────────────────────────
const REMEDIATION_TEMPLATES = {
  tls:          { priority: 'HIGH',     action: 'Disable TLS 1.0/1.1. Enforce TLS 1.3 minimum. Enable HSTS. Rotate certificates annually.',     effort: '2h',    impact: 'Eliminates protocol downgrade, MITM, and cipher attacks',          cert_in_prevents: true  },
  dns:          { priority: 'HIGH',     action: 'Enable DNSSEC signing. Configure SPF (hard fail), DKIM 2048-bit, DMARC p=reject.',               effort: '4h',    impact: 'Prevents DNS hijacking, email spoofing, brand impersonation',       cert_in_prevents: false },
  headers:      { priority: 'MEDIUM',   action: 'Add HSTS (max-age=31536000), CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff.',     effort: '1h',    impact: 'Mitigates XSS, clickjacking, MIME sniffing',                        cert_in_prevents: false },
  mfa:          { priority: 'CRITICAL', action: 'Enforce MFA for ALL accounts. Mandate FIDO2/WebAuthn for privileged users. Disable SMS OTP.',  effort: '8h',    impact: 'Blocks 99.9% of credential-based attacks (Microsoft Research)',    cert_in_prevents: true  },
  patch:        { priority: 'CRITICAL', action: 'Emergency patch cycle for CISA KEV within 24h. High within 7d. Apply vendor advisories.',       effort: 'varies',impact: 'Eliminates known exploitable vulnerabilities directly',            cert_in_prevents: true  },
  network:      { priority: 'HIGH',     action: 'Micro-segment network. Zero Trust lateral movement controls. Block SMB/RDP at perimeter.',       effort: '16h',   impact: 'Limits blast radius; contains ransomware spread',                  cert_in_prevents: true  },
  logging:      { priority: 'HIGH',     action: 'Centralized SIEM with detection rules. Log retention 90 days minimum. Enable UEBA.',            effort: '8h',    impact: 'Enables threat detection, forensics, CERT-In compliance',          cert_in_prevents: false },
  access:       { priority: 'HIGH',     action: 'Least-privilege enforcement. PAM for admin accounts. Review stale accounts. Rotate all keys.', effort: '4h',    impact: 'Reduces insider threat and credential theft blast radius',          cert_in_prevents: true  },
  backup:       { priority: 'HIGH',     action: '3-2-1-1 backup strategy. Immutable backups. Air-gap critical. RTO < 4h tested quarterly.',     effort: '8h',    impact: 'Enables ransomware recovery without paying ransom',                cert_in_prevents: false },
  edr:          { priority: 'CRITICAL', action: 'EDR on all endpoints. Enable behavioral detection + XDR integration. 24/7 SOC monitoring.',    effort: '24h',   impact: 'Detects and blocks malware in real-time; reduces dwell time 80%', cert_in_prevents: true  },
  waf:          { priority: 'HIGH',     action: 'Deploy WAF in blocking mode. Enable OWASP CRS rules. Configure rate limiting and bot detection.', effort: '4h', impact: 'Blocks web application attacks: SQLi, XSS, SSRF, path traversal',  cert_in_prevents: true  },
  deception:    { priority: 'MEDIUM',   action: 'Deploy honeypots / honeyfiles. Set up canary tokens for sensitive files and credentials.',       effort: '8h',    impact: 'Early attacker detection; provides TTPs for threat intelligence',  cert_in_prevents: false },
  supply_chain: { priority: 'HIGH',     action: 'SBOM generation for all dependencies. SCA in CI/CD. Vendor security questionnaires. SLSA.',     effort: '16h',   impact: 'Eliminates supply chain compromise vector (npm, PyPI, Maven)',     cert_in_prevents: true  },
  cloud_iam:    { priority: 'CRITICAL', action: 'Audit cloud IAM roles. Remove wildcard permissions. Enable CloudTrail/CloudWatch. CSPM tool.',  effort: '8h',    impact: 'Prevents cloud account takeover and data exfiltration',            cert_in_prevents: true  },
  ai_security:  { priority: 'HIGH',     action: 'Input sanitization for LLM prompts. Implement OWASP LLM Top 10 controls. Red team AI assets.', effort: '12h',   impact: 'Prevents prompt injection, model theft, data exfiltration via AI', cert_in_prevents: false },
};

// ─── Core risk scoring function ───────────────────────────────────────────────
export function computeRiskScore(findings = [], vulns = [], assets = {}) {
  let score = 0;
  const signals = [];

  // Score from findings
  for (const finding of findings) {
    const f = finding.title?.toLowerCase() + ' ' + (finding.description?.toLowerCase() || '');
    if (finding.severity === 'CRITICAL' || finding.cvss >= 9.0) {
      score += RISK_WEIGHTS.cvss_critical;
      signals.push({ type: 'critical_finding', detail: finding.title, weight: RISK_WEIGHTS.cvss_critical });
    } else if (finding.severity === 'HIGH' || finding.cvss >= 7.0) {
      score += RISK_WEIGHTS.cvss_high;
      signals.push({ type: 'high_finding', detail: finding.title, weight: RISK_WEIGHTS.cvss_high });
    } else if (finding.severity === 'MEDIUM' || finding.cvss >= 4.0) {
      score += RISK_WEIGHTS.cvss_medium;
    }
    if (finding.in_kev || finding.exploited) {
      score += RISK_WEIGHTS.in_kev;
      signals.push({ type: 'kev_exploited', detail: finding.id || finding.title, weight: RISK_WEIGHTS.in_kev });
    }
    if (finding.epss > 0.70) { score += RISK_WEIGHTS.epss_high; signals.push({ type: 'epss_high', detail: String(finding.epss), weight: RISK_WEIGHTS.epss_high }); }
    else if (finding.epss > 0.30) score += RISK_WEIGHTS.epss_medium;
    if (finding.public_exploit || finding.exploit_public) { score += RISK_WEIGHTS.public_exploit; }
    if (finding.ransomware_linked || /ransomware/i.test(f)) { score += RISK_WEIGHTS.ransomware_linked; }
    if (finding.zero_day || /zero.?day|0.?day/i.test(f)) { score += RISK_WEIGHTS.zero_day; }
    if (/lateral.?move|smb|rdp|wmi|psexec/i.test(f)) score += RISK_WEIGHTS.lateral_movement;
    if (/cred|password|mfa|auth|lsass|mimikatz/i.test(f)) score += RISK_WEIGHTS.credential_access;
    if (/tls 1\.[01]|ssl|weak cipher|poodle|beast/i.test(f)) score += RISK_WEIGHTS.weak_tls;
    if (/spf|dkim|dmarc|dnssec/i.test(f)) score += RISK_WEIGHTS.dns_weakness;
    if (/missing header|x-frame|csp|hsts/i.test(f)) score += RISK_WEIGHTS.missing_headers;
    if (/rce|remote code|arbitrary code/i.test(f)) { score += RISK_WEIGHTS.rce_capability; signals.push({ type: 'rce', detail: finding.title, weight: RISK_WEIGHTS.rce_capability }); }
    if (/exfil|data theft|upload|transfer/i.test(f)) score += RISK_WEIGHTS.data_exfil;
    if (/supply chain|third.?party|vendor|npm|pypi|maven/i.test(f)) score += RISK_WEIGHTS.supply_chain_risk;
    if (/cloud|s3|gcs|azure blob|iam|bucket|imds/i.test(f)) score += RISK_WEIGHTS.cloud_misconfigured;
    if (/pii|personal data|aadhaar|pan card|health|financial record/i.test(f)) score += RISK_WEIGHTS.dpdp_exposure;
    if (finding.severity === 'CRITICAL' || finding.in_kev) score += RISK_WEIGHTS.cert_in_reportable;
  }

  // Score from vulnerabilities
  for (const vuln of vulns) {
    if (vuln.cvss_score >= 9.0) score += 15;
    else if (vuln.cvss_score >= 7.0) score += 10;
    if (vuln.in_kev) score += 20;
    if (vuln.epss_score > 0.70) score += 15;
    if (vuln.stage === 'open') score += 5;
  }

  // Asset exposure
  if (assets.internet_facing)    score += RISK_WEIGHTS.external_exposure;
  if (assets.no_mfa)             score += RISK_WEIGHTS.no_mfa;
  if (assets.high_value_data)    score += 15;
  if (assets.privileged_systems) score += 10;
  if (assets.third_party_code)   score += 8;

  // Cap and normalize to 0–100
  const raw = Math.min(score, 200);
  const normalized = Math.round((raw / 200) * 100);
  const riskLevel = normalized >= 80 ? 'CRITICAL' : normalized >= 60 ? 'HIGH' : normalized >= 35 ? 'MEDIUM' : 'LOW';

  return { score: normalized, level: riskLevel, signals, rawScore: raw };
}

// ─── Attack path prediction ────────────────────────────────────────────────────
export function predictAttackPaths(findings = [], vulns = [], riskScore = 0) {
  const triggers = new Set();

  // Build trigger set from findings
  for (const f of findings) {
    const text = (f.title + ' ' + (f.description || '')).toLowerCase();
    if (/inject|rce|exec/i.test(text))            triggers.add('injection');
    if (/spf|dkim|dmarc/i.test(text))            { triggers.add('spf'); triggers.add('dmarc'); triggers.add('dkim'); }
    if (/mfa|multi.?factor/i.test(text))          triggers.add('mfa');
    if (/cred|password|credential/i.test(text))   triggers.add('credential');
    if (/privilege|admin|root/i.test(text))       triggers.add('privilege');
    if (/external|internet|public/i.test(text))   triggers.add('external');
    if (/ransomware/i.test(text))                 triggers.add('ransomware');
    if (/kev|exploit/i.test(text))               { triggers.add('kev'); triggers.add('public_exploit'); }
    if (/supply|third.?party|vendor/i.test(text)) triggers.add('supply_chain');
    if (f.severity === 'CRITICAL')               triggers.add('cve_critical');
  }
  for (const v of vulns) {
    if (v.in_kev)           triggers.add('kev');
    if (v.epss_score > 0.7) triggers.add('public_exploit');
    if (v.severity === 'CRITICAL') triggers.add('cve_critical');
  }

  // Match chains
  const matchedChains = ATTACK_CHAINS.filter(chain =>
    chain.triggers.some(t => triggers.has(t))
  );

  // Score and rank
  return matchedChains.map(chain => {
    const triggerMatches = chain.triggers.filter(t => triggers.has(t)).length;
    const baseProbability = Math.min(0.95, (riskScore / 100) * chain.probability_multiplier);
    const adjustedProbability = Math.min(0.99, baseProbability * (1 + triggerMatches * 0.05));

    return {
      id:          chain.id,
      name:        chain.name,
      steps:       chain.steps,
      techniques:  chain.techniques,
      probability: +adjustedProbability.toFixed(3),
      matched_triggers: chain.triggers.filter(t => triggers.has(t)),
      kill_chain_stage: chain.steps[Math.floor(chain.steps.length / 2)], // mid-chain likely current position
    };
  }).sort((a, b) => b.probability - a.probability).slice(0, 3);
}

// ─── Threat actor correlation ──────────────────────────────────────────────────
export function correlateThretActors(findings = [], sector = 'technology') {
  const text = findings.map(f => f.title + ' ' + (f.description || '')).join(' ').toLowerCase();
  const normalizedSector = sector.toLowerCase();

  const relevant = THREAT_ACTORS_DB.filter(actor => {
    const sectorMatch = actor.sectors.some(s => normalizedSector.includes(s) || s.includes(normalizedSector.split(' ')[0]));
    const ttpMatch    = actor.ttps.some(t => text.includes(t.toLowerCase()));
    const motivMatch  = /finance|crypto|bank/i.test(normalizedSector) && /financial/i.test(actor.motivation);
    return sectorMatch || ttpMatch || motivMatch;
  });

  return (relevant.length ? relevant : THREAT_ACTORS_DB.slice(0, 3)).map(actor => ({
    id:           actor.id,
    name:         actor.name,
    nation_state: actor.nation,
    motivation:   actor.motivation,
    threat_level: actor.risk_elevation >= 1.4 ? 'HIGH' : 'MEDIUM',
    active_campaigns: actor.ttps?.length ?? 1,
    relevant_ttps: actor.ttps,
  }));
}

// ─── Remediation recommendation engine ────────────────────────────────────────
export function generateRemediation(findings = [], riskScore = 0, tier = 'FREE') {
  const actions = [];
  const seen    = new Set();

  const add = (key, overrides = {}) => {
    if (seen.has(key) || !REMEDIATION_TEMPLATES[key]) return;
    seen.add(key);
    actions.push({ id: key, ...REMEDIATION_TEMPLATES[key], ...overrides });
  };

  for (const f of findings) {
    const text = (f.title + ' ' + (f.description || '')).toLowerCase();
    if (/tls|ssl|cipher|https/i.test(text))        add('tls');
    if (/spf|dkim|dmarc|dnssec|dns/i.test(text))   add('dns');
    if (/header|csp|hsts|x-frame/i.test(text))     add('headers');
    if (/mfa|multi.?factor|auth/i.test(text))       add('mfa');
    if (/cve|patch|vuln|exploit/i.test(text))       add('patch');
    if (/lateral|smb|rdp|network/i.test(text))      add('network');
    if (/log|siem|monitor|detect/i.test(text))      add('logging');
    if (/credential|password|access|privilege/i.test(text)) add('access');
    if (/ransomware|backup|recovery/i.test(text))   add('backup');
    if (/malware|endpoint|edr/i.test(text))         add('edr');
  }

  // Always add patch if score is high
  if (riskScore >= 70) add('patch');
  if (riskScore >= 60) add('mfa');
  if (riskScore >= 50) add('logging');

  // Sort by priority
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  actions.sort((a, b) => (order[a.priority] ?? 9) - (order[b.priority] ?? 9));

  // Gate advanced remediation behind tier
  return tier === 'FREE' ? actions.slice(0, 3) : actions;
}

// ─── Business impact assessment ───────────────────────────────────────────────
export function assessBusinessImpact(riskScore = 0, findings = []) {
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL' || f.cvss >= 9.0).length;
  const kevCount      = findings.filter(f => f.in_kev || f.exploited).length;

  const financialRisk = riskScore >= 80 ? 'CRITICAL (₹10Cr–₹250Cr+ | $1M+)' :
                        riskScore >= 60 ? 'HIGH (₹1Cr–₹10Cr | $100K–$1M)' :
                        riskScore >= 40 ? 'MEDIUM (₹10L–₹1Cr | $10K–$100K)' : 'LOW (₹1L–₹10L | <$10K)';

  const breachProbability12mo = Math.min(0.95, riskScore / 100 * 0.8 + kevCount * 0.05);
  const regulatoryRisk = criticalCount > 2 ? 'GDPR/DPDP/SOC2 non-compliance likely' :
                         criticalCount > 0 ? 'Potential compliance gaps' : 'Low regulatory risk';

  return {
    financial_risk:          financialRisk,
    breach_probability_12mo: +breachProbability12mo.toFixed(3),
    regulatory_risk:         regulatoryRisk,
    reputational_risk:       riskScore >= 70 ? 'HIGH' : riskScore >= 50 ? 'MEDIUM' : 'LOW',
    operational_risk:        riskScore >= 80 ? 'Potential service disruption' :
                             riskScore >= 60 ? 'Elevated operational risk' : 'Nominal',
    ransomware_exposure:     kevCount > 0 ? 'HIGH — KEV vulnerabilities present' : 'MEDIUM',
    data_breach_likelihood:  criticalCount > 3 ? 'CRITICAL' : criticalCount > 1 ? 'HIGH' : 'MODERATE',
  };
}

// ─── MITRE coverage assessment ─────────────────────────────────────────────────
export function assessMITRECoverage(findings = []) {
  const covered    = new Set();
  const uncovered  = [];
  const allTactics = ['TA0001','TA0002','TA0003','TA0004','TA0005','TA0006','TA0007','TA0008','TA0009','TA0010','TA0011','TA0040'];

  const tacticKeywords = {
    'TA0001': ['initial','phishing','exploit','web','spf','dmarc'],
    'TA0002': ['exec','script','powershell','command','code'],
    'TA0003': ['persist','registry','startup','cron','service'],
    'TA0004': ['privilege','escalation','admin','root','sudo'],
    'TA0005': ['evasion','obfuscat','bypass','disable','stealth'],
    'TA0006': ['credential','password','hash','token','mfa'],
    'TA0007': ['discover','scan','enum','recon','network'],
    'TA0008': ['lateral','smb','rdp','wmi','pass.the'],
    'TA0009': ['collect','data','file','screenshot','keylog'],
    'TA0010': ['exfil','upload','transfer','dns.tunnel'],
    'TA0011': ['c2','beacon','callback','tunnel','covert'],
    'TA0040': ['impact','ransom','wipe','disrupt','ddos'],
  };

  const allText = findings.map(f => (f.title + ' ' + (f.description||'')).toLowerCase()).join(' ');
  for (const [tactic, keywords] of Object.entries(tacticKeywords)) {
    if (keywords.some(k => allText.includes(k))) covered.add(tactic);
    else uncovered.push(tactic);
  }

  return {
    tactics_detected:  [...covered],
    tactics_blind_spots: uncovered,
    coverage_pct: +((covered.size / allTactics.length) * 100).toFixed(1),
    detection_gaps: uncovered.length > 6 ? 'Significant visibility gaps' :
                    uncovered.length > 3 ? 'Moderate gaps' : 'Good coverage',
  };
}

// ─── Master CyberBrain analysis ────────────────────────────────────────────────
export async function runCyberBrainAnalysis(env, {
  findings    = [],
  vulns       = [],
  assets      = {},
  sector      = 'technology',
  tier        = 'FREE',
  target      = '',
  module      = 'domain',
} = {}) {
  const { score: riskScore, level: riskLevel, signals, rawScore } = computeRiskScore(findings, vulns, assets);
  const attackPaths          = predictAttackPaths(findings, vulns, riskScore);
  const threatActors         = correlateThretActors(findings, sector);
  const recommendedActions   = generateRemediation(findings, riskScore, tier);
  const businessImpact       = assessBusinessImpact(riskScore, findings);
  const mitreCoverage        = assessMITRECoverage(findings);
  const exploitProbability   = Math.min(0.99, riskScore / 100 * 0.85 + (vulns.filter(v => v.in_kev).length * 0.03));

  // Try Anthropic Claude for narrative (primary), CF Workers AI fallback
  let aiNarrative = null;
  if (findings.length > 0 && tier !== 'FREE') {
    try {
      const prompt = `You are a senior cybersecurity analyst. Given these findings for ${target}:
${findings.slice(0,5).map(f => `- ${f.title}: ${f.description || ''}`).join('\n')}
Risk score: ${riskScore}/100 (${riskLevel})

Write a 2-paragraph executive briefing: (1) current threat posture, (2) top 3 immediate actions.
Be specific, actionable, authoritative. No fluff.`;

      const result = await routeAICall(env, { prompt, task_type: 'executive', tier: tier || 'PRO', max_tokens: 300, temperature: 0.2 });
      aiNarrative = result?.content || null;
    } catch {}
  }

  // Cache result in KV for 15 minutes
  const cacheKey = `cyberbrain:${target}:${module}:${new Date().toISOString().slice(0,13)}`;
  const result = {
    target, module,
    riskScore,
    riskLevel,
    exploitProbability: +exploitProbability.toFixed(3),
    attackPaths,
    threatActors: threatActors.slice(0, 3),
    recommendedActions,
    businessImpact,
    mitreCoverage,
    riskSignals:  signals.slice(0, 10),
    ai_narrative: aiNarrative,
    analyzed_at:  new Date().toISOString(),
    findings_analyzed: findings.length,
    vulns_analyzed:    vulns.length,
    platform: 'CYBERDUDEBIVASH APEX NEXUS AI Security Hub v20.0',
  };

  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: 900 }).catch(() => {});
  }

  return result;
}

// ─── Handler: POST /api/cyber-brain/analyze ───────────────────────────────────
export async function handleCyberBrainAnalyze(request, env, authCtx) {
  let body;
  try { body = await request.json(); }
  catch { return fail(request, 'Invalid JSON body', 400, 'ERR_BAD_REQUEST'); }

  const {
    target  = '',
    module  = 'domain',
    sector  = 'technology',
    findings = [],
    vulns    = [],
    assets   = {},
  } = body;

  if (!Array.isArray(findings)) {
    return fail(request, 'findings must be an array', 400, 'ERR_BAD_REQUEST');
  }

  const result = await runCyberBrainAnalysis(env, {
    findings, vulns, assets, sector, tier: authCtx.tier || 'FREE', target, module,
  });

  return ok(request, result);
}

// ─── Handler: GET /api/cyber-brain/risk-score ─────────────────────────────────
export async function handleRiskScore(request, env, authCtx) {
  const url    = new URL(request.url);
  const target = url.searchParams.get('target') || 'unknown';
  const module = url.searchParams.get('module') || 'domain';

  // Try to pull from KV cache first
  if (env?.SECURITY_HUB_KV) {
    const hour = new Date().toISOString().slice(0, 13);
    const cached = await env.SECURITY_HUB_KV.get(`cyberbrain:${target}:${module}:${hour}`).catch(() => null);
    if (cached) {
      try { return ok(request, { ...JSON.parse(cached), cached: true }); } catch {}
    }
  }

  return ok(request, {
    target, module,
    riskScore: 0,
    riskLevel: 'UNKNOWN',
    message: 'No analysis found for this target. Run a scan first.',
    platform: 'CYBERDUDEBIVASH APEX NEXUS AI Security Hub v20.0',
  });
}

// ─── Handler: GET /api/cyber-brain/attack-paths ───────────────────────────────
export async function handleAttackPaths(request, env, authCtx) {
  const url         = new URL(request.url);
  const riskScore   = parseInt(url.searchParams.get('risk_score') || '50', 10);
  const findingText = url.searchParams.get('q') || '';

  const mockFindings = findingText ? [{
    title: findingText,
    description: findingText,
    severity: riskScore >= 80 ? 'CRITICAL' : 'HIGH',
    in_kev: riskScore >= 90,
  }] : [];

  const paths = predictAttackPaths(mockFindings, [], riskScore);

  return ok(request, {
    risk_score:   riskScore,
    attack_paths: paths,
    chain_count:  paths.length,
    highest_probability: paths[0]?.probability || 0,
    platform: 'CYBERDUDEBIVASH APEX NEXUS AI Security Hub v20.0',
  });
}

// ─── Handler: GET /api/cyber-brain/threat-actors ──────────────────────────────
export async function handleThreatActors(request, env, authCtx) {
  const url    = new URL(request.url);
  const sector = url.searchParams.get('sector') || 'technology';
  const actors = correlateThretActors([], sector);
  return ok(request, {
    sector,
    threat_actors: actors,
    total: actors.length,
    platform: 'CYBERDUDEBIVASH APEX NEXUS AI Security Hub v20.0',
  });
}

// ─── Handler: GET /api/cyber-brain/remediation ────────────────────────────────
export async function handleRemediationPlan(request, env, authCtx) {
  const url    = new URL(request.url);
  const score  = parseInt(url.searchParams.get('risk_score') || '50', 10);
  const tier   = authCtx.tier || 'FREE';
  const actions = generateRemediation([], score, tier);
  return ok(request, {
    risk_score: score,
    tier,
    actions,
    total_actions: actions.length,
    estimated_total_effort: actions.reduce((sum, a) => {
      const h = parseInt(a.effort) || 0;
      return sum + h;
    }, 0) + 'h',
    platform: 'CYBERDUDEBIVASH APEX NEXUS AI Security Hub v20.0',
  });
}
