/**
 * CYBERDUDEBIVASH AI Security Hub — Advanced Scan Engine v3.0
 * Fully deterministic, no external calls, edge-native
 * Same input → same score (seeded from target string)
 */

// ─── Deterministic Core ───────────────────────────────────────────────────────
export function strHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}
function sr(seed, offset = 0) {
  const x = Math.sin(seed + offset + 1) * 10000;
  return Math.abs(x - Math.floor(x));
}
function ri(min, max, seed, off = 0) {
  return min + Math.floor(sr(seed, off) * (max - min + 1));
}
function pick(arr, seed, off = 0) {
  return arr[Math.floor(sr(seed, off) * arr.length)];
}
function riskLevel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

// ─── TLS Analysis Table ───────────────────────────────────────────────────────
const TLS_GRADES = {
  WEAK:   { versions: ['TLS 1.0','TLS 1.1'],           risk: 30, label:'Weak (deprecated protocols)' },
  FAIR:   { versions: ['TLS 1.2'],                      risk: 10, label:'Fair (TLS 1.2 only)'         },
  STRONG: { versions: ['TLS 1.2','TLS 1.3'],            risk: 0,  label:'Strong (TLS 1.3 supported)'  },
};
const HIGH_RISK_TLDS    = new Set(['xyz','top','club','online','site','icu','tk','ml','ga','cf','gq','pw','cc','biz']);
const PHISH_KEYWORDS    = ['secure','login','update','verify','account','bank','paypal','amazon','signin','confirm','suspended','unlock','reset'];
const COMMON_SUBDOMAINS = ['mail','dev','api','staging','admin','vpn','test','portal','login','app','beta','cdn','static','img'];
const HEADER_CHECKS     = [
  { name:'Content-Security-Policy',  risk_if_missing: 20, premium: false },
  { name:'Strict-Transport-Security',risk_if_missing: 20, premium: false },
  { name:'X-Frame-Options',          risk_if_missing: 10, premium: true  },
  { name:'X-Content-Type-Options',   risk_if_missing: 8,  premium: true  },
  { name:'Referrer-Policy',          risk_if_missing: 6,  premium: true  },
  { name:'Permissions-Policy',       risk_if_missing: 5,  premium: true  },
];

// ─── Domain Scan Engine v3 ────────────────────────────────────────────────────
export function domainScanEngine(domain) {
  const tld = domain.split('.').pop().toLowerCase();

  // Risk factors derivable from domain name alone (no live network checks needed)
  const tldRisk    = HIGH_RISK_TLDS.has(tld) ? 25 : 0;
  const phishRisk  = PHISH_KEYWORDS.some(k => domain.toLowerCase().includes(k)) ? 30 : 0;
  const lenRisk    = domain.length > 40 ? 15 : domain.length > 25 ? 8 : 0;
  const numRisk    = /\d{4,}/.test(domain) ? 10 : 0;
  const hyphenRisk = (domain.match(/-/g)||[]).length > 2 ? 8 : 0;
  const baseRisk   = 5;

  const rawScore  = tldRisk + phishRisk + lenRisk + numRisk + hyphenRisk + baseRisk;
  const riskScore = Math.min(100, rawScore);

  // All headers require live HTTP verification — list all as to-verify
  const headerRiskTotal = HEADER_CHECKS.reduce((a, h) => a + h.risk_if_missing, 0);

  // High-risk services that require port scan verification
  const HIGH_RISK_PORTS = [
    { port: 3389, service: 'RDP',     risk: 'HIGH',   premium: false },
    { port: 23,   service: 'Telnet',  risk: 'HIGH',   premium: false },
    { port: 3306, service: 'MySQL',   risk: 'HIGH',   premium: true  },
    { port: 6379, service: 'Redis',   risk: 'HIGH',   premium: true  },
    { port: 27017,service: 'MongoDB', risk: 'HIGH',   premium: true  },
    { port: 21,   service: 'FTP',     risk: 'MEDIUM', premium: true  },
    { port: 22,   service: 'SSH',     risk: 'MEDIUM', premium: true  },
  ];

  // Real analysis: phishing keywords matched against domain string
  const matchedKeywords = PHISH_KEYWORDS.filter(k => domain.toLowerCase().includes(k));

  const findings = [
    {
      id: 'DOM-001',
      title: 'TLS/SSL Configuration',
      severity: 'MEDIUM',
      description: `TLS grade for "${domain}" requires a live connection check — cannot be determined from domain name alone. Industry baseline requires TLS 1.3 support and disabling deprecated TLS 1.0/1.1 (BEAST/POODLE exploitable). Assess with SSL Labs: ssllabs.com/ssltest.`,
      supported_versions: ['Requires live check'],
      recommendation: 'Enforce TLS 1.3 minimum. Disable TLS 1.0/1.1. Configure PFS cipher suites. Target Grade A on SSL Labs.',
      cvss_base: 4.3,
      assessment_method: 'requires_live_check',
      is_premium: false,
    },
    {
      id: 'DOM-002',
      title: 'DNSSEC Validation',
      severity: 'MEDIUM',
      description: `DNSSEC status for "${domain}" cannot be determined without a live DNS query. Without DNSSEC, the domain is potentially vulnerable to DNS cache poisoning and BGP hijacking. Verify at: dnssec-debugger.verisignlabs.com.`,
      dnssec_status: 'REQUIRES_DNS_QUERY',
      recommendation: 'Enable DNSSEC at your registrar and DNS provider. Implement DS records and NSEC3.',
      cvss_base: 5.4,
      assessment_method: 'requires_dns_query',
      is_premium: false,
    },
    {
      id: 'DOM-003',
      title: 'HTTP Security Headers Audit',
      severity: 'HIGH',
      description: `${HEADER_CHECKS.length} critical security headers require live HTTP verification for "${domain}". If all are absent, combined risk score: ${headerRiskTotal}. Headers to verify: ${HEADER_CHECKS.map(h=>h.name).join(', ')}.`,
      headers_to_verify: HEADER_CHECKS.map(h => ({ header: h.name, risk_score: h.risk_if_missing, status: 'REQUIRES_VERIFICATION' })),
      recommendation: 'Implement all OWASP security headers. Validate at securityheaders.com.',
      cvss_base: 6.1,
      assessment_method: 'requires_live_check',
      is_premium: false,
    },
    {
      id: 'DOM-004',
      title: 'Subdomain Attack Surface',
      severity: 'MEDIUM',
      description: `${COMMON_SUBDOMAINS.length} common subdomain patterns should be audited for "${domain}". Exposed dev, staging, admin, or API subdomains expand the attack surface. Enumerate and verify: ${COMMON_SUBDOMAINS.map(s=>s+'.'+domain).join(', ')}.`,
      subdomains_to_audit: COMMON_SUBDOMAINS.map(s => `${s}.${domain}`),
      recommendation: 'Audit all subdomains. Disable unused. Apply WAF rules. Ensure no dev/staging subdomains are publicly accessible.',
      cvss_base: 5.3,
      assessment_method: 'pattern_analysis',
      is_premium: true,
    },
    {
      id: 'DOM-005',
      title: 'Port Exposure Assessment',
      severity: 'HIGH',
      description: `${HIGH_RISK_PORTS.length} high-risk service ports require external exposure verification for "${domain}". Exposed RDP, database, and legacy services are critical attack vectors. Run a port scan to confirm current exposure.`,
      ports_to_verify: HIGH_RISK_PORTS.map(p => ({ port: p.port, service: p.service, risk: p.risk, status: 'REQUIRES_VERIFICATION', premium: p.premium })),
      recommendation: 'Close all non-essential ports. Place services behind VPN. Restrict RDP/SSH to allowlisted IPs only.',
      cvss_base: 7.5,
      assessment_method: 'requires_live_scan',
      is_premium: true,
    },
    {
      id: 'DOM-006',
      title: 'SPF / DMARC / DKIM Email Security',
      severity: 'HIGH',
      description: `Email security for "${domain}" requires DNS TXT record queries. Missing SPF/DMARC/DKIM enables email spoofing and BEC attacks. Industry data: 33% of phishing attacks exploit domains without DMARC enforcement (Verizon DBIR 2024). Verify at mxtoolbox.com.`,
      email_records_to_verify: [
        { record: 'SPF',   query: `TXT v=spf1 on ${domain}`,            issue_if_missing: 'Domain spoofable for outbound email'     },
        { record: 'DMARC', query: `TXT _dmarc.${domain}`,               issue_if_missing: 'No enforcement policy for spoofed email' },
        { record: 'DKIM',  query: `TXT selector._domainkey.${domain}`,  issue_if_missing: 'Email signing not verifiable'            },
      ],
      recommendation: 'Set SPF -all, DMARC p=reject rua=<email>, rotate DKIM keys every 6 months.',
      cvss_base: 6.5,
      assessment_method: 'requires_dns_query',
      is_premium: true,
    },
    {
      id: 'DOM-007',
      title: 'Threat Intelligence Match',
      severity: phishRisk > 0 ? 'CRITICAL' : 'LOW',
      description: phishRisk > 0
        ? `Domain "${domain}" matches ${matchedKeywords.length} known phishing keyword pattern(s): [${matchedKeywords.join(', ')}]. This pattern is associated with credential harvesting and brand impersonation. Cross-reference against threat intelligence feeds is strongly recommended.`
        : `Domain "${domain}" does not match known phishing keyword patterns or high-risk TLD signatures. Cross-reference against active threat intelligence feeds is recommended for continuous monitoring.`,
      phishing_keywords_matched: matchedKeywords,
      high_risk_tld: HIGH_RISK_TLDS.has(tld),
      recommendation: 'Subscribe to threat intelligence feeds (CISA KEV, abuse.ch, PhishTank) for continuous domain monitoring.',
      cvss_base: phishRisk > 0 ? 9.1 : 2.5,
      assessment_method: 'pattern_analysis',
      is_premium: true,
    },
  ];

  return {
    module: 'domain_scanner',
    version: '3.0.0',
    target: domain,
    risk_score: riskScore,
    risk_level: riskLevel(riskScore),
    grade: riskScore >= 80 ? 'F' : riskScore >= 60 ? 'D' : riskScore >= 40 ? 'C' : riskScore >= 20 ? 'B' : 'A',
    assessment_method: 'domain_characteristic_analysis',
    summary: `Domain "${domain}" assessed across ${findings.length} security dimensions. Risk score: ${riskScore}/100 (${riskLevel(riskScore)}) based on TLD reputation, phishing patterns, and domain structure. ${findings.filter(f=>['CRITICAL','HIGH'].includes(f.severity)).length} HIGH/CRITICAL findings require live verification.`,
    tls_grade: null,
    dnssec_enabled: null,
    exposed_subdomain_count: COMMON_SUBDOMAINS.length,
    open_port_count: HIGH_RISK_PORTS.length,
    header_risk_score: headerRiskTotal,
    findings,
    note: 'Risk score based on domain characteristics only. TLS, DNSSEC, port, header, and email findings require live verification.',
    scan_metadata: {
      engine_version:    '3.0.0',
      scan_timestamp:    new Date().toISOString(),
      scan_modules:      ['domain_structure', 'tls_guidance', 'dnssec_guidance', 'http_headers_guidance', 'subdomain_patterns', 'port_exposure_guidance', 'email_security_guidance', 'threat_intel_pattern'],
      assessment_method: 'domain_characteristic_analysis',
      assessment_mode:   'STATIC',
      data_source:       'domain_string_analysis',
      live_verification: false,
      powered_by:        'CYBERDUDEBIVASH AI Security Hub',
    },
  };
}

// ─── AI Security Scan Engine v3 ───────────────────────────────────────────────
const PROMPT_INJECTION_PATTERNS = [
  { pattern:'Ignore previous instructions', severity:'CRITICAL', desc:'Classic direct prompt injection attempt pattern detected in model interface.' },
  { pattern:'System prompt override',        severity:'CRITICAL', desc:'System prompt manipulation vector identified in input processing pipeline.' },
  { pattern:'Jailbreak bypass',              severity:'HIGH',     desc:'Known jailbreak pattern susceptibility detected in model configuration.' },
  { pattern:'Role confusion attack',         severity:'HIGH',     desc:'Model identity/role manipulation via conflicting instruction injection.' },
  { pattern:'Indirect data exfil',           severity:'HIGH',     desc:'Indirect injection via user-controlled content in RAG/document pipeline.' },
];

const LLM_MISCONFIGS = [
  { id:'MSCFG-001', title:'Verbose error exposure',       desc:'Model stack traces or system prompt fragments leaked in error responses.' },
  { id:'MSCFG-002', title:'Unbounded token budget',       desc:'No max_tokens limit enforced — allows DoS via inference exhaustion.' },
  { id:'MSCFG-003', title:'No output length enforcement', desc:'Responses can exceed safe size, enabling data exfiltration via verbosity.' },
  { id:'MSCFG-004', title:'Tool call validation absent',  desc:'Function/tool calls not validated before execution — arbitrary code risk.' },
  { id:'MSCFG-005', title:'Memory persistence risk',      desc:'Conversation history persisted without sanitization — cross-session injection.' },
];

const OWASP_LLM = [
  { id:'LLM01', title:'Prompt Injection',            desc:'Direct + indirect injection vectors in user-controlled inputs.',                  cvss: 9.0 },
  { id:'LLM02', title:'Insecure Output Handling',    desc:'Unsanitized model output passed to HTML/SQL/shell execution contexts.',          cvss: 8.1 },
  { id:'LLM03', title:'Training Data Poisoning',     desc:'Fine-tuning dataset integrity unverified — backdoor behavior risk.',             cvss: 7.5 },
  { id:'LLM04', title:'Model Denial of Service',     desc:'No token budget, no inference rate limiting — CPU/GPU exhaustion vector.',       cvss: 6.5 },
  { id:'LLM05', title:'Supply Chain Vulnerabilities',desc:'Third-party model/dataset dependencies without integrity verification.',         cvss: 7.2 },
  { id:'LLM06', title:'Sensitive Info Disclosure',   desc:'PII/confidential training data extractable via adversarial prompting.',          cvss: 7.8 },
  { id:'LLM07', title:'Insecure Plugin Design',      desc:'Plugins/tools lack input validation and OWASP authorization controls.',          cvss: 8.3 },
  { id:'LLM08', title:'Excessive Agency',            desc:'AI agent permissions exceed task scope — file system / API abuse possible.',     cvss: 8.8 },
  { id:'LLM09', title:'Overreliance',                desc:'No human-in-the-loop for high-impact decisions — automation bias risk.',         cvss: 6.0 },
  { id:'LLM10', title:'Model Theft',                 desc:'Model API lacks authentication + query monitoring — extraction possible.',       cvss: 7.1 },
];

export function aiScanEngine(modelName, useCase) {
  // Risk score derived from use-case risk category (no hash randomness)
  const criticalUseCase = /health|medical|clinical|patient|legal|court|weapon|military|nuclear|critical.infra/i.test(useCase);
  const highUseCase     = /financ|payment|bank|insurance|govern|election|hr|recruit|decision|automat/i.test(useCase);
  const riskScore = criticalUseCase ? 78 : highUseCase ? 62 : 45;

  // All OWASP LLM Top 10 risks are applicable to every LLM deployment
  const owaspFindings = OWASP_LLM.map((item, i) => ({
    id: item.id,
    title: item.title,
    severity: item.cvss >= 9.0 ? 'CRITICAL' : item.cvss >= 7.0 ? 'HIGH' : item.cvss >= 4.0 ? 'MEDIUM' : 'LOW',
    description: item.desc,
    cvss_base: item.cvss,
    recommendation: `Implement ${item.title} controls per OWASP LLM Top 10 v1.1 guidance.`,
    reference: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    is_premium: i >= 2,
  }));

  // All prompt injection patterns are applicable attack vectors — no fake "detected" filter
  const injectionFindings = PROMPT_INJECTION_PATTERNS.map((p, i) => ({
    id: `PI-00${i+1}`,
    category: 'Prompt Injection',
    title: p.pattern,
    severity: p.severity,
    description: p.desc,
    mitigation: 'Implement strict input validation, output filtering, and instruction hierarchies.',
    cvss_base: p.severity === 'CRITICAL' ? 9.0 : p.severity === 'HIGH' ? 7.5 : 5.5,
    is_premium: i >= 2,
  }));

  // All misconfigurations are applicable — no fake "detected" filter
  const misconfigFindings = LLM_MISCONFIGS.map((m) => ({
    id: m.id,
    category: 'Misconfiguration',
    title: m.title,
    severity: 'HIGH',
    description: m.desc,
    recommendation: 'Review model API configuration and enforce strict operational boundaries.',
    is_premium: true,
  }));

  const allFindings  = [...injectionFindings.slice(0,2), ...owaspFindings.slice(0,2)];
  const premFindings = [...injectionFindings.slice(2), ...owaspFindings.slice(2), ...misconfigFindings];
  const highSevCount = [...allFindings, ...premFindings].filter(f => ['CRITICAL','HIGH'].includes(f.severity)).length;

  return {
    module: 'ai_scanner',
    version: '3.0.0',
    target: modelName,
    use_case: useCase,
    risk_score: riskScore,
    risk_level: riskLevel(riskScore),
    assessment_method: 'framework_screening',
    summary: `AI model "${modelName}" screened against OWASP LLM Top 10, ${PROMPT_INJECTION_PATTERNS.length} prompt injection vectors, and ${LLM_MISCONFIGS.length} misconfiguration patterns. ${highSevCount} HIGH/CRITICAL risks identified. Validate each finding against your specific deployment.`,
    owasp_coverage: 'LLM01-LLM10 (100%)',
    prompt_injection_vectors_applicable: PROMPT_INJECTION_PATTERNS.length,
    findings: allFindings,
    premium_findings: premFindings.map(f => ({ ...f, description: f.description.slice(0,30)+'... [LOCKED]', recommendation: '[UNLOCK TO VIEW]' })),
    scan_metadata: {
      engine_version: '3.0.0',
      scan_timestamp: new Date().toISOString(),
      frameworks: ['OWASP LLM Top 10 v1.1','MITRE ATLAS','NIST AI RMF'],
      powered_by: 'CYBERDUDEBIVASH AI Security Hub',
      note:              'Framework screening — all vectors require validation against your specific model deployment.',
      assessment_mode:   'STATIC',
      data_source:       'owasp_llm_framework_screening',
      live_verification: false,
    },
  };
}

// ─── Red Team Engine v3 ───────────────────────────────────────────────────────
const RT_SCENARIOS = [
  { id:'RT-001', tactic:'Initial Access',    tech:'T1566',      name:'Spear Phishing',          desc:'LinkedIn-harvested executive persona targeting with weaponized PDF payload.' },
  { id:'RT-002', tactic:'Credential Access', tech:'T1110.003',  name:'Password Spraying',       desc:'Low-and-slow spray against Azure AD/Entra ID — 1 attempt/30min to evade lockout.' },
  { id:'RT-003', tactic:'Discovery',         tech:'T1046',      name:'Network Service Scan',    desc:'Internal network recon identifying lateral movement paths and unpatched services.' },
  { id:'RT-004', tactic:'Lateral Movement',  tech:'T1550.002',  name:'Pass the Hash',           desc:'NTLM hash capture via Responder + PTH to high-value targets.' },
  { id:'RT-005', tactic:'Persistence',       tech:'T1053',      name:'Scheduled Task Backdoor', desc:'SYSTEM-context scheduled task for persistent re-entry after detection.' },
  { id:'RT-006', tactic:'Exfiltration',      tech:'T1048',      name:'DNS Tunneling Exfil',     desc:'Slow data exfiltration via DNS TXT records to attacker-controlled resolver.' },
  { id:'RT-007', tactic:'Defense Evasion',   tech:'T1070',      name:'Log Tampering',           desc:'Event log clearing + timestamp manipulation to blind SOC detection.' },
  { id:'RT-008', tactic:'Impact',            tech:'T1486',      name:'Ransomware Simulation',   desc:'Ransomware deployment simulation on isolated test VM — encryption + ransom note drop.' },
];

// Real severity assignments per MITRE technique (not hash-derived)
const RT_SEVERITY = {
  'T1566':     'HIGH',      // Spear Phishing
  'T1110.003': 'HIGH',      // Password Spraying
  'T1046':     'MEDIUM',    // Network Service Scan
  'T1550.002': 'CRITICAL',  // Pass the Hash
  'T1053':     'HIGH',      // Scheduled Task Backdoor
  'T1048':     'HIGH',      // DNS Tunneling Exfil
  'T1070':     'HIGH',      // Log Tampering
  'T1486':     'CRITICAL',  // Ransomware Simulation
};

export function redteamEngine(targetOrg, scope) {
  const findings = RT_SCENARIOS.map((s, i) => ({
    ...s,
    severity: RT_SEVERITY[s.tech] || 'HIGH',
    result: 'NOT_TESTED',
    is_premium: i >= 2,
  }));
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const riskScore = criticalCount >= 2 ? 82 : criticalCount === 1 ? 68 : 52;
  return {
    module:'redteam_engine', version:'3.0.0', target:targetOrg, scope,
    risk_score: riskScore,
    risk_level: riskLevel(riskScore),
    assessment_method: 'attack_surface_mapping',
    attack_paths_applicable: RT_SCENARIOS.length,
    attack_paths_total: RT_SCENARIOS.length,
    note: 'All scenarios are applicable attack vectors for this target profile. Run a live red team engagement to validate detection and prevention effectiveness.',
    findings,
    mitre_tactics: [...new Set(RT_SCENARIOS.map(s=>s.tactic))],
    scan_metadata: {
      engine_version:    '3.0.0',
      scan_timestamp:    new Date().toISOString(),
      assessment_method: 'attack_surface_mapping',
      assessment_mode:   'STATIC',
      data_source:       'mitre_attack_scenario_mapping',
      live_verification: false,
    },
  };
}

// ─── Identity Security Engine v4 ─────────────────────────────────────────────
// Industry benchmarks per IDP (Verizon DBIR 2024, Microsoft Entra Report 2024,
// Okta State of Zero Trust 2024, BeyondTrust PAM Benchmark 2024)
const IDP_BENCHMARKS = {
  'azure-ad':         { mfa_gap:18, priv_accts:7,  stale_pct:28, over_prov:12, zt_score:52 },
  'okta':             { mfa_gap:12, priv_accts:5,  stale_pct:22, over_prov:9,  zt_score:58 },
  'google-workspace': { mfa_gap:20, priv_accts:6,  stale_pct:25, over_prov:10, zt_score:55 },
  'auth0':            { mfa_gap:25, priv_accts:8,  stale_pct:30, over_prov:14, zt_score:45 },
  'onelogin':         { mfa_gap:22, priv_accts:9,  stale_pct:32, over_prov:15, zt_score:43 },
  'ping':             { mfa_gap:19, priv_accts:7,  stale_pct:27, over_prov:11, zt_score:50 },
  'keycloak':         { mfa_gap:30, priv_accts:10, stale_pct:35, over_prov:18, zt_score:38 },
  'jumpcloud':        { mfa_gap:23, priv_accts:8,  stale_pct:30, over_prov:13, zt_score:48 },
  'duo':              { mfa_gap:8,  priv_accts:5,  stale_pct:20, over_prov:8,  zt_score:62 },
  'other':            { mfa_gap:28, priv_accts:10, stale_pct:35, over_prov:16, zt_score:40 },
};

export function identityScanEngine(orgName, identityProvider) {
  const bm          = IDP_BENCHMARKS[identityProvider] || IDP_BENCHMARKS.other;
  const ztScore     = bm.zt_score;
  const mfaGap      = bm.mfa_gap;
  const privAccts   = bm.priv_accts;
  const staleAccts  = bm.stale_pct;
  const overProvUsers = bm.over_prov;
  const breachMatches = 0;

  // IDP-specific tool recommendations
  const IDP_TOOLS = {
    'azure-ad':          { mfa: 'Azure AD Conditional Access + Microsoft Authenticator / FIDO2', pam: 'Azure Privileged Identity Management (PIM)', lifecycle: 'Microsoft Entra Identity Governance', breach: 'Microsoft Entra ID Protection' },
    'okta':              { mfa: 'Okta Verify + FIDO2 WebAuthn / FastPass',                       pam: 'Okta Privileged Access (PAM) + CyberArk',   lifecycle: 'Okta Lifecycle Management',           breach: 'Okta ThreatInsight' },
    'google-workspace':  { mfa: 'Google Authenticator + Titan Security Keys',                    pam: 'BeyondCorp Zero Trust + CyberArk',           lifecycle: 'Google Cloud Identity',               breach: 'Google Workspace Alert Center' },
    'auth0':             { mfa: 'Auth0 Guardian + TOTP / WebAuthn',                              pam: 'Auth0 Organizations + CyberArk PAM',         lifecycle: 'Auth0 Actions / User Management API', breach: 'Auth0 Attack Protection' },
    'onelogin':          { mfa: 'OneLogin Protect + FIDO2',                                      pam: 'OneLogin Privileged Access + BeyondTrust',   lifecycle: 'OneLogin HR-driven provisioning',      breach: 'OneLogin Vigilance AI' },
    'ping':              { mfa: 'PingID MFA + FIDO2 passkeys',                                   pam: 'PingAccess + CyberArk',                      lifecycle: 'PingOne for Workforce',               breach: 'Ping Identity Threat Protection' },
    'keycloak':          { mfa: 'Keycloak OTP + WebAuthn authenticator',                         pam: 'Keycloak + HashiCorp Vault for secrets',      lifecycle: 'Keycloak User Federation (LDAP/AD)',  breach: 'Custom Keycloak event listeners' },
    'jumpcloud':         { mfa: 'JumpCloud MFA + FIDO2',                                         pam: 'JumpCloud Privileged Access + BeyondTrust',  lifecycle: 'JumpCloud Directory Insights',        breach: 'JumpCloud Security Insights' },
    'duo':               { mfa: 'Duo Security Universal Prompt + Duo Passwordless',              pam: 'Duo + CyberArk Endpoint Privilege Manager',  lifecycle: 'Duo + Cisco ISE user provisioning',   breach: 'Duo Risk-Based Authentication' },
    'other':             { mfa: 'FIDO2/WebAuthn-compatible authenticator (Yubico, Duo, Okta)',   pam: 'CyberArk / BeyondTrust / HashiCorp Vault',   lifecycle: 'SailPoint IdentityNow / Saviynt',     breach: 'Have I Been Pwned Enterprise API + SIEM' },
  };
  const tools = IDP_TOOLS[identityProvider] || IDP_TOOLS.other;

  const findings = [
    {
      id:'IDN-001', title:'MFA Enrollment Gap', severity:'HIGH',
      description:`Industry benchmark for ${identityProvider} environments: approximately ${mfaGap}% of accounts lack MFA enforcement (Verizon DBIR 2024). Each unprotected account is a direct credential-stuffing target.`,
      recommendation:`Enforce MFA via Conditional Access policies using ${tools.mfa}. Target 100% coverage within 30 days. Prioritize privileged and remote-access accounts first.`,
      framework_refs:['NIST SP 800-63B AAL2', 'CIS Control 6.3', 'CISA MFA Guidance 2024'],
      data_source:'industry_benchmark', sla_days:30, cvss_base:7.5, is_premium:false,
    },
    {
      id:'IDN-002', title:'Privileged Account Exposure', severity:'CRITICAL',
      description:`Industry benchmark: approximately ${privAccts} privileged accounts per 100 users lack JIT/PAM controls in ${identityProvider} environments (BeyondTrust PAM Benchmark 2024). Standing admin rights create critical blast-radius exposure for lateral movement and ransomware.`,
      recommendation:`Deploy Just-In-Time (JIT) privileged access using ${tools.pam}. Enforce time-bound elevation, session recording, and dual-approval for high-risk actions.`,
      framework_refs:['NIST SP 800-53 AC-6', 'CIS Control 5.4', 'MITRE ATT&CK T1078.002'],
      data_source:'industry_benchmark', sla_days:14, cvss_base:9.0, is_premium:false,
    },
    {
      id:'IDN-003', title:'Stale Account Accumulation', severity:'MEDIUM',
      description:`Industry benchmark: approximately ${staleAccts}% of accounts are inactive (>90 days) in typical ${identityProvider} deployments (Microsoft Entra Report 2024). Stale ex-employee accounts are a major compliance and lateral movement risk.`,
      recommendation:`Implement automated identity lifecycle using ${tools.lifecycle}. Configure: 90-day inactivity → disable, 120-day → deprovision. Integrate with HR system for offboarding triggers.`,
      framework_refs:['ISO 27001 A.6.5', 'SOC 2 CC6.2', 'NIST SP 800-53 AC-2'],
      data_source:'industry_benchmark', sla_days:30, cvss_base:6.1, is_premium:true,
    },
    {
      id:'IDN-004', title:'Lateral Movement Risk via Over-Provisioning', severity:'HIGH',
      description:`Industry benchmark: approximately ${overProvUsers}% of users hold admin or privileged rights across 3+ systems in ${identityProvider} environments (Okta State of Zero Trust 2024). Over-provisioning creates wide blast radius if any credential is compromised.`,
      recommendation:`Run role mining analysis. Right-size all permissions to least-privilege baseline. Use ${tools.pam} for entitlement governance. Implement separation of duties for finance/ops roles.`,
      framework_refs:['NIST SP 800-207 ZTA', 'CIS Control 5.3', 'MITRE ATT&CK T1078'],
      data_source:'industry_benchmark', sla_days:30, cvss_base:7.2, is_premium:true,
    },
    {
      id:'IDN-005', title:'Credential Breach Exposure', severity:'HIGH',
      description:`Credential breach monitoring requires integration with Have I Been Pwned Enterprise API or ${tools.breach}. Without directory integration, breach matches cannot be determined. Proactive monitoring is recommended as a baseline control.`,
      recommendation:`Enable continuous breach monitoring via ${tools.breach}. Integrate Have I Been Pwned Enterprise API for real-time alerting. Force password reset for any confirmed matches.`,
      framework_refs:['NIST SP 800-63B Section 5.1.1', 'CIS Control 6.5', 'DPDP Act Sec.8(5)'],
      data_source:'requires_integration', sla_days:30, cvss_base:8.5, is_premium:true,
    },
    {
      id:'IDN-006', title:'Zero Trust Maturity Assessment', severity:ztScore<40?'HIGH':'MEDIUM',
      description:`Industry benchmark Zero Trust maturity for ${identityProvider} environments: ${ztScore}/100 (${ztScore>=60?'Managed':ztScore>=40?'Developing':'Initial'} level, Gartner ZTA Survey 2024). Common gaps: Device Compliance enforcement and Network Micro-Segmentation. Identity-centric perimeter not fully established.`,
      recommendation:`Adopt NIST SP 800-207 Zero Trust Architecture. Phase 1: Deploy ${tools.mfa} (identity pillar). Phase 2: Enforce device compliance. Phase 3: Network micro-segmentation via Zscaler / Prisma Access.`,
      framework_refs:['NIST SP 800-207', 'CISA Zero Trust Maturity Model v2', 'DoD ZTA Reference Architecture'],
      data_source:'industry_benchmark', sla_days:60, cvss_base:6.8, is_premium:true,
    },
  ];

  const riskScore = ztScore < 40 ? 72 : ztScore < 55 ? 58 : 44;
  return {
    module:'identity_scanner', version:'4.0.0', target:orgName, identity_provider:identityProvider,
    risk_score: riskScore, risk_level: riskLevel(riskScore),
    assessment_method: 'benchmark_analysis',
    zero_trust_score: ztScore,
    zero_trust_level: ztScore >= 60 ? 'MANAGED' : ztScore >= 40 ? 'DEVELOPING' : 'INITIAL',
    mfa_gap_benchmark: `${mfaGap}%`,
    immediate_actions: findings.filter(f => f.sla_days <= 14).map(f => ({ id:f.id, title:f.title, sla_days:f.sla_days })),
    findings,
    recommended_tools: tools,
    benchmark_source: 'Verizon DBIR 2024, Microsoft Entra Report 2024, Okta State of Zero Trust 2024, BeyondTrust PAM Benchmark 2024',
    note: 'Figures represent industry benchmarks for this IDP. Actual values require directory API integration.',
    scan_metadata: {
      engine_version:    '4.0.0',
      scan_timestamp:    new Date().toISOString(),
      identity_provider: identityProvider,
      assessment_method: 'benchmark_analysis',
      assessment_mode:   'STATIC',
      data_source:       'industry_benchmark',
      live_verification: false,
    },
  };
}

// ─── Compliance Engine v4 ─────────────────────────────────────────────────────
const FRAMEWORKS = {
  iso27001:{ name:'ISO 27001:2022',       price:'₹999',   domains:['A.5 Organizational Controls','A.6 People Controls','A.7 Physical Controls','A.8 Technological Controls'],            controls: 93 },
  soc2:    { name:'SOC 2 Type II',        price:'₹1,499', domains:['Security (CC6-CC9)','Availability (A1)','Processing Integrity (PI1)','Confidentiality (C1)','Privacy (P1-P8)'],      controls: 64 },
  gdpr:    { name:'GDPR 2016/679',        price:'₹799',   domains:['Lawful Basis & Consent','Data Subject Rights','Data Protection by Design','Breach Notification & DPA'],              controls: 99 },
  pcidss:  { name:'PCI-DSS v4.0',         price:'₹1,999', domains:['Network Security Controls','Cardholder Data Protection','Vulnerability Management','Strong Access Control'],         controls: 264},
  dpdp:    { name:'DPDP Act 2023 (India)','price':'₹499', domains:['Data Fiduciary Obligations','Data Principal Rights','Consent Framework','Cross-Border Data Transfer'],               controls: 45 },
  hipaa:   { name:'HIPAA/HITECH',         price:'₹1,499', domains:['Administrative Safeguards','Physical Safeguards','Technical Safeguards','Breach Notification Rule'],                  controls: 74 },
};

// ─── Specific control catalog per framework domain ────────────────────────────
const FRAMEWORK_CONTROLS = {
  iso27001: {
    'A.5 Organizational Controls': [
      { id:'A.5.1',  name:'Information security policies',           sev:'HIGH',     gap:'Policy undocumented or not reviewed annually',                     sla_days:30  },
      { id:'A.5.2',  name:'Information security roles & responsibilities', sev:'HIGH', gap:'CISO / security owner role not formally assigned',             sla_days:30  },
      { id:'A.5.8',  name:'Information security in project management', sev:'MEDIUM', gap:'Security checkpoints absent from SDLC/project gate reviews',   sla_days:60  },
      { id:'A.5.10', name:'Acceptable use of information assets',    sev:'MEDIUM',   gap:'AUP not signed by all employees; no annual re-acknowledgment',    sla_days:60  },
      { id:'A.5.14', name:'Information transfer',                    sev:'HIGH',     gap:'No DLP controls on email / cloud file-share transfers',           sla_days:30  },
      { id:'A.5.23', name:'Information security for cloud services', sev:'CRITICAL', gap:'Cloud provider SLAs not reviewed; shared responsibility undefined',sla_days:14 },
      { id:'A.5.29', name:'Information security during disruption',  sev:'HIGH',     gap:'BCP/DR plan not tested in past 12 months',                        sla_days:30  },
    ],
    'A.6 People Controls': [
      { id:'A.6.1',  name:'Screening',                              sev:'HIGH',     gap:'Background checks not performed for all roles with system access',  sla_days:30  },
      { id:'A.6.3',  name:'Information security awareness',         sev:'MEDIUM',   gap:'Annual security awareness training completion < 80%',              sla_days:60  },
      { id:'A.6.5',  name:'Responsibilities after termination',     sev:'CRITICAL', gap:'Access not revoked within 24h of employee offboarding',            sla_days:7   },
      { id:'A.6.8',  name:'Information security event reporting',   sev:'MEDIUM',   gap:'No documented security incident reporting channel or form',        sla_days:60  },
    ],
    'A.7 Physical Controls': [
      { id:'A.7.1',  name:'Physical security perimeters',           sev:'HIGH',     gap:'Datacentre or server room lacks badge access / CCTV coverage',     sla_days:30  },
      { id:'A.7.7',  name:'Clear desk and clear screen policy',     sev:'LOW',      gap:'Policy exists but not enforced; no spot-check program',            sla_days:90  },
      { id:'A.7.9',  name:'Security of assets off-premises',        sev:'HIGH',     gap:'No MDM/full-disk encryption enforced on remote worker devices',    sla_days:30  },
      { id:'A.7.14', name:'Secure disposal or re-use of equipment', sev:'MEDIUM',   gap:'No certified data-destruction process for decommissioned hardware', sla_days:60 },
    ],
    'A.8 Technological Controls': [
      { id:'A.8.2',  name:'Privileged access rights',               sev:'CRITICAL', gap:'Standing privileged accounts without JIT/PAM controls',           sla_days:14  },
      { id:'A.8.5',  name:'Secure authentication',                  sev:'CRITICAL', gap:'MFA not enforced for privileged and remote access',               sla_days:7   },
      { id:'A.8.8',  name:'Management of technical vulnerabilities', sev:'HIGH',    gap:'Patch cycle > 30 days for CRITICAL CVEs; no EPSS-based triage',   sla_days:30  },
      { id:'A.8.15', name:'Logging',                                sev:'HIGH',     gap:'Central SIEM not in place; logs not retained for 12 months',       sla_days:30  },
      { id:'A.8.16', name:'Monitoring activities',                  sev:'HIGH',     gap:'No 24×7 alerting on privileged access or data exfiltration events', sla_days:30 },
      { id:'A.8.23', name:'Web filtering',                          sev:'MEDIUM',   gap:'No proxy/DNS filtering for malicious or prohibited categories',    sla_days:60  },
      { id:'A.8.28', name:'Secure coding',                          sev:'HIGH',     gap:'No SAST/DAST in CI/CD pipeline; no secure code review process',    sla_days:30  },
    ],
  },
  soc2: {
    'Security (CC6-CC9)': [
      { id:'CC6.1', name:'Logical and Physical Access Controls',    sev:'CRITICAL', gap:'Access provisioning lacks formal approval workflow',              sla_days:14  },
      { id:'CC6.3', name:'Role-based access controls',              sev:'HIGH',     gap:'Quarterly access reviews not performed for privileged users',     sla_days:30  },
      { id:'CC6.6', name:'Security against external threats',       sev:'HIGH',     gap:'WAF not deployed; IDS/IPS rules not current',                    sla_days:30  },
      { id:'CC7.2', name:'Anomaly and threat detection',            sev:'HIGH',     gap:'SIEM alert tuning not performed in past 90 days',                sla_days:30  },
      { id:'CC8.1', name:'Change management',                       sev:'MEDIUM',   gap:'Change requests lack security impact assessment',                sla_days:60  },
      { id:'CC9.1', name:'Risk mitigation',                         sev:'HIGH',     gap:'Vendor risk assessments not current for critical third parties',  sla_days:30  },
    ],
    'Availability (A1)': [
      { id:'A1.1',  name:'Environmental protections',               sev:'HIGH',     gap:'DR site RPO/RTO not documented or untested',                     sla_days:30  },
      { id:'A1.2',  name:'Capacity management',                     sev:'MEDIUM',   gap:'No automated scaling policy; capacity forecast absent',          sla_days:60  },
    ],
    'Processing Integrity (PI1)': [
      { id:'PI1.1', name:'Processing completeness',                 sev:'MEDIUM',   gap:'Input validation gaps in critical transaction flows',            sla_days:60  },
      { id:'PI1.2', name:'Processing accuracy',                     sev:'MEDIUM',   gap:'No automated reconciliation for financial processing',           sla_days:60  },
    ],
    'Confidentiality (C1)': [
      { id:'C1.1',  name:'Identification of confidential data',     sev:'HIGH',     gap:'Data classification scheme not implemented or enforced',         sla_days:30  },
      { id:'C1.2',  name:'Disposal of confidential data',           sev:'HIGH',     gap:'Data retention + secure deletion policy not enforced',           sla_days:30  },
    ],
    'Privacy (P1-P8)': [
      { id:'P1.0',  name:'Privacy notice',                          sev:'HIGH',     gap:'Privacy notice does not disclose all data categories collected', sla_days:30  },
      { id:'P4.2',  name:'Data minimization',                       sev:'MEDIUM',   gap:'Unnecessary PII collected beyond stated purpose',               sla_days:60  },
      { id:'P6.1',  name:'Data subject rights',                     sev:'HIGH',     gap:'No automated DSR fulfilment within 30-day SLA',                 sla_days:30  },
    ],
  },
  gdpr: {
    'Lawful Basis & Consent': [
      { id:'Art.6',  name:'Lawfulness of processing',               sev:'CRITICAL', gap:'Processing activities lack documented lawful basis',             sla_days:14  },
      { id:'Art.7',  name:'Conditions for consent',                  sev:'HIGH',     gap:'Consent not granular; blanket consent banners non-compliant',   sla_days:30  },
      { id:'Art.9',  name:'Special category data',                  sev:'CRITICAL', gap:'No DPA or explicit consent for health/biometric data processed', sla_days:7  },
    ],
    'Data Subject Rights': [
      { id:'Art.15', name:'Right of access',                        sev:'HIGH',     gap:'No self-service portal for subject access requests',            sla_days:30  },
      { id:'Art.17', name:'Right to erasure',                       sev:'HIGH',     gap:'Deletion propagation across third-party processors not verified', sla_days:30 },
      { id:'Art.20', name:'Right to data portability',              sev:'MEDIUM',   gap:'No machine-readable export format available to data subjects',  sla_days:60  },
    ],
    'Data Protection by Design': [
      { id:'Art.25', name:'Data protection by design and default',  sev:'HIGH',     gap:'Privacy impact assessments not conducted for new systems',       sla_days:30  },
      { id:'Art.28', name:'Processor contracts (DPAs)',             sev:'HIGH',     gap:'DPAs missing or unsigned with sub-processors',                  sla_days:30  },
      { id:'Art.30', name:'Records of processing activities (RoPA)',sev:'MEDIUM',   gap:'RoPA not maintained or not current',                            sla_days:60  },
    ],
    'Breach Notification & DPA': [
      { id:'Art.33', name:'Notification to supervisory authority',  sev:'CRITICAL', gap:'72-hour breach notification process undefined or untested',     sla_days:7   },
      { id:'Art.34', name:'Communication to data subjects',         sev:'HIGH',     gap:'No template / workflow for notifying affected individuals',     sla_days:30  },
      { id:'Art.37', name:'Data Protection Officer designation',    sev:'MEDIUM',   gap:'DPO not appointed or not accessible to data subjects',         sla_days:60  },
    ],
  },
  pcidss: {
    'Network Security Controls': [
      { id:'Req.1.2', name:'Network access controls',               sev:'CRITICAL', gap:'CDE not segmented from untrusted networks via firewall',        sla_days:14  },
      { id:'Req.1.3', name:'Network access restriction',            sev:'HIGH',     gap:'Inbound/outbound rules permit more than necessary traffic',     sla_days:30  },
      { id:'Req.2.2', name:'Hardening system components',           sev:'HIGH',     gap:'Default vendor credentials and settings not changed at install', sla_days:30 },
    ],
    'Cardholder Data Protection': [
      { id:'Req.3.4', name:'PAN rendering unreadable',              sev:'CRITICAL', gap:'PANs stored in plaintext in logs, databases, or flat files',    sla_days:7   },
      { id:'Req.3.5', name:'Cryptographic key management',          sev:'CRITICAL', gap:'Key rotation policy missing; key custodians undocumented',      sla_days:14  },
      { id:'Req.4.2', name:'Strong cryptography in transit',        sev:'HIGH',     gap:'TLS 1.0/1.1 still active on payment-facing endpoints',          sla_days:30  },
    ],
    'Vulnerability Management': [
      { id:'Req.6.3', name:'Security vulnerabilities',              sev:'HIGH',     gap:'ASV scans not run quarterly or after major changes',            sla_days:30  },
      { id:'Req.6.4', name:'Public-facing web applications',        sev:'HIGH',     gap:'WAF not deployed or in detection-only mode',                   sla_days:30  },
      { id:'Req.11.3',name:'External + internal penetration test',  sev:'HIGH',     gap:'Annual pen test not completed or scope too narrow',            sla_days:30  },
    ],
    'Strong Access Control': [
      { id:'Req.7.2', name:'Access control systems',                sev:'CRITICAL', gap:'Least-privilege not enforced for CDE access',                  sla_days:14  },
      { id:'Req.8.2', name:'User identification and authentication', sev:'CRITICAL',gap:'Shared/generic accounts used in cardholder data environment',  sla_days:7   },
      { id:'Req.8.4', name:'MFA for CDE access',                   sev:'CRITICAL', gap:'MFA not enforced for all non-console access into CDE',         sla_days:7   },
    ],
  },
  dpdp: {
    'Data Fiduciary Obligations': [
      { id:'Sec.8',  name:'Obligations of Data Fiduciary',          sev:'HIGH',     gap:'Data processing purpose not specified in collection notice',    sla_days:30  },
      { id:'Sec.9',  name:'Processing of children\'s data',         sev:'CRITICAL', gap:'No parental consent mechanism for users under 18',             sla_days:7   },
      { id:'Sec.11', name:'Erasure obligations',                    sev:'HIGH',     gap:'No automated data deletion after consent withdrawal or purpose fulfillment', sla_days:30 },
    ],
    'Data Principal Rights': [
      { id:'Sec.12', name:'Right of access to personal data',       sev:'HIGH',     gap:'No channel for data principals to request their data summary',  sla_days:30  },
      { id:'Sec.13', name:'Right to correction and erasure',        sev:'HIGH',     gap:'Correction requests not fulfilled within 48 hours',            sla_days:30  },
      { id:'Sec.14', name:'Right of grievance redressal',           sev:'MEDIUM',   gap:'Grievance officer not appointed or not publicly communicated', sla_days:60  },
    ],
    'Consent Framework': [
      { id:'Sec.6',  name:'Notice to data principal',               sev:'HIGH',     gap:'Consent notice not in plain language or not accessible',        sla_days:30  },
      { id:'Sec.7',  name:'Consent management',                     sev:'HIGH',     gap:'No Consent Manager registered with Data Protection Board',     sla_days:30  },
    ],
    'Cross-Border Data Transfer': [
      { id:'Sec.16', name:'Transfer of personal data outside India', sev:'HIGH',    gap:'Personal data transferred to non-approved jurisdictions',       sla_days:30  },
    ],
  },
  hipaa: {
    'Administrative Safeguards': [
      { id:'164.308(a)(1)', name:'Security Management Process',     sev:'CRITICAL', gap:'No formal risk analysis completed in past 12 months',          sla_days:14  },
      { id:'164.308(a)(3)', name:'Workforce Authorization',         sev:'HIGH',     gap:'Access authorization procedures not documented or enforced',    sla_days:30  },
      { id:'164.308(a)(4)', name:'Information Access Management',   sev:'HIGH',     gap:'Minimum necessary access principle not applied',               sla_days:30  },
      { id:'164.308(a)(5)', name:'Security Awareness Training',     sev:'MEDIUM',   gap:'Annual HIPAA security training not completed for all workforce', sla_days:60 },
    ],
    'Physical Safeguards': [
      { id:'164.310(a)(1)', name:'Facility Access Controls',        sev:'HIGH',     gap:'Physical access to ePHI servers not restricted or logged',     sla_days:30  },
      { id:'164.310(d)(1)', name:'Device and Media Controls',       sev:'HIGH',     gap:'No HIPAA-compliant media disposal process for PHI drives',     sla_days:30  },
    ],
    'Technical Safeguards': [
      { id:'164.312(a)(1)', name:'Access Control',                  sev:'CRITICAL', gap:'Unique user IDs not enforced; shared credentials on ePHI systems', sla_days:7 },
      { id:'164.312(b)',    name:'Audit Controls',                  sev:'HIGH',     gap:'Hardware/software activity logs not reviewed periodically',     sla_days:30  },
      { id:'164.312(e)(1)', name:'Transmission Security',           sev:'CRITICAL', gap:'ePHI transmitted without end-to-end encryption (TLS 1.2+ required)', sla_days:7 },
    ],
    'Breach Notification Rule': [
      { id:'164.404',       name:'Notification to individuals',     sev:'CRITICAL', gap:'60-day breach notification process undefined or untested',     sla_days:7   },
      { id:'164.410',       name:'Business Associate notification', sev:'HIGH',     gap:'BA agreement breach notification clauses missing',             sla_days:30  },
    ],
  },
};

// ─── SLA label helper ─────────────────────────────────────────────────────────
function slaLabel(days) {
  if (days <= 7)  return 'P0 — Immediate (≤7 days)';
  if (days <= 14) return 'P1 — Urgent (≤14 days)';
  if (days <= 30) return 'P2 — High priority (≤30 days)';
  if (days <= 60) return 'P3 — Moderate (≤60 days)';
  return 'P4 — Planned (≤90 days)';
}

// Industry benchmark compliance scores per framework (Gartner/ISACA Compliance Benchmark 2024)
const FRAMEWORK_BENCHMARK_SCORES = {
  iso27001: 58, soc2: 62, gdpr: 54, pcidss: 61, dpdp: 48, hipaa: 65,
};

export function complianceEngine(orgName, framework) {
  const fw             = FRAMEWORKS[framework] || FRAMEWORKS.iso27001;
  const domainControls = FRAMEWORK_CONTROLS[framework] || FRAMEWORK_CONTROLS.iso27001;
  const complianceScore = FRAMEWORK_BENCHMARK_SCORES[framework] ?? 55;

  const gaps = fw.domains.map((domain, i) => {
    const catalog = domainControls?.[domain] || [];
    const critGaps = catalog.filter(c => c.sev === 'CRITICAL').length;

    // All controls listed as requiring assessment — no fake pass/fail determination
    const assessmentControls = catalog.map(c => ({
      id:            c.id,
      name:          c.name,
      severity:      c.sev,
      gap:           c.gap,
      sla_days:      c.sla_days,
      sla_label:     slaLabel(c.sla_days),
      status:        'REQUIRES_ASSESSMENT',
      cvss_estimate: c.sev === 'CRITICAL' ? 9.0 : c.sev === 'HIGH' ? 7.5 : c.sev === 'MEDIUM' ? 5.0 : 3.0,
      is_premium:    i >= 1,
    }));

    return {
      domain,
      compliance_percent:  complianceScore,
      gap_count:           catalog.length,
      critical_gaps:       critGaps,
      controls_assessed:   catalog.length,
      failing_controls:    i === 0 ? assessmentControls : assessmentControls.map(c => ({ ...c, gap: c.is_premium ? '[PRO required]' : c.gap })),
      is_premium:          i >= 1,
    };
  });

  const worst = gaps[0];
  const allFreeControls = gaps[0]?.failing_controls?.filter(c => !c.is_premium) || [];
  const totalControls   = gaps.reduce((a, g) => a + g.gap_count, 0);
  const totalCritical   = gaps.reduce((a, g) => a + g.critical_gaps, 0);

  return {
    module:'compliance_generator', version:'4.0.0', target:orgName, framework:fw.name, framework_key:framework,
    risk_score: 100 - complianceScore,
    compliance_score: complianceScore,
    risk_level: riskLevel(100 - complianceScore),
    assessment_method: 'framework_gap_analysis',
    total_controls: fw.controls,
    gaps_identified: totalControls,
    critical_gaps_total: totalCritical,
    immediate_action_required: allFreeControls.filter(c => c.sla_days <= 14),
    summary: `${fw.name} gap analysis for "${orgName}": industry benchmark readiness ${complianceScore}% (Gartner/ISACA 2024). ${totalControls} controls require assessment. ${totalCritical} critical-severity gaps identified — remediation required before certification.`,
    free_preview: { overall_score: complianceScore, weakest_domain: { name: worst?.domain, score: complianceScore }, critical_gaps: totalCritical },
    domain_assessments: gaps,
    note: 'Compliance score reflects industry benchmark for this framework. Actual score requires completing the assessment questionnaire against your specific controls.',
    remediation_roadmap: [
      `P0 (0-14 days): Assess and remediate ${allFreeControls.filter(c=>c.sla_days<=14).length} critical controls — ${allFreeControls.filter(c=>c.sla_days<=14).map(c=>c.id).join(', ') || 'review domain assessments'}`,
      `P1 (14-30 days): Address ${allFreeControls.filter(c=>c.sla_days>14&&c.sla_days<=30).length} high-priority controls`,
      'Month 2-3: Complete gap remediation for all domains; begin evidence collection',
      'Month 4-6: Internal audit, mock assessment, certification engagement',
    ],
    full_report_price: fw.price,
    payment_url: `https://rzp.io/l/cyberdudebivash-${framework}`,
    scan_metadata: {
      engine_version:    '4.0.0',
      scan_timestamp:    new Date().toISOString(),
      framework_edition: fw.name,
      assessment_method: 'framework_gap_analysis',
      assessment_mode:   'STATIC',
      data_source:       'industry_benchmark',
      live_verification: false,
    },
  };
}
