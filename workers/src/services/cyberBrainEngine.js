/**
 * CYBERDUDEBIVASH AI Security Hub — CyberBrain Engine v19.0
 * Central AI Intelligence Core: aggregates vulnerabilities, threat actors, asset telemetry,
 * predicts attack paths, generates dynamic risk scores, recommends automated remediation.
 *
 * This is the GOD-level intelligence layer that powers:
 *   - /api/scan/* (enriches scan results with AI risk scoring)
 *   - /api/vulns  (prioritizes vulnerabilities by exploitability + business impact)
 *   - /api/hunt   (recommends hunt queries based on asset profile)
 *   - /api/cyber-brain/* (direct CyberBrain API)
 *
 * Output schema:
 *   {
 *     riskScore: 0–100,
 *     riskLevel: 'CRITICAL|HIGH|MEDIUM|LOW',
 *     attackPaths: [...],
 *     exploitProbability: 0.0–1.0,
 *     threatActors: [...],
 *     recommendedActions: [...],
 *     businessImpact: {...},
 *     mitreCoverage: {...},
 *   }
 */

// ─── Risk weight table ────────────────────────────────────────────────────────
// Weights represent contribution to overall risk score
const RISK_WEIGHTS = {
  cvss_critical:     30,   // CVSS 9.0–10.0
  cvss_high:         20,   // CVSS 7.0–8.9
  cvss_medium:       10,   // CVSS 4.0–6.9
  in_kev:            25,   // CISA KEV confirmed exploited
  epss_high:         20,   // EPSS > 0.70
  epss_medium:       10,   // EPSS 0.30–0.70
  public_exploit:    15,   // PoC / exploit publicly available
  ransomware_linked: 20,   // Ransomware group leverages this
  zero_day:          35,   // No patch available
  lateral_movement:  15,   // Can facilitate lateral movement
  credential_access: 18,   // Enables credential theft
  external_exposure: 20,   // Internet-facing asset
  no_mfa:            12,   // Auth weakness
  missing_headers:    5,   // Each missing security header
  weak_tls:          12,   // TLS 1.0/1.1 or weak ciphers
  dns_weakness:       8,   // Missing SPF/DKIM/DMARC
};

// ─── MITRE ATT&CK attack patterns ────────────────────────────────────────────
const ATTACK_CHAINS = [
  {
    id: 'chain_web_rce',
    name: 'Web Exploitation → RCE → Lateral Movement',
    steps: ['Reconnaissance', 'Initial Access (Web)', 'Execution', 'Privilege Escalation', 'Lateral Movement', 'Data Exfiltration'],
    techniques: ['T1190', 'T1059', 'T1548', 'T1021', 'T1041'],
    probability_multiplier: 1.4,
    triggers: ['injection', 'rce', 'cve_critical', 'external'],
  },
  {
    id: 'chain_phishing_cred',
    name: 'Spear Phishing → Credential Theft → Persistence',
    steps: ['Reconnaissance', 'Phishing Email', 'Credential Harvest', 'Persistence', 'Internal Discovery'],
    techniques: ['T1566', 'T1078', 'T1547', 'T1057'],
    probability_multiplier: 1.2,
    triggers: ['spf', 'dmarc', 'dkim', 'mfa', 'credential'],
  },
  {
    id: 'chain_supply_chain',
    name: 'Supply Chain → Backdoor → Long-Term APT',
    steps: ['Vendor Compromise', 'Trusted Update Delivery', 'Backdoor Execution', 'Covert C2', 'Long-Term Exfiltration'],
    techniques: ['T1195', 'T1543', 'T1071', 'T1020'],
    probability_multiplier: 0.8,
    triggers: ['supply_chain', 'third_party', 'dependency'],
  },
  {
    id: 'chain_ransomware',
    name: 'Initial Access → Ransomware Deployment',
    steps: ['Initial Access', 'Execution', 'Defense Evasion', 'Data Staging', 'Encryption + Extortion'],
    techniques: ['T1190', 'T1059', 'T1027', 'T1486', 'T1490'],
    probability_multiplier: 1.3,
    triggers: ['ransomware', 'kev', 'public_exploit'],
  },
  {
    id: 'chain_insider',
    name: 'Insider Threat → Privilege Abuse → Exfiltration',
    steps: ['Privileged Access', 'Lateral Discovery', 'Data Collection', 'Exfiltration'],
    techniques: ['T1078', 'T1087', 'T1005', 'T1048'],
    probability_multiplier: 0.6,
    triggers: ['privilege', 'admin', 'access_control'],
  },
];

// ─── Threat actor correlation table ──────────────────────────────────────────
const THREAT_ACTORS_DB = [
  { id: 'apt41',    name: 'APT41 (Winnti)',     nation: 'CN', motivation: 'Espionage+Financial', sectors: ['tech','healthcare','finance'],    ttps: ['T1190','T1059','T1027'], risk_elevation: 1.3 },
  { id: 'apt28',    name: 'APT28 (Fancy Bear)', nation: 'RU', motivation: 'Espionage',           sectors: ['gov','defense','energy'],         ttps: ['T1566','T1078','T1547'], risk_elevation: 1.2 },
  { id: 'apt29',    name: 'APT29 (Cozy Bear)',  nation: 'RU', motivation: 'Espionage',           sectors: ['gov','tech','finance'],           ttps: ['T1195','T1071','T1020'], risk_elevation: 1.4 },
  { id: 'lazarus',  name: 'Lazarus Group',      nation: 'KP', motivation: 'Financial',           sectors: ['finance','crypto','defense'],     ttps: ['T1190','T1548','T1041'], risk_elevation: 1.5 },
  { id: 'lockbit',  name: 'LockBit 3.0',        nation: 'RU', motivation: 'Ransomware-as-a-Service', sectors: ['healthcare','manufacturing'], ttps: ['T1486','T1490','T1059'], risk_elevation: 1.6 },
  { id: 'clop',     name: 'CL0P',               nation: 'RU', motivation: 'Ransomware+Extortion',sectors: ['healthcare','education'],         ttps: ['T1190','T1486','T1048'], risk_elevation: 1.5 },
  { id: 'fin7',     name: 'FIN7',               nation: 'RU', motivation: 'Financial',           sectors: ['retail','hospitality','finance'], ttps: ['T1566','T1078','T1005'], risk_elevation: 1.2 },
  { id: 'blackcat', name: 'ALPHV/BlackCat',     nation: 'RU', motivation: 'RaaS',               sectors: ['healthcare','energy'],            ttps: ['T1486','T1190','T1027'], risk_elevation: 1.4 },
];

// ─── Remediation action templates ────────────────────────────────────────────
const REMEDIATION_TEMPLATES = {
  tls:        { priority: 'HIGH',     action: 'Disable TLS 1.0/1.1. Enforce TLS 1.3 minimum. Rotate certificates.', effort: '2h', impact: 'Eliminates protocol downgrade attacks' },
  dns:        { priority: 'HIGH',     action: 'Enable DNSSEC. Configure SPF/DKIM/DMARC records.', effort: '4h', impact: 'Prevents DNS hijacking and email spoofing' },
  headers:    { priority: 'MEDIUM',   action: 'Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers.', effort: '1h', impact: 'Mitigates XSS, clickjacking, MIME sniffing' },
  mfa:        { priority: 'CRITICAL', action: 'Enable MFA for all accounts. Enforce FIDO2/WebAuthn for admins.', effort: '8h', impact: 'Blocks 99.9% of credential-based attacks' },
  patch:      { priority: 'CRITICAL', action: 'Apply vendor patches within SLA. Prioritize KEV vulnerabilities.', effort: 'varies', impact: 'Eliminates known exploitable vulnerabilities' },
  network:    { priority: 'HIGH',     action: 'Segment network. Restrict lateral movement paths. Deploy micro-segmentation.', effort: '16h', impact: 'Contains blast radius of breaches' },
  logging:    { priority: 'MEDIUM',   action: 'Enable centralized logging. Deploy SIEM with detection rules.', effort: '8h', impact: 'Enables threat detection and forensics' },
  access:     { priority: 'HIGH',     action: 'Implement least-privilege. Review admin accounts. Rotate credentials.', effort: '4h', impact: 'Reduces attack surface from insider threats' },
  backup:     { priority: 'HIGH',     action: 'Implement 3-2-1 backup strategy. Test restoration. Air-gap critical backups.', effort: '8h', impact: 'Enables recovery from ransomware' },
  edr:        { priority: 'CRITICAL', action: 'Deploy EDR on all endpoints. Enable behavioral detection.', effort: '24h', impact: 'Detects and blocks malware execution in real-time' },
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
    if (/inject|rce|exec/i.test(text))           triggers.add('injection');
    if (/spf|dkim|dmarc/i.test(text))            triggers.add('spf'); triggers.add('dmarc'); triggers.add('dkim');
    if (/mfa|multi.?factor/i.test(text))         triggers.add('mfa');
    if (/cred|password|credential/i.test(text))  triggers.add('credential');
    if (/privilege|admin|root/i.test(text))      triggers.add('privilege');
    if (/external|internet|public/i.test(text))  triggers.add('external');
    if (/ransomware/i.test(text))                triggers.add('ransomware');
    if (/kev|exploit/i.test(text))               triggers.add('kev'); triggers.add('public_exploit');
    if (/supply|third.?party|vendor/i.test(text))triggers.add('supply_chain');
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
    active_campaigns: Math.floor(Math.random() * 10 + 1), // simulated active campaigns
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

  const financialRisk = riskScore >= 80 ? 'HIGH ($1M+)' :
                        riskScore >= 60 ? 'MEDIUM ($100K–$1M)' :
                        riskScore >= 40 ? 'LOW ($10K–$100K)' : 'MINIMAL (<$10K)';

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

  // Try Workers AI for narrative if available
  let aiNarrative = null;
  if (env?.AI && findings.length > 0 && tier !== 'FREE') {
    try {
      const prompt = `You are a senior cybersecurity analyst. Given these findings for ${target}:
${findings.slice(0,5).map(f => `- ${f.title}: ${f.description || ''}`).join('\n')}
Risk score: ${riskScore}/100 (${riskLevel})

Write a 2-paragraph executive briefing: (1) current threat posture, (2) top 3 immediate actions.
Be specific, actionable, authoritative. No fluff.`;

      const aiResp = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 300,
      });
      aiNarrative = aiResp?.response || null;
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
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
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
  catch { return Response.json({ error: 'Invalid JSON body' }, { status: 400 }); }

  const {
    target  = '',
    module  = 'domain',
    sector  = 'technology',
    findings = [],
    vulns    = [],
    assets   = {},
  } = body;

  if (!Array.isArray(findings)) {
    return Response.json({ error: 'findings must be an array' }, { status: 400 });
  }

  const result = await runCyberBrainAnalysis(env, {
    findings, vulns, assets, sector, tier: authCtx.tier || 'FREE', target, module,
  });

  return Response.json(result);
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
      try { return Response.json({ ...JSON.parse(cached), cached: true }); } catch {}
    }
  }

  return Response.json({
    target, module,
    riskScore: 0,
    riskLevel: 'UNKNOWN',
    message: 'No analysis found for this target. Run a scan first.',
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
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

  return Response.json({
    risk_score:   riskScore,
    attack_paths: paths,
    chain_count:  paths.length,
    highest_probability: paths[0]?.probability || 0,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── Handler: GET /api/cyber-brain/threat-actors ──────────────────────────────
export async function handleThreatActors(request, env, authCtx) {
  const url    = new URL(request.url);
  const sector = url.searchParams.get('sector') || 'technology';
  const actors = correlateThretActors([], sector);
  return Response.json({
    sector,
    threat_actors: actors,
    total: actors.length,
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}

// ─── Handler: GET /api/cyber-brain/remediation ────────────────────────────────
export async function handleRemediationPlan(request, env, authCtx) {
  const url    = new URL(request.url);
  const score  = parseInt(url.searchParams.get('risk_score') || '50', 10);
  const tier   = authCtx.tier || 'FREE';
  const actions = generateRemediation([], score, tier);
  return Response.json({
    risk_score: score,
    tier,
    actions,
    total_actions: actions.length,
    estimated_total_effort: actions.reduce((sum, a) => {
      const h = parseInt(a.effort) || 0;
      return sum + h;
    }, 0) + 'h',
    platform: 'CYBERDUDEBIVASH AI Security Hub v19.0',
  });
}
