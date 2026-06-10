/**
 * CYBERDUDEBIVASH AI Security Hub — AI Cyber Brain v8.0
 *
 * Generates human-readable security intelligence from scan results:
 *   - Plain-language threat narratives written at C-suite + analyst level
 *   - Real-world attack context for each finding
 *   - Prioritized, actionable remediation plans
 *   - Auto-generated blog posts and executive briefings
 *   - Dynamic MITRE ATT&CK narrative mapping
 *
 * Uses Workers AI (env.AI) when available; falls back to structured
 * template reasoning that produces senior-consultant-quality output.
 */

// ─── MITRE ATT&CK knowledge base ─────────────────────────────────────────────
const MITRE_TACTICS = {
  reconnaissance:     { id:'TA0043', name:'Reconnaissance',       icon:'🔍' },
  initial_access:     { id:'TA0001', name:'Initial Access',        icon:'🚪' },
  execution:          { id:'TA0002', name:'Execution',             icon:'⚡' },
  persistence:        { id:'TA0003', name:'Persistence',           icon:'🪝' },
  privilege_escalation:{ id:'TA0004', name:'Privilege Escalation', icon:'⬆️' },
  defense_evasion:    { id:'TA0005', name:'Defense Evasion',       icon:'🦅' },
  credential_access:  { id:'TA0006', name:'Credential Access',     icon:'🔑' },
  discovery:          { id:'TA0007', name:'Discovery',             icon:'🗺️' },
  lateral_movement:   { id:'TA0008', name:'Lateral Movement',      icon:'↔️' },
  collection:         { id:'TA0009', name:'Collection',            icon:'📦' },
  exfiltration:       { id:'TA0010', name:'Exfiltration',          icon:'📤' },
  impact:             { id:'TA0040', name:'Impact',                icon:'💥' },
  command_and_control:{ id:'TA0011', name:'C2',                    icon:'📡' },
};

// Real ATT&CK technique database — keyword → structured T-code object
const TECHNIQUE_DB = {
  'tls':            { id:'T1040',   name:'Network Sniffing',                   url:'https://attack.mitre.org/techniques/T1040/' },
  'ssl':            { id:'T1557',   name:'Adversary-in-the-Middle (AitM)',      url:'https://attack.mitre.org/techniques/T1557/' },
  'dns tunnel':     { id:'T1071.004',name:'DNS Application Layer Protocol',    url:'https://attack.mitre.org/techniques/T1071/004/' },
  'dns':            { id:'T1590.002',name:'DNS Passive Collection',             url:'https://attack.mitre.org/techniques/T1590/002/' },
  'dnssec':         { id:'T1565.002',name:'Transmitted Data Manipulation',     url:'https://attack.mitre.org/techniques/T1565/002/' },
  'spf':            { id:'T1566.002',name:'Spear Phishing via Service',        url:'https://attack.mitre.org/techniques/T1566/002/' },
  'dkim':           { id:'T1566.002',name:'Spear Phishing via Service',        url:'https://attack.mitre.org/techniques/T1566/002/' },
  'dmarc':          { id:'T1566',   name:'Phishing',                           url:'https://attack.mitre.org/techniques/T1566/' },
  'hsts':           { id:'T1557',   name:'Adversary-in-the-Middle (AitM)',      url:'https://attack.mitre.org/techniques/T1557/' },
  'header':         { id:'T1505',   name:'Server Software Component',          url:'https://attack.mitre.org/techniques/T1505/' },
  'csp':            { id:'T1059.007',name:'JavaScript / Cross-Site Scripting', url:'https://attack.mitre.org/techniques/T1059/007/' },
  'port':           { id:'T1595.001',name:'Scanning IP Blocks',                url:'https://attack.mitre.org/techniques/T1595/001/' },
  'subdomain':      { id:'T1584',   name:'Compromise Infrastructure',          url:'https://attack.mitre.org/techniques/T1584/' },
  'password spray': { id:'T1110.003',name:'Password Spraying',                 url:'https://attack.mitre.org/techniques/T1110/003/' },
  'brute force':    { id:'T1110',   name:'Brute Force',                        url:'https://attack.mitre.org/techniques/T1110/' },
  'mfa':            { id:'T1621',   name:'MFA Request Generation',             url:'https://attack.mitre.org/techniques/T1621/' },
  'phish':          { id:'T1566',   name:'Phishing',                           url:'https://attack.mitre.org/techniques/T1566/' },
  'injection':      { id:'T1190',   name:'Exploit Public-Facing Application',  url:'https://attack.mitre.org/techniques/T1190/' },
  'prompt inject':  { id:'T1059',   name:'Command and Scripting Interpreter',  url:'https://attack.mitre.org/techniques/T1059/' },
  'xss':            { id:'T1059.007',name:'JavaScript / XSS',                  url:'https://attack.mitre.org/techniques/T1059/007/' },
  'csrf':           { id:'T1185',   name:'Browser Session Hijacking',          url:'https://attack.mitre.org/techniques/T1185/' },
  'privilege':      { id:'T1548',   name:'Abuse Elevation Control Mechanism',  url:'https://attack.mitre.org/techniques/T1548/' },
  'stale':          { id:'T1078.003',name:'Local Accounts (stale)',            url:'https://attack.mitre.org/techniques/T1078/003/' },
  'lateral':        { id:'T1021',   name:'Remote Services',                    url:'https://attack.mitre.org/techniques/T1021/' },
  'ransomware':     { id:'T1486',   name:'Data Encrypted for Impact',          url:'https://attack.mitre.org/techniques/T1486/' },
  'exfil':          { id:'T1041',   name:'Exfiltration Over C2 Channel',       url:'https://attack.mitre.org/techniques/T1041/' },
  'backdoor':       { id:'T1505.003',name:'Web Shell',                         url:'https://attack.mitre.org/techniques/T1505/003/' },
  'credential':     { id:'T1552',   name:'Unsecured Credentials',              url:'https://attack.mitre.org/techniques/T1552/' },
  'token':          { id:'T1528',   name:'Steal Application Access Token',     url:'https://attack.mitre.org/techniques/T1528/' },
  'default':        { id:'T1190',   name:'Exploit Public-Facing Application',  url:'https://attack.mitre.org/techniques/T1190/' },
};

// Finding keyword → ATT&CK tactic mapping
const FINDING_TACTIC_MAP = {
  tls:                ['initial_access','defense_evasion'],
  ssl:                ['initial_access','defense_evasion'],
  dnssec:             ['initial_access','collection'],
  dns:                ['reconnaissance','command_and_control'],
  header:             ['initial_access','defense_evasion'],
  csp:                ['execution','initial_access'],
  hsts:               ['initial_access'],
  spf:                ['initial_access'],
  dkim:               ['initial_access'],
  dmarc:              ['initial_access'],
  port:               ['reconnaissance','initial_access'],
  subdomain:          ['reconnaissance'],
  exposure:           ['reconnaissance','collection'],
  credential:         ['credential_access'],
  password:           ['credential_access','persistence'],
  mfa:                ['credential_access','initial_access'],
  phishing:           ['initial_access','credential_access'],
  injection:          ['execution','initial_access'],
  prompt:             ['execution','initial_access'],
  xss:                ['execution','collection'],
  csrf:               ['execution'],
  privilege:          ['privilege_escalation'],
  admin:              ['privilege_escalation','discovery'],
  lateral:            ['lateral_movement'],
  ransomware:         ['impact','execution'],
  exfil:              ['exfiltration','collection'],
  data:               ['collection','exfiltration'],
  persistence:        ['persistence'],
  backdoor:           ['persistence','command_and_control'],
  c2:                 ['command_and_control'],
  tunnel:             ['command_and_control','exfiltration'],
  recon:              ['reconnaissance','discovery'],
  scan:               ['reconnaissance','discovery'],
  stale:              ['persistence','privilege_escalation'],
  access:             ['credential_access','initial_access'],
  gap:                ['discovery'],
  compliance:         ['discovery'],
};

// Real-world attack context per module
const ATTACK_CONTEXTS = {
  domain: {
    threat_actors: ['APT28 (Fancy Bear)', 'Lazarus Group', 'FIN7', 'Scattered Spider'],
    attack_patterns: [
      'Adversaries targeting exposed TLS weaknesses to intercept encrypted traffic via MITM attacks at ISP level.',
      'DNS hijacking campaigns leveraging missing DNSSEC to redirect users to credential-harvesting clones.',
      'Email spoofing operations exploiting absent SPF/DMARC to launch spear-phishing at scale — attributed to nation-state actors.',
      'Subdomain takeover attacks where expired DNS records are claimed by attackers to serve malicious content under your domain.',
      'Port scanning reconnaissance typically precedes targeted exploitation of exposed services within 24-72 hours of discovery.',
    ],
    business_impact: [
      'Customer data interception via MITM on insecure TLS',
      'Brand damage from domain/email spoofing campaigns',
      'Regulatory fines under DPDP Act / GDPR for data-in-transit exposure',
      'SEO damage and blacklisting from subdomain takeover abuse',
    ],
  },
  ai: {
    threat_actors: ['State-sponsored AI red teams', 'Automated LLM exploit kits', 'Insider threat actors'],
    attack_patterns: [
      'Prompt injection attacks have been observed bypassing safety controls in production LLM deployments, exfiltrating system prompts and user PII.',
      'Indirect prompt injection via poisoned documents in RAG pipelines — attacker controls what the model "reads" and therefore outputs.',
      'Excessive agency exploitation: malicious users manipulating autonomous AI agents into executing unauthorized actions (file deletion, API calls, purchases).',
      'Model inversion attacks reconstructing training data to expose private information embedded during fine-tuning.',
      'Jailbreak chaining — combining multiple low-severity prompt weaknesses into a full safety-bypass kill chain.',
    ],
    business_impact: [
      'Regulatory liability for AI-generated harmful or biased outputs',
      'Intellectual property exposure via system prompt leakage',
      'Reputational damage from AI agent unauthorized actions',
      'GDPR/DPDP violations from AI-driven PII mishandling',
    ],
  },
  redteam: {
    threat_actors: ['APT29 (Cozy Bear)', 'REvil/Sodinokibi', 'Cl0p Ransomware Group', 'DarkSide'],
    attack_patterns: [
      'Password spray attacks running at 1 attempt/account/hour to evade lockout — bypassing perimeter entirely using valid credentials.',
      'Spear phishing with AI-generated lure documents targeted at finance and HR staff — achieving credential theft within hours.',
      'Living-off-the-land (LotL) techniques using built-in Windows tools to avoid EDR detection during lateral movement.',
      'DNS tunneling C2 channels that bypass egress filtering by encoding data in DNS queries — undetectable without DNS inspection.',
      'Ransomware pre-positioning: attackers maintain persistent access for 6-12 months before deploying payload at maximum impact.',
    ],
    business_impact: [
      'Average ransomware recovery cost: ₹4.2 Cr for mid-market organizations',
      'Business interruption during incident response (avg 21 days)',
      'Regulatory breach notification obligations under DPDP Act §8(7)',
      'Executive accountability and potential legal liability',
    ],
  },
  identity: {
    threat_actors: ['Okta breach actors', 'Lapsus$ group', 'Azure AD focused APTs'],
    attack_patterns: [
      'MFA fatigue attacks: flooding users with authentication push notifications until they accidentally approve.',
      'Stale account hijacking — compromising accounts that were never properly deprovisioned after employee departure.',
      'Privileged identity abuse: over-privileged service accounts used as pivot points for lateral movement.',
      'Conditional Access policy bypass via legacy authentication protocols that do not enforce MFA.',
      'Token theft via adversary-in-the-middle (AiTM) phishing frameworks capturing session cookies post-MFA.',
    ],
    business_impact: [
      'Compliance failure across SOC 2 CC6.1, ISO 27001 A.9, PCI DSS Req 8',
      'Insider threat exposure from over-privileged accounts',
      'Regulatory investigation risk from inadequate access controls under DPDP',
      'Supply chain compromise via third-party identity federation weaknesses',
    ],
  },
  compliance: {
    threat_actors: ['Regulatory auditors', 'Class-action plaintiffs', 'Supply chain attackers exploiting compliance gaps'],
    attack_patterns: [
      'Attackers specifically probe for compliance gaps because they indicate underfunded security programs.',
      'Regulatory non-compliance creates both financial exposure (fines) and reputational risk that attracts opportunistic attackers.',
      'Third-party auditors and penetration testers first check for documented policies — absence indicates immature security posture.',
      'Supply chain partners require compliance evidence before integration — gaps block revenue opportunities.',
    ],
    business_impact: [
      'GDPR fines up to 4% of annual global turnover',
      'DPDP Act penalties up to ₹250 Cr for significant data fiduciaries',
      'PCI-DSS non-compliance: $5,000-$100,000/month in processor fines + potential card acceptance loss',
      'Customer trust damage and contract loss from failed security questionnaires',
    ],
  },
};

// Severity score weights for narrative
const SEV_WEIGHTS = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Generate comprehensive AI brain insights from a scan result.
 * Optionally uses Workers AI if env.AI is bound.
 * V3: adds exploit_probability, structured T-codes, ₹ business impact.
 */
export async function generateAIInsights(scanResult, module, env = null) {
  const findings  = [...(scanResult.findings || []), ...(scanResult.locked_findings || [])];
  const score     = scanResult.risk_score || 0;
  const level     = scanResult.risk_level || 'MEDIUM';
  const target    = scanResult.target || scanResult.domain || scanResult.model_name || 'the assessed system';

  const crits  = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs  = findings.filter(f => f.severity === 'HIGH').length;
  const totalSev = findings.reduce((s, f) => s + (SEV_WEIGHTS[f.severity] || 0), 0);
  const maxSev   = Math.max(findings.length * 4, 1);

  // V3: exploit_probability — prefer enterprise intelligence enrichment, fall back to computed
  const exploit_probability =
    scanResult?.enterprise_intelligence?.exploit_probability_pct
    ?? Math.round(Math.min(98, 10 + crits * 20 + highs * 10 + (score / 3)));

  // Build structured insight object
  const insights = {
    executive_brief:    buildExecutiveBrief(scanResult, module, target, findings, score, level),
    threat_narrative:   buildThreatNarrative(findings, module, target, score, level),
    attack_scenario:    buildAttackScenario(findings, module, target),
    remediation_plan:   buildDetailedRemediationPlan(findings, module),
    mitre_mapping:      buildMitreMapping(findings, module),  // V3: now returns flat array
    risk_forecast:      buildRiskForecast(score, findings, module),
    blog_post:          generateBlogPost(scanResult, module, target, findings),
    // V3 top-level convenience fields (mirrors aiAnalysis.js format)
    exploit_probability,
    exploit_probability_label: crits > 0 ? 'CRITICAL' : highs > 0 ? 'HIGH' : score > 35 ? 'MEDIUM' : 'LOW',
    risk_summary: {
      score,
      level,
      crits,
      highs,
      total_findings: findings.length,
      exploit_probability,
    },
  };

  // Enhance with Workers AI if available (optional, graceful fallback)
  if (env?.AI && findings.length > 0) {
    try {
      insights.ai_enhanced = await enhanceWithWorkersAI(env, insights.threat_narrative, module, target);
    } catch (_) {
      // Workers AI unavailable — continue with template output
    }
  }

  return insights;
}

/**
 * Generate just the executive brief (for report headers).
 */
export function buildExecutiveBrief(scanResult, module, target, findings, score, level) {
  const ctx     = ATTACK_CONTEXTS[module] || ATTACK_CONTEXTS.domain;
  const crits   = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs   = findings.filter(f => f.severity === 'HIGH').length;
  const dateStr = new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });

  let urgency = '';
  if (crits > 0) urgency = `This assessment identified ${crits} CRITICAL finding${crits > 1 ? 's' : ''} requiring immediate remediation within 24-48 hours to prevent active exploitation. `;
  else if (highs > 0) urgency = `${highs} HIGH severity finding${highs > 1 ? 's' : ''} present significant business risk and should be addressed within 7 days. `;
  else urgency = 'No critical or high-severity findings were identified. The assessed security posture is acceptable, with medium-priority improvements recommended. ';

  const impactStr = ctx.business_impact[0];
  const actorStr  = ctx.threat_actors[0];

  return {
    date:      dateStr,
    target,
    module:    module.toUpperCase(),
    score,
    level,
    headline:  `${target} security assessment reveals ${level} risk posture (${score}/100)`,
    paragraph: `On ${dateStr}, CYBERDUDEBIVASH AI Security Hub conducted a comprehensive ${module.toUpperCase()} security assessment of ${target}. The platform identified a risk score of ${score}/100 (${level}). ${urgency}Threat actors including ${actorStr} have been observed targeting similar vulnerabilities. The primary business exposure includes ${impactStr.toLowerCase()}. This briefing summarizes key findings, attack scenarios, and a prioritized remediation roadmap.`,
    board_summary: `Risk level: ${level} (${score}/100). ${crits > 0 ? `${crits} critical issues need 24h response.` : highs > 0 ? `${highs} high-severity issues need 7-day remediation.` : 'Security posture acceptable. Continue monitoring.'} Immediate investment in recommended controls will reduce exposure by an estimated 60-80%.`,
  };
}

/**
 * Build a real-world threat narrative explaining how attackers would leverage findings.
 */
export function buildThreatNarrative(findings, module, target, score, level) {
  const ctx = ATTACK_CONTEXTS[module] || ATTACK_CONTEXTS.domain;
  if (!findings.length) {
    return `No significant vulnerabilities detected on ${target}. Threat actors performing reconnaissance would likely deprioritize this target in favor of softer ones. Continue current security posture and maintain monitoring.`;
  }

  const critFinding = findings.find(f => f.severity === 'CRITICAL');
  const highFinding = findings.find(f => f.severity === 'HIGH');
  const topFinding  = critFinding || highFinding || findings[0];
  const pattern     = ctx.attack_patterns[Math.floor(score / 25) % ctx.attack_patterns.length];
  const actor       = ctx.threat_actors[0];

  let narrative = `## Real-World Threat Scenario for ${target}\n\n`;
  narrative += `**Threat Actor Profile:** ${ctx.threat_actors.join(', ')}\n\n`;
  narrative += `A sophisticated threat actor profiling ${target} would immediately identify the most exploitable entry points. `;

  if (topFinding) {
    narrative += `The "${topFinding.title}" finding presents the highest immediate risk: ${topFinding.description || 'this vulnerability enables unauthorized access'} `;
    narrative += `This aligns with ${actor}'s known TTPs — specifically ${pattern}\n\n`;
  }

  narrative += `**Attack Kill Chain:**\n`;
  const steps = buildKillChainSteps(findings, module, target);
  steps.forEach((step, i) => { narrative += `${i + 1}. **${step.phase}**: ${step.action}\n`; });

  narrative += `\n**Estimated Time to Exploit:** ${score >= 70 ? '24-72 hours' : score >= 50 ? '1-2 weeks' : '4-8 weeks'} for a motivated attacker.\n`;
  narrative += `\n**Primary Business Impact:** ${ctx.business_impact.slice(0, 2).join('; ')}.\n`;

  return narrative;
}

/**
 * Build step-by-step kill chain from findings.
 */
function buildKillChainSteps(findings, module, target) {
  const steps = [];
  const phases = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Lateral Movement', 'Data Collection', 'Exfiltration'];

  // Map findings to kill chain phases
  const phaseFindings = {
    'Reconnaissance':        findings.filter(f => /dns|port|subdomain|recon|scan|expir/i.test(f.title)),
    'Initial Access':        findings.filter(f => /tls|ssl|phish|spf|dkim|dmarc|header|inject|auth/i.test(f.title)),
    'Execution':             findings.filter(f => /inject|xss|csrf|exec|prompt|payload/i.test(f.title)),
    'Persistence':           findings.filter(f => /persist|backdoor|stale|account|token/i.test(f.title)),
    'Privilege Escalation':  findings.filter(f => /privilege|admin|escalat|jit|role/i.test(f.title)),
    'Lateral Movement':      findings.filter(f => /lateral|pivot|spread|mfa|cred/i.test(f.title)),
    'Data Collection':       findings.filter(f => /data|collect|pii|log|record|ai|model/i.test(f.title)),
    'Exfiltration':          findings.filter(f => /exfil|tunnel|dns|covert|channel|c2/i.test(f.title)),
  };

  const moduleKillChains = {
    domain:     ['Reconnaissance', 'Initial Access', 'Execution', 'Lateral Movement'],
    ai:         ['Reconnaissance', 'Initial Access', 'Execution', 'Data Collection', 'Exfiltration'],
    redteam:    ['Reconnaissance', 'Initial Access', 'Persistence', 'Privilege Escalation', 'Lateral Movement', 'Exfiltration'],
    identity:   ['Reconnaissance', 'Initial Access', 'Privilege Escalation', 'Lateral Movement', 'Persistence'],
    compliance: ['Reconnaissance', 'Initial Access', 'Data Collection'],
  };

  const chain = moduleKillChains[module] || phases.slice(0, 4);

  chain.forEach(phase => {
    const pf = phaseFindings[phase];
    if (pf.length > 0) {
      steps.push({ phase, action: `Exploit "${pf[0].title}" — ${pf[0].description?.slice(0, 80) || 'vulnerability identified'}` });
    } else {
      const defaults = {
        'Reconnaissance':       `Passive scanning of ${target} reveals infrastructure profile`,
        'Initial Access':       `Leverage identified vulnerability to gain initial foothold`,
        'Execution':            `Execute malicious payload post-access`,
        'Persistence':          `Install persistence mechanism to maintain access`,
        'Privilege Escalation': `Escalate from low-privilege user to admin`,
        'Lateral Movement':     `Move laterally to higher-value systems`,
        'Data Collection':      `Identify and stage valuable data assets`,
        'Exfiltration':         `Exfiltrate data via covert channel`,
      };
      steps.push({ phase, action: defaults[phase] });
    }
  });

  return steps;
}

/**
 * Build a concise attack scenario with likelihood and impact ratings.
 */
export function buildAttackScenario(findings, module, target) {
  const ctx      = ATTACK_CONTEXTS[module] || ATTACK_CONTEXTS.domain;
  const crits    = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs    = findings.filter(f => f.severity === 'HIGH').length;
  const totalSev = findings.reduce((s, f) => s + (SEV_WEIGHTS[f.severity] || 0), 0);
  const maxSev   = findings.length * 4;
  const likelihood = maxSev > 0 ? Math.min(Math.round((totalSev / maxSev) * 100), 95) : 10;

  const scenarios = ctx.attack_patterns.slice(0, 3).map((pattern, i) => ({
    id:          `AS-${String(i + 1).padStart(2, '0')}`,
    title:       pattern.split(' — ')[0].split(':')[0],
    description: pattern,
    likelihood:  Math.max(likelihood - i * 15, 5),
    impact:      crits > 0 ? 'CRITICAL' : highs > 0 ? 'HIGH' : 'MEDIUM',
    threat_actor: ctx.threat_actors[i % ctx.threat_actors.length],
    business_impact: ctx.business_impact[i % ctx.business_impact.length],
  }));

  return {
    scenarios,
    overall_likelihood: likelihood,
    overall_impact:     crits > 0 ? 'CRITICAL' : highs > 0 ? 'HIGH' : 'MEDIUM',
    risk_rating:        crits > 0 ? 'UNACCEPTABLE' : highs > 0 ? 'HIGH' : 'MODERATE',
  };
}

/**
 * Build prioritized, actionable remediation plan.
 */
export function buildDetailedRemediationPlan(findings, module) {
  const sorted = [...findings].sort((a, b) =>
    (SEV_WEIGHTS[b.severity] || 0) - (SEV_WEIGHTS[a.severity] || 0)
  );

  const phases = [
    {
      id: 'P1', label: 'Phase 1 — Immediate (24-48h)', color: 'CRITICAL',
      items: sorted.filter(f => f.severity === 'CRITICAL'),
      effort: 'High', owner: 'Security Team + DevOps',
    },
    {
      id: 'P2', label: 'Phase 2 — Short-Term (7 days)', color: 'HIGH',
      items: sorted.filter(f => f.severity === 'HIGH'),
      effort: 'Medium', owner: 'Engineering Team',
    },
    {
      id: 'P3', label: 'Phase 3 — Medium-Term (30 days)', color: 'MEDIUM',
      items: sorted.filter(f => f.severity === 'MEDIUM'),
      effort: 'Low-Medium', owner: 'IT / DevSecOps',
    },
    {
      id: 'P4', label: 'Phase 4 — Planned (90 days)', color: 'LOW',
      items: sorted.filter(f => f.severity === 'LOW' || f.severity === 'INFO'),
      effort: 'Low', owner: 'Operations Team',
    },
  ];

  return phases
    .filter(p => p.items.length > 0)
    .map(p => ({
      ...p,
      items: p.items.map(f => ({
        id:              f.id || `FND-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
        title:           f.title,
        severity:        f.severity,
        action:          f.recommendation || f.description || 'Remediate according to vendor guidance',
        validation:      buildValidationStep(f),
        estimated_hours: estimateEffortHours(f),
      })),
    }));
}

function buildValidationStep(finding) {
  const t = (finding.title || '').toLowerCase();
  if (/tls|ssl/.test(t))       return 'Run: testssl.sh target.com | grep CRITICAL';
  if (/dnssec/.test(t))        return 'Run: dig target.com +dnssec and verify AD flag';
  if (/header/.test(t))        return 'Check: securityheaders.com/target.com — expect A grade';
  if (/spf|dkim|dmarc/.test(t))return 'Validate: mxtoolbox.com/emailhealth — expect all green';
  if (/mfa/.test(t))           return 'Audit: Azure AD / Okta sign-in logs — confirm 100% MFA enforcement';
  if (/port/.test(t))          return 'Re-scan with nmap: nmap -sV -p target.com — confirm port closed';
  if (/inject/.test(t))        return 'Test with OWASP ZAP or Burp Suite — confirm payload rejected';
  return 'Re-run the CYBERDUDEBIVASH scanner and verify finding resolved';
}

function estimateEffortHours(finding) {
  const sev = finding.severity;
  const t   = (finding.title || '').toLowerCase();
  if (sev === 'CRITICAL' && /config|setting|policy/.test(t)) return '1-2h';
  if (sev === 'CRITICAL') return '4-8h';
  if (sev === 'HIGH')     return '2-4h';
  if (sev === 'MEDIUM')   return '1-2h';
  return '0.5-1h';
}

/**
 * Resolve a finding title to a structured ATT&CK technique object.
 * Returns { id, name, url } from TECHNIQUE_DB.
 */
function resolveATTACKTechnique(title) {
  const t = (title || '').toLowerCase();
  for (const [keyword, tech] of Object.entries(TECHNIQUE_DB)) {
    if (t.includes(keyword)) return tech;
  }
  return TECHNIQUE_DB['default'];
}

/**
 * Dynamically map findings to MITRE ATT&CK tactics and techniques.
 * V3: Returns a flat array of technique objects with id/name/url/tactic
 * (compatible with both frontend renderV2Tab and legacy callers).
 * The full structured object is available on .detail for callers that need it.
 */
export function buildMitreMapping(findings, module) {
  const seenIds  = new Set();
  const flatList = [];
  const tacticSet = new Set();
  const detailedMappings = [];

  findings.forEach(f => {
    const titleLower = (f.title || '').toLowerCase();
    const technique  = resolveATTACKTechnique(f.title);
    const matchedTactics = new Set();

    Object.entries(FINDING_TACTIC_MAP).forEach(([keyword, tactics]) => {
      if (titleLower.includes(keyword)) tactics.forEach(t => matchedTactics.add(t));
    });
    if (!matchedTactics.size) matchedTactics.add('initial_access');

    const tacticsArr = [...matchedTactics].map(k => MITRE_TACTICS[k]).filter(Boolean);
    tacticsArr.forEach(t => tacticSet.add(t.id));

    // Deduplicate techniques in flat list by ID
    if (!seenIds.has(technique.id)) {
      seenIds.add(technique.id);
      const tactic = tacticsArr[0] || MITRE_TACTICS.initial_access;
      flatList.push({
        id:     technique.id,
        name:   technique.name,
        url:    technique.url,
        tactic: tactic?.name || 'Initial Access',
        severity: f.severity,
      });
    }

    detailedMappings.push({
      finding_id:    f.id || f.title?.slice(0, 8),
      finding_title: f.title,
      severity:      f.severity,
      technique,
      tactics:       tacticsArr,
    });
  });

  const uniqueTactics = [...tacticSet].map(id =>
    Object.values(MITRE_TACTICS).find(t => t.id === id)
  ).filter(Boolean);

  // Return flat array (frontend-compatible) with detail attached
  flatList.detail = {
    tactics_covered: uniqueTactics,
    technique_count: flatList.length,
    mappings:        detailedMappings,
    coverage_pct:    Math.round((uniqueTactics.length / Object.keys(MITRE_TACTICS).length) * 100),
    navigator_url:   'https://mitre-attack.github.io/attack-navigator/',
  };

  return flatList;
}

/** @deprecated — use resolveATTACKTechnique() for structured output */
function getTechniqueHint(title, module) {
  const tech = resolveATTACKTechnique(title);
  return `${tech.id} — ${tech.name}`;
}

/**
 * Build a risk forecast (predicted trajectory if findings not remediated).
 */
export function buildRiskForecast(score, findings, module) {
  const critCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;

  // Simulate score degradation without remediation
  const month1 = Math.min(score + critCount * 5 + highCount * 2, 100);
  const month3 = Math.min(month1 + critCount * 8 + highCount * 3, 100);
  const month6 = Math.min(month3 + critCount * 10 + highCount * 4, 100);

  // Simulate score with remediation
  const remediated1 = Math.max(score - critCount * 15 - highCount * 8, 5);
  const remediated3 = Math.max(remediated1 - findings.length * 3, 5);

  const levelMap = s => s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH' : s >= 35 ? 'MEDIUM' : 'LOW';

  return {
    current:    { score, level: levelMap(score) },
    no_action:  {
      month_1: { score: month1, level: levelMap(month1), note: 'Increased exposure from threat actor reconnaissance' },
      month_3: { score: month3, level: levelMap(month3), note: 'Active exploitation likely for unpatched CRITICAL findings' },
      month_6: { score: month6, level: levelMap(month6), note: 'High probability of breach incident' },
    },
    with_remediation: {
      month_1: { score: remediated1, level: levelMap(remediated1), note: 'Critical and high findings resolved' },
      month_3: { score: remediated3, level: levelMap(remediated3), note: 'Full remediation plan executed' },
    },
    key_insight: critCount > 0
      ? `Without remediation, this environment will reach a CRITICAL breach probability within ${critCount > 2 ? '30' : '60'} days based on known exploitation patterns.`
      : highCount > 0
        ? 'Unaddressed HIGH findings provide a viable attack path for persistent threat actors operating over a 60-90 day window.'
        : 'Current risk trajectory is manageable. Maintain monitoring cadence and address MEDIUM findings within 30 days.',
  };
}

/**
 * Auto-generate a professional blog post from scan results.
 * Suitable for LinkedIn, website, and Telegram publishing.
 */
export function generateBlogPost(scanResult, module, target, findings) {
  const score  = scanResult.risk_score || 0;
  const level  = scanResult.risk_level || 'MEDIUM';
  const date   = new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });
  const ctx    = ATTACK_CONTEXTS[module] || ATTACK_CONTEXTS.domain;
  const crits  = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs  = findings.filter(f => f.severity === 'HIGH').length;
  const topFinding = findings.find(f => f.severity === 'CRITICAL') || findings.find(f => f.severity === 'HIGH') || findings[0];

  const titleOptions = {
    domain:     `${crits > 0 ? 'CRITICAL: ' : ''}${target} Security Audit — ${crits + highs} High-Risk Findings Discovered`,
    ai:         `AI Security Assessment: ${target} Scored ${score}/100 — ${crits > 0 ? 'Critical LLM Vulnerabilities Found' : 'OWASP LLM Analysis Complete'}`,
    redteam:    `Red Team Re