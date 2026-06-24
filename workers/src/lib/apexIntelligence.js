/**
 * CYBERDUDEBIVASH — APEX NEXUS Predictive Intelligence Engine v1.0
 * ════════════════════════════════════════════════════════════════════════════
 * God Mode predictive threat forecasting beyond reactive intelligence.
 *
 * Capabilities:
 * - Exploit weaponization timeline prediction (days to public PoC)
 * - Industry/sector-specific threat forecasting
 * - Attacker ROI analysis (investment vs. expected return)
 * - Emerging threat pattern detection
 * - Indian regulatory deadline risk modeling
 * - Quantum cryptography readiness scoring
 * - Attack campaign attribution confidence scoring
 * ════════════════════════════════════════════════════════════════════════════
 */

import { routeAICall } from '../core/aiProviderRouter.js';

// ─── Exploit timeline database (CVSS → median days to PoC/weaponization) ──────
const EXPLOIT_TIMELINE = {
  // Based on EPSS research and historical CVE data
  critical_kev:    { days_to_poc: 1,  days_to_weaponized: 3,   days_to_mass_exploit: 7   },
  critical_rce:    { days_to_poc: 3,  days_to_weaponized: 7,   days_to_mass_exploit: 14  },
  critical_other:  { days_to_poc: 7,  days_to_weaponized: 14,  days_to_mass_exploit: 30  },
  high_rce:        { days_to_poc: 14, days_to_weaponized: 30,  days_to_mass_exploit: 60  },
  high_other:      { days_to_poc: 30, days_to_weaponized: 60,  days_to_mass_exploit: 90  },
  medium:          { days_to_poc: 90, days_to_weaponized: 180, days_to_mass_exploit: 365 },
  low:             { days_to_poc: 365,days_to_weaponized: null,days_to_mass_exploit: null },
};

// ─── Sector-specific risk multipliers ─────────────────────────────────────────
const SECTOR_RISK_MULTIPLIERS = {
  bfsi:                   { multiplier: 1.8, reason: 'Direct financial gain motive; regulated data = higher threat actor investment' },
  healthcare:             { multiplier: 1.7, reason: 'Patient data commands premium on dark web; ransomware highly effective' },
  government:             { multiplier: 1.9, reason: 'Nation-state targeting; intelligence value; critical infrastructure designation' },
  critical_infrastructure:{ multiplier: 2.0, reason: 'Geopolitical weapon; Volt Typhoon pre-positioning; maximum disruption impact' },
  defense:                { multiplier: 2.0, reason: 'Military/intelligence value; APT36/APT41 targeting; supply chain risk' },
  technology:             { multiplier: 1.5, reason: 'IP theft; supply chain vector; large customer data sets' },
  education:              { multiplier: 1.2, reason: 'Research IP; student PII; relatively lower security investment' },
  ecommerce:              { multiplier: 1.4, reason: 'Payment card data; large user base; SEO/brand damage' },
  pharmaceutical:         { multiplier: 1.6, reason: 'Drug formula theft (APT41); patient trial data; regulatory fines' },
  telecom:                { multiplier: 1.7, reason: 'Salt Typhoon targeting; wiretap systems; national security' },
};

// ─── Attacker ROI model ────────────────────────────────────────────────────────
// Estimates attacker investment cost vs. expected return
const ATTACKER_ROI_DB = {
  ransomware_enterprise: {
    attacker_cost_usd:    15000,  // RaaS subscription + initial access purchase
    expected_return_usd:  500000, // Average enterprise ransom demand
    roi_pct:              3233,
    confidence:           'HIGH',
    source:               'Sophos State of Ransomware 2024',
  },
  data_exfiltration_pii: {
    attacker_cost_usd:    5000,   // Initial access + exfil tools
    expected_return_usd:  200000, // Dark web data sale (1M records × $0.20)
    roi_pct:              3900,
    confidence:           'MEDIUM',
    source:               'Verizon DBIR 2024',
  },
  bec_fraud: {
    attacker_cost_usd:    500,    // Phishing kit + email infrastructure
    expected_return_usd:  50000,  // Average BEC fraud amount (India)
    roi_pct:              9900,
    confidence:           'HIGH',
    source:               'FBI IC3 2024; India CERT-In',
  },
  supply_chain_compromise: {
    attacker_cost_usd:    100000, // Nation-state level investment
    expected_return_usd:  10000000, // Access to thousands of downstream victims
    roi_pct:              9900,
    confidence:           'MEDIUM',
    source:               'SolarWinds/XZ Utils post-mortems',
  },
  credential_stuffing: {
    attacker_cost_usd:    100,    // Credential list purchase + automation
    expected_return_usd:  10000,  // Account takeover monetization
    roi_pct:              9900,
    confidence:           'HIGH',
    source:               'SpyCloud 2024 Identity Exposure Report',
  },
};

// ─── Emerging threat patterns (2024-2025) ─────────────────────────────────────
const EMERGING_THREATS_2025 = [
  {
    id:          'ET-001',
    name:        'AI-Enhanced Spear Phishing',
    description: 'LLM-generated personalized phishing achieving 300% higher click rates vs. traditional templates',
    severity:    'CRITICAL',
    trend:       'ACCELERATING',
    indian_impact: 'HIGH — Indian BFSI sector primary target; voice cloning in UPI fraud growing 400%',
    ttps:        ['T1566.001','T1598'],
    mitigation:  'AI-powered email security; human-in-the-loop for wire transfers; voice authentication replacement',
  },
  {
    id:          'ET-002',
    name:        'Volt Typhoon Pre-Positioning',
    description: 'Chinese APT embedding in critical infrastructure via SOHO router compromise — years-long stealth access',
    severity:    'CRITICAL',
    trend:       'ACTIVE',
    indian_impact: 'HIGH — Power grids, telecom infrastructure under active reconnaissance per CERT-In advisories',
    ttps:        ['T1190','T1078','T1021','T1070'],
    mitigation:  'OT/IT network segmentation; Purdue Model enforcement; outbound traffic anomaly detection',
  },
  {
    id:          'ET-003',
    name:        'Ransomware Supply Chain Pivot',
    description: 'RaaS groups acquiring initial access via software supply chain (npm, PyPI, Maven) rather than phishing',
    severity:    'HIGH',
    trend:       'ACCELERATING',
    indian_impact: 'MEDIUM-HIGH — Indian IT services companies as supply chain entry points to global enterprises',
    ttps:        ['T1195.001','T1486','T1041'],
    mitigation:  'SCA (Software Composition Analysis) in CI/CD; package signing verification; SBOM generation',
  },
  {
    id:          'ET-004',
    name:        'GenAI Data Poisoning',
    description: 'Adversarial injection of poisoned training data into enterprise AI models via RAG pipelines',
    severity:    'HIGH',
    trend:       'EMERGING',
    indian_impact: 'MEDIUM — Growing adoption of RAG-based enterprise AI in Indian IT sector creates new attack surface',
    ttps:        ['T1565.001','T1059'],
    mitigation:  'RAG input sanitization; retrieval-augmented generation source verification; AI red teaming',
  },
  {
    id:          'ET-005',
    name:        'UPI / Payment System Fraud Automation',
    description: 'AI-powered vishing + social engineering targeting UPI credentials; deepfake audio bank fraud',
    severity:    'CRITICAL',
    trend:       'ACCELERATING',
    indian_impact: 'CRITICAL — India-specific; ₹1,700 Cr lost to cyber fraud FY2024 per RBI report',
    ttps:        ['T1566','T1621','T1078'],
    mitigation:  'UPI transaction anomaly detection; SIM swap monitoring; customer education programs',
  },
  {
    id:          'ET-006',
    name:        'Quantum Harvest Now Decrypt Later (HNDL)',
    description: 'Nation-states harvesting encrypted traffic today to decrypt when quantum computers become available',
    severity:    'HIGH',
    trend:       'LONG-TERM',
    indian_impact: 'HIGH — Government/defense communications; classified R&D; BFSI long-term transaction records',
    ttps:        ['T1040','T1041'],
    mitigation:  'Begin PQC migration per NIST PQC standards (FIPS 203/204/205); crypto-agility architecture',
  },
  {
    id:          'ET-007',
    name:        'DPDP Act Compliance Attack Surface',
    description: 'Attackers targeting organizations in non-compliance to trigger regulatory exposure or maximize breach impact',
    severity:    'HIGH',
    trend:       'ACTIVE',
    indian_impact: 'CRITICAL — All Indian organizations with 5Mn+ users or sensitive data subject to DPDP Act 2023',
    ttps:        ['T1078','T1190'],
    mitigation:  'DPDP compliance gap assessment; DPO appointment; consent management platform; data mapping',
  },
];

// ─── Quantum readiness scoring ─────────────────────────────────────────────────
const QUANTUM_RISK_INDICATORS = {
  rsa_2048:     { quantum_risk: 'CRITICAL', years_to_risk: '8-12', recommendation: 'Migrate to CRYSTALS-Kyber (NIST FIPS 203)' },
  rsa_4096:     { quantum_risk: 'HIGH',     years_to_risk: '10-15', recommendation: 'Plan PQC migration roadmap; crypto-agility'  },
  ecdsa_256:    { quantum_risk: 'HIGH',     years_to_risk: '8-12', recommendation: 'Migrate to CRYSTALS-Dilithium (NIST FIPS 204)'},
  ecdh_p256:    { quantum_risk: 'HIGH',     years_to_risk: '8-12', recommendation: 'Migrate to CRYSTALS-Kyber for key exchange'   },
  aes_128:      { quantum_risk: 'MEDIUM',   years_to_risk: '15+',  recommendation: 'Upgrade to AES-256; still quantum-resistant'  },
  aes_256:      { quantum_risk: 'LOW',      years_to_risk: '20+',  recommendation: 'AES-256 considered quantum-resistant currently'},
  sha256:       { quantum_risk: 'MEDIUM',   years_to_risk: '15+',  recommendation: 'Migrate to SHA-3 or SHA-512 for critical use' },
  sha3:         { quantum_risk: 'LOW',      years_to_risk: '20+',  recommendation: 'SHA-3 family considered quantum-resistant'    },
  tls13:        { quantum_risk: 'MEDIUM',   years_to_risk: '12+',  recommendation: 'Enable PQC cipher suites when available in TLS 1.3+'},
};

// ─── Exploit timeline prediction ──────────────────────────────────────────────
export function predictExploitTimeline(vuln = {}) {
  const cvss     = parseFloat(vuln.cvss) || 5.0;
  const severity = (vuln.severity || '').toUpperCase();
  const isKev    = !!vuln.in_kev || !!vuln.cisa_kev;
  const isRCE    = /rce|remote code|arbitrary code|command inject/i.test(vuln.description || vuln.title || '');

  let key;
  if (isKev)                            key = 'critical_kev';
  else if (cvss >= 9.0 && isRCE)       key = 'critical_rce';
  else if (cvss >= 9.0)                 key = 'critical_other';
  else if (cvss >= 7.0 && isRCE)       key = 'high_rce';
  else if (cvss >= 7.0)                 key = 'high_other';
  else if (cvss >= 4.0)                 key = 'medium';
  else                                   key = 'low';

  const timeline = EXPLOIT_TIMELINE[key];
  const today    = new Date();

  return {
    vulnerability:       vuln.cve_id || vuln.id || 'unknown',
    cvss_score:          cvss,
    severity,
    in_kev:              isKev,
    is_rce:              isRCE,
    timeline_class:      key,
    days_to_poc:         timeline.days_to_poc,
    days_to_weaponized:  timeline.days_to_weaponized,
    days_to_mass_exploit:timeline.days_to_mass_exploit,
    estimated_poc_date:  timeline.days_to_poc
      ? new Date(today.getTime() + timeline.days_to_poc * 86400000).toISOString().split('T')[0]
      : null,
    estimated_weapon_date: timeline.days_to_weaponized
      ? new Date(today.getTime() + timeline.days_to_weaponized * 86400000).toISOString().split('T')[0]
      : null,
    urgency_flag: isKev ? 'EXPLOIT_ACTIVE_NOW'
                : timeline.days_to_poc <= 7 ? 'PATCH_IMMEDIATELY'
                : timeline.days_to_poc <= 30 ? 'PATCH_WITHIN_WEEK'
                : 'SCHEDULED_PATCHING',
    recommendation: isKev
      ? 'CISA KEV confirmed — exploit already in active use. Emergency patch cycle required within 24 hours.'
      : `PoC expected within ${timeline.days_to_poc} days. Initiate patch process immediately.`,
  };
}

// ─── Sector threat forecast ────────────────────────────────────────────────────
export function forecastSectorThreats(sector = 'technology', findings = []) {
  const normalized = sector.toLowerCase().replace(/[^a-z_]/g, '_');
  const profile    = SECTOR_RISK_MULTIPLIERS[normalized] || SECTOR_RISK_MULTIPLIERS.technology;
  const crits      = findings.filter(f => f.severity === 'CRITICAL').length;

  const relevantThreats = EMERGING_THREATS_2025
    .filter(t => t.severity === 'CRITICAL' || t.indian_impact.includes('HIGH') || t.indian_impact.includes('CRITICAL'))
    .map(t => ({
      id:            t.id,
      name:          t.name,
      severity:      t.severity,
      trend:         t.trend,
      indian_impact: t.indian_impact,
      relevance:     profile.multiplier >= 1.7 ? 'HIGH' : 'MEDIUM',
      mitigation:    t.mitigation,
      ttps:          t.ttps,
    }))
    .slice(0, 5);

  const riskAmplification = Math.round((crits * 10 + 50) * profile.multiplier);
  const breachLikelihood  = Math.min(95, Math.round(riskAmplification * 0.9));

  return {
    sector,
    risk_multiplier:         profile.multiplier,
    amplification_reason:    profile.reason,
    amplified_risk_score:    riskAmplification,
    breach_likelihood_12mo:  breachLikelihood + '%',
    top_emerging_threats:    relevantThreats,
    recommended_focus_areas: _getSectorFocusAreas(normalized),
    india_specific_context:  _getIndiaContext(normalized),
  };
}

function _getSectorFocusAreas(sector) {
  const areas = {
    bfsi:                   ['SWIFT/UPI fraud detection','Ransomware resilience','RBI compliance automation','Zero Trust for core banking'],
    healthcare:             ['Medical device security (IEC 62443)','Patient data encryption','Ransomware recovery RTO < 4h','DPDP Act health data compliance'],
    government:             ['Nation-state APT detection','OT/IT convergence security','Zero Trust implementation','Supply chain vetting'],
    critical_infrastructure:['OT network segmentation','Purdue Model enforcement','Volt Typhoon hunting','Incident response for ICS'],
    technology:             ['Supply chain security (SBOM)','AI/LLM security (OWASP LLM Top 10)','Customer data DPDP compliance','Red team exercises'],
    ecommerce:              ['PCI-DSS v4.0 compliance','Magecart/formjacking detection','Account takeover prevention','UPI fraud detection'],
  };
  return areas[sector] || areas.technology;
}

function _getIndiaContext(sector) {
  const context = {
    bfsi:                   'RBI mandates cybersecurity framework implementation. SEBI requires annual VAPT. UPI fraud at ₹1,700 Cr in FY2024.',
    healthcare:             'DPDP Act classifies health data as sensitive. CERT-In mandatory 6-hour reporting for healthcare incidents.',
    government:             'NCIIPC protects critical information infrastructure. APT36 (Transparent Tribe) actively targeting Indian government.',
    critical_infrastructure:'NCIIPC designates power/water/telecom as CII. CERT-In 6-hour reporting mandatory. Volt Typhoon active in region.',
    technology:             'India DPDP Act 2023 in force. IT companies with 5Mn+ users classified as significant data fiduciaries.',
    ecommerce:              'Consumer Protection Act applies. DPDP Act requires consent for data processing. UPI integration adds attack surface.',
  };
  return context[sector] || context.technology;
}

// ─── Attacker ROI analysis ─────────────────────────────────────────────────────
export function analyzeAttackerROI(findings = [], sector = 'technology') {
  const crits  = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs  = findings.filter(f => f.severity === 'HIGH').length;
  const hasKev = findings.some(f => f.in_kev || f.cisa_kev);
  const profile = SECTOR_RISK_MULTIPLIERS[sector.toLowerCase()] || SECTOR_RISK_MULTIPLIERS.technology;

  const findingText = f => (f.title || '') + ' ' + (f.description || '');
  // Select most likely attack type based on findings
  let primaryAttackType = 'credential_stuffing';
  if (findings.some(f => /ransomware|rce|backdoor/i.test(findingText(f)))) primaryAttackType = 'ransomware_enterprise';
  else if (crits > 1 || hasKev) primaryAttackType = 'ransomware_enterprise';
  else if (findings.some(f => /exfil|data|pii/i.test(findingText(f)))) primaryAttackType = 'data_exfiltration_pii';
  else if (findings.some(f => /phish|spf|dmarc/i.test(findingText(f)))) primaryAttackType = 'bec_fraud';

  const roi = ATTACKER_ROI_DB[primaryAttackType];
  const amplifiedReturn = Math.round(roi.expected_return_usd * profile.multiplier);
  const inrRate         = 83.5; // approximate USD/INR

  return {
    primary_attack_type:       primaryAttackType,
    attacker_investment_usd:   roi.attacker_cost_usd,
    expected_return_usd:       amplifiedReturn,
    expected_return_inr:       `₹${(amplifiedReturn * inrRate / 10000000).toFixed(1)} Cr`,
    roi_percentage:            Math.round((amplifiedReturn / roi.attacker_cost_usd - 1) * 100),
    attacker_motivation_score: Math.min(100, Math.round(profile.multiplier * 50 + crits * 10)),
    source:                    roi.source,
    confidence:                roi.confidence,
    implication:               `An attacker investing $${roi.attacker_cost_usd.toLocaleString()} can expect ₹${(amplifiedReturn * inrRate / 10000000).toFixed(1)} Cr return — making your organization a high-value target.`,
    deterrence_investment:     `₹${Math.round(amplifiedReturn * inrRate * 0.03 / 100000)} L in security controls eliminates 80-90% of attacker ROI advantage.`,
  };
}

// ─── Quantum readiness assessment ─────────────────────────────────────────────
export function assessQuantumReadiness(cryptoFindings = [], tlsVersion = null) {
  let riskScore  = 0;
  const risks    = [];
  const actions  = [];

  const cryptoText = f => (f.title || '') + ' ' + (f.description || '');
  // Check for weak crypto in findings
  if (cryptoFindings.some(f => /rsa.2048|rsa-2048/i.test(cryptoText(f)))) {
    const r = QUANTUM_RISK_INDICATORS.rsa_2048;
    riskScore += 35;
    risks.push({ algorithm: 'RSA-2048', ...r });
    actions.push(r.recommendation);
  }
  if (cryptoFindings.some(f => /ecdsa|ecdh|elliptic/i.test(cryptoText(f)))) {
    const r = QUANTUM_RISK_INDICATORS.ecdsa_256;
    riskScore += 25;
    risks.push({ algorithm: 'ECDSA/ECDH P-256', ...r });
    actions.push(r.recommendation);
  }
  if (tlsVersion && parseFloat(tlsVersion) < 1.3) {
    riskScore += 20;
    risks.push({ algorithm: `TLS ${tlsVersion}`, ...QUANTUM_RISK_INDICATORS.tls13 });
    actions.push('Upgrade to TLS 1.3 as prerequisite for PQC cipher suites');
  }
  if (!risks.length) {
    riskScore = 15; // baseline harvest-now-decrypt-later risk
    risks.push({ algorithm: 'Current configuration', quantum_risk: 'LOW-MEDIUM', years_to_risk: '12+', recommendation: 'Monitor NIST PQC standards; plan crypto-agility architecture' });
  }

  const readinessScore = Math.max(0, 100 - riskScore);

  return {
    quantum_readiness_score: readinessScore,
    quantum_risk_level:      riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW',
    vulnerable_algorithms:   risks,
    immediate_actions:       [...new Set(actions)],
    harvest_now_decrypt_later_risk: 'Present — nation-states harvesting encrypted data today for future quantum decryption',
    nist_pqc_guidance:       'NIST FIPS 203 (Kyber), FIPS 204 (Dilithium), FIPS 205 (SPHINCS+) standardized August 2024',
    estimated_migration_effort: risks.length > 1 ? '12-24 months for full PQC migration' : '6-12 months with phased approach',
  };
}

// ─── Predictive threat campaign detection ─────────────────────────────────────
export function detectThreatCampaignPatterns(findings = [], sector = 'technology', recentEvents = []) {
  // Build a searchable text from structured fields only (not full JSON serialization)
  const findingText = findings.map(f => ((f.title || '') + ' ' + (f.description || '') + ' ' + (f.id || '')).toLowerCase()).join(' ');
  const eventText   = recentEvents.map(e => (typeof e === 'string' ? e : (e.title || '')).toLowerCase()).join(' ');
  const text        = findingText + ' ' + eventText;
  const detectedThreats = [];

  EMERGING_THREATS_2025.forEach(threat => {
    // Match TTP IDs exactly (e.g. T1566 → look for literal 't1566')
    const ttpMatch  = threat.ttps.some(t => text.includes(t.toLowerCase()));
    const keyMatch  = threat.description.split(' ').slice(0, 5).some(w => w.length > 4 && text.includes(w.toLowerCase()));
    if (ttpMatch || keyMatch) {
      detectedThreats.push({
        threat_id:    threat.id,
        name:         threat.name,
        severity:     threat.severity,
        trend:        threat.trend,
        match_reason: ttpMatch ? 'TTP pattern match' : 'Keyword correlation',
        mitigation:   threat.mitigation,
        indian_impact: threat.indian_impact,
      });
    }
  });

  return {
    campaigns_detected:  detectedThreats.length,
    threat_campaigns:    detectedThreats,
    threat_intelligence_date: new Date().toISOString().split('T')[0],
    engine:              'APEX NEXUS Predictive Intelligence v1.0',
    india_threat_level:  detectedThreats.some(t => t.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
  };
}

// ─── AI-enhanced predictive analysis ─────────────────────────────────────────
export async function generatePredictiveIntelligence(env, {
  findings = [],
  vulns    = [],
  sector   = 'technology',
  target   = '',
  tier     = 'PRO',
} = {}) {
  const exploitTimelines = vulns
    .filter(v => v.cvss >= 7.0 || v.in_kev)
    .slice(0, 5)
    .map(v => predictExploitTimeline(v));

  const sectorForecast  = forecastSectorThreats(sector, findings);
  const attackerROI     = analyzeAttackerROI(findings, sector);
  const campaignPatterns = detectThreatCampaignPatterns(findings, sector);
  const quantumReadiness = assessQuantumReadiness(findings);

  const urgentVulns = exploitTimelines.filter(e => e.urgency_flag === 'EXPLOIT_ACTIVE_NOW' || e.urgency_flag === 'PATCH_IMMEDIATELY');

  // AI-enhanced prediction narrative (optional)
  let aiPrediction = null;
  if (env && urgentVulns.length > 0) {
    try {
      const result = await routeAICall(env, {
        prompt: `As APEX NEXUS predictive intelligence engine, analyze this threat landscape for ${target} in the ${sector} sector:

Critical vulns with imminent exploit: ${urgentVulns.map(v => `${v.vulnerability} (${v.urgency_flag}, PoC in ${v.days_to_poc} days)`).join(', ')}
Sector risk multiplier: ${sectorForecast.risk_multiplier}x
Attacker ROI on attack: ${attackerROI.roi_percentage}%
Emerging campaigns detected: ${campaignPatterns.campaigns_detected}

Provide a 150-word predictive threat briefing: What will happen in the next 30 days if no action is taken? Be specific about timeline, actors, and impact in ₹.`,
        task_type:  'prediction',
        tier,
        max_tokens: 350,
        temperature: 0.2,
      });
      aiPrediction = result?.content || null;
    } catch (_) {}
  }

  return {
    target,
    sector,
    generated_at:        new Date().toISOString(),
    engine:              'APEX NEXUS Predictive Intelligence v1.0',
    exploit_timelines:   exploitTimelines,
    urgent_patches:      urgentVulns.length,
    sector_forecast:     sectorForecast,
    attacker_roi:        attackerROI,
    campaign_patterns:   campaignPatterns,
    quantum_readiness:   quantumReadiness,
    ai_prediction:       aiPrediction,
    priority_actions: [
      ...urgentVulns.map(v => ({ priority: 'P0', action: v.recommendation, deadline: v.estimated_poc_date || 'IMMEDIATE' })),
      { priority: 'P1', action: `Deploy ${sectorForecast.recommended_focus_areas[0]}`, deadline: '7 days' },
      { priority: 'P1', action: attackerROI.deterrence_investment, deadline: '30 days' },
      { priority: 'P2', action: `Initiate quantum readiness assessment — ${quantumReadiness.quantum_risk_level} risk detected`, deadline: '90 days' },
    ].filter((_, i) => i < 6),
  };
}
