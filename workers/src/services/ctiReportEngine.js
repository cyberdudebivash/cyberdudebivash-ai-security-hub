/**
 * CYBERDUDEBIVASH AI Security Hub — CTI Report Engine v1.0
 * Services:
 *   CDB-CTI-PRO-001 (₹999)  — Premium CTI Intelligence Brief (instant)
 *   CDB-TIR-001     (₹4,999) — Threat Intelligence Report (comprehensive)
 */

// ── CISA KEV (Known Exploited Vulnerabilities) ──────────────────────────────
async function fetchCISAKEV(limit = 20) {
  try {
    const r = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(10000) }
    );
    if (!r.ok) return [];
    const data = await r.json();
    const vulns = (data.vulnerabilities || [])
      .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
      .slice(0, limit);
    return vulns.map(v => ({
      cve_id:         v.cveID,
      vendor:         v.vendorProject,
      product:        v.product,
      vulnerability:  v.vulnerabilityName,
      date_added:     v.dateAdded,
      due_date:       v.dueDate,
      required_action: v.requiredAction,
      notes:          v.notes,
      known_ransomware: v.knownRansomwareCampaignUse === 'Known',
    }));
  } catch {
    return [];
  }
}

// ── NVD CVE Search (NIST) ────────────────────────────────────────────────────
async function fetchNVDCVEs(keyword, limit = 10) {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${limit}`;
    const r = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'CyberdudeBivash-SecurityHub/1.0' },
    });
    if (!r.ok) return [];
    const data = await r.json();
    return (data.vulnerabilities || []).map(v => ({
      cve_id:       v.cve?.id,
      description:  v.cve?.descriptions?.find(d => d.lang === 'en')?.value?.substring(0, 200),
      severity:     v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
                    v.cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
      cvss_score:   v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                    v.cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || null,
      published:    v.cve?.published,
      modified:     v.cve?.lastModified,
    }));
  } catch {
    return [];
  }
}

// ── Pull threat actor data from D1 ───────────────────────────────────────────
async function getTopThreatActors(db, limit = 5) {
  if (!db) return getBuiltinActors(limit);
  try {
    const rows = await db.prepare(
      `SELECT actor_id, name, origin_country, motivation, threat_level, active, description
       FROM threat_actors WHERE active = 1 ORDER BY threat_level DESC, name ASC LIMIT ?`
    ).bind(limit).all();
    if (!rows.results || rows.results.length === 0) return getBuiltinActors(limit);
    return rows.results;
  } catch {
    return getBuiltinActors(limit);
  }
}

function getBuiltinActors(limit) {
  const actors = [
    { actor_id: 'APT28', name: 'APT28 (Fancy Bear)', origin_country: 'Russia', motivation: 'Espionage', threat_level: 95, description: 'Russian GRU-linked group targeting government, military, political organizations worldwide' },
    { actor_id: 'LAZARUS', name: 'Lazarus Group', origin_country: 'North Korea', motivation: 'Financial/Espionage', threat_level: 92, description: 'DPRK state-sponsored group targeting financial institutions and cryptocurrency exchanges' },
    { actor_id: 'VOLT_TYPHOON', name: 'Volt Typhoon', origin_country: 'China', motivation: 'Critical Infrastructure', threat_level: 97, description: 'Chinese APT targeting US critical infrastructure for pre-positioning' },
    { actor_id: 'SCATTERED_SPIDER', name: 'Scattered Spider', origin_country: 'US/UK', motivation: 'Financial', threat_level: 85, description: 'Sophisticated social engineering and SIM-swapping group targeting enterprises' },
    { actor_id: 'SALT_TYPHOON', name: 'Salt Typhoon', origin_country: 'China', motivation: 'Espionage', threat_level: 96, description: 'Chinese APT compromising telecommunications infrastructure globally' },
  ];
  return actors.slice(0, limit);
}

// ── Pull recent threat intel from D1 ─────────────────────────────────────────
async function getRecentIOCs(db, limit = 20) {
  if (!db) return [];
  try {
    const rows = await db.prepare(
      `SELECT ioc_value, ioc_type, verdict, risk_score, sources_hit, enriched_at
       FROM ioc_enrichment_cache
       WHERE verdict IN ('malicious','suspicious')
       ORDER BY enriched_at DESC LIMIT ?`
    ).bind(limit).all();
    return rows.results || [];
  } catch {
    return [];
  }
}

// ── Industry threat context ───────────────────────────────────────────────────
function getIndustryContext(industry) {
  const contexts = {
    'Finance': {
      top_threats: ['Business Email Compromise (BEC)', 'Credential Stuffing', 'Swift/Banking Trojans', 'Ransomware targeting financial data'],
      key_actors:  ['Lazarus Group', 'FIN7', 'Carbanak', 'SCATTERED SPIDER'],
      regulatory_concerns: ['PCI DSS v4.0', 'GLBA', 'SOX compliance'],
      attack_vectors: ['Phishing targeting treasury staff', 'API abuse in banking apps', 'Third-party vendor compromise'],
    },
    'Healthcare': {
      top_threats: ['Ransomware targeting medical records', 'PHI data theft', 'Medical device compromise', 'Supply chain attacks'],
      key_actors:  ['Clop', 'BlackCat/ALPHV', 'Rhysida', 'LockBit'],
      regulatory_concerns: ['HIPAA enforcement', 'FDA medical device security', 'HITECH Act'],
      attack_vectors: ['Unpatched medical devices', 'Phishing targeting clinical staff', 'Remote access exploitation'],
    },
    'Technology': {
      top_threats: ['Supply chain attacks', 'Intellectual property theft', 'Cloud misconfiguration', 'Zero-day exploitation'],
      key_actors:  ['APT41', 'Volt Typhoon', 'APT29', 'LAPSUS$'],
      regulatory_concerns: ['GDPR', 'CCPA', 'SEC Cybersecurity Disclosure'],
      attack_vectors: ['Developer credential theft', 'Open source package compromise', 'CI/CD pipeline attacks'],
    },
    'Government': {
      top_threats: ['Nation-state espionage', 'Critical infrastructure attacks', 'Insider threats', 'Election interference'],
      key_actors:  ['APT28', 'APT29', 'Salt Typhoon', 'Charming Kitten'],
      regulatory_concerns: ['FISMA', 'CMMC 2.0', 'Zero Trust mandate (EO 14028)'],
      attack_vectors: ['Spear-phishing', 'VPN/remote access exploitation', 'Contractor compromise'],
    },
    'General': {
      top_threats: ['Ransomware', 'Phishing', 'BEC', 'Supply chain compromise', 'Credential theft'],
      key_actors:  ['LockBit', 'BlackCat/ALPHV', 'Scattered Spider', 'Rhysida'],
      regulatory_concerns: ['ISO 27001:2022', 'NIST CSF 2.0', 'GDPR'],
      attack_vectors: ['Spear-phishing emails', 'Exposed remote services', 'Unpatched vulnerabilities'],
    },
  };
  return contexts[industry] || contexts['General'];
}

// ─────────────────────────────────────────────────────────────────────────────
// CDB-CTI-PRO-001: Premium CTI Intelligence Brief (instant, ₹999)
// ─────────────────────────────────────────────────────────────────────────────
export async function generateCTIBrief(env, industry = 'General', orderId = null) {
  const startedAt = new Date().toISOString();

  // Fetch data in parallel
  const [kevData, threatActors, recentIOCs] = await Promise.all([
    fetchCISAKEV(10),
    getTopThreatActors(env?.DB, 5),
    getRecentIOCs(env?.DB, 10),
  ]);

  const industryCtx = getIndustryContext(industry);
  const threatDate  = new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });

  // Overall threat level assessment
  const criticalKEV = kevData.filter(v => v.known_ransomware);
  const threatLevel = criticalKEV.length > 5 ? 'CRITICAL' : criticalKEV.length > 2 ? 'HIGH' : 'ELEVATED';

  const report = {
    meta: {
      service:      'CDB-CTI-PRO-001',
      service_name: 'Premium CTI Intelligence Brief',
      version:      '1.0',
      industry,
      generated_at: startedAt,
      report_date:  threatDate,
      valid_until:  new Date(Date.now() + 7 * 86400000).toISOString(),
      powered_by:   'CYBERDUDEBIVASH AI Security Hub™',
      classification: 'CONFIDENTIAL — For Authorized Recipients Only',
    },
    executive_summary: {
      overall_threat_level:   threatLevel,
      key_headline:           `${kevData.length} actively exploited CVEs tracked | ${criticalKEV.length} linked to ransomware campaigns`,
      industry_risk:          industryCtx.top_threats[0],
      critical_cves_count:    kevData.filter(v => v.known_ransomware).length,
      total_kev_tracked:      kevData.length,
      active_threat_actors:   threatActors.length,
      iocs_observed:          recentIOCs.length,
      day7_outlook:           `Elevated phishing activity expected. Monitor for ${industryCtx.key_actors[0]} TTPs.`,
    },
    critical_cves: kevData.map(v => ({
      cve_id:          v.cve_id,
      vendor:          v.vendor,
      product:         v.product,
      vulnerability:   v.vulnerability,
      date_added:      v.date_added,
      ransomware_link: v.known_ransomware,
      required_action: v.required_action,
      priority:        v.known_ransomware ? 'IMMEDIATE' : 'HIGH',
    })),
    threat_actors: threatActors.map(a => ({
      id:          a.actor_id,
      name:        a.name,
      origin:      a.origin_country,
      motivation:  a.motivation,
      threat_level: a.threat_level,
      description: a.description,
      relevance:   industryCtx.key_actors.some(n => a.name?.includes(n.split(' ')[0])) ? 'HIGH' : 'MEDIUM',
    })),
    industry_threat_landscape: {
      sector:          industry,
      top_threats:     industryCtx.top_threats,
      key_actors:      industryCtx.key_actors,
      attack_vectors:  industryCtx.attack_vectors,
      regulatory_watch: industryCtx.regulatory_concerns,
    },
    ioc_summary: {
      recent_iocs:    recentIOCs.slice(0, 5),
      malicious_count: recentIOCs.filter(i => i.verdict === 'malicious').length,
      suspicious_count: recentIOCs.filter(i => i.verdict === 'suspicious').length,
    },
    seven_day_outlook: {
      threat_trajectory: 'INCREASING',
      key_risks: [
        `Continued exploitation of KEV CVEs in ${industry} sector`,
        `${industryCtx.key_actors[0]} activity expected to remain elevated`,
        'AI-enhanced phishing campaigns targeting enterprise credentials',
        'Supply chain compromise attempts via third-party software updates',
      ],
      recommended_actions: [
        `Patch all CISA KEV CVEs within 72 hours`,
        `Implement MFA on all remote access points`,
        `Review and restrict external-facing services`,
        `Conduct tabletop exercise for ransomware response`,
      ],
    },
  };

  if (env?.DB && orderId) {
    await storeAssessmentResult(env.DB, orderId, 'CDB-CTI-PRO-001', industry, report, 50, 'MODERATE');
  }

  return report;
}

// ─────────────────────────────────────────────────────────────────────────────
// CDB-TIR-001: Threat Intelligence Report (comprehensive, ₹4,999)
// ─────────────────────────────────────────────────────────────────────────────
export async function generateThreatIntelReport(env, domain, industry = 'General', orderId = null) {
  const startedAt = new Date().toISOString();
  const cleanDomain = (domain || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  // Fetch comprehensive data
  const [kevData, kevCritical, threatActors, recentIOCs, domainNVD] = await Promise.all([
    fetchCISAKEV(30),
    fetchCISAKEV(50),
    getTopThreatActors(env?.DB, 10),
    getRecentIOCs(env?.DB, 30),
    cleanDomain ? fetchNVDCVEs(cleanDomain.split('.')[0], 5) : Promise.resolve([]),
  ]);

  const industryCtx  = getIndustryContext(industry);
  const ransomwareKEV = kevData.filter(v => v.known_ransomware);

  // Attack surface quick check via Shodan
  let shodanData = null;
  if (cleanDomain) {
    try {
      const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=A`;
      const doh = await fetch(dohUrl, { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
      if (doh.ok) {
        const dohJson = await doh.json();
        const ip = dohJson.Answer?.find(r => r.type === 1)?.data;
        if (ip) {
          const sd = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(5000) });
          if (sd.ok) shodanData = await sd.json();
        }
      }
    } catch {}
  }

  // Risk scoring
  let riskScore = 30; // baseline
  riskScore += Math.min(ransomwareKEV.length * 2, 20);
  riskScore += Math.min((shodanData?.vulns?.length || 0) * 10, 30);
  riskScore += Math.min((shodanData?.ports?.filter(p => [3306,5432,6379,27017,3389].includes(p)).length || 0) * 10, 20);
  riskScore = Math.min(100, riskScore);

  const report = {
    meta: {
      service:         'CDB-TIR-001',
      service_name:    'Threat Intelligence Report',
      version:         '1.0',
      domain:          cleanDomain || 'N/A',
      industry,
      generated_at:    startedAt,
      analysis_window: '30 days',
      powered_by:      'CYBERDUDEBIVASH AI Security Hub™',
      classification:  'CONFIDENTIAL — Client Use Only',
    },
    executive_summary: {
      risk_score:                riskScore,
      risk_grade:                riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW',
      total_cves_analyzed:       kevData.length,
      ransomware_linked_cves:    ransomwareKEV.length,
      threat_actors_profiled:    threatActors.length,
      domain_specific_cves:      domainNVD.length,
      exposed_services:          shodanData?.ports?.length || 0,
      known_host_vulns:          shodanData?.vulns?.length || 0,
      iocs_in_database:          recentIOCs.length,
    },
    threat_landscape: {
      industry_sector:   industry,
      top_active_threats: industryCtx.top_threats,
      key_threat_actors:  industryCtx.key_actors,
      primary_attack_vectors: industryCtx.attack_vectors,
    },
    cve_analysis: {
      actively_exploited_cves: kevData,
      ransomware_campaigns:    ransomwareKEV,
      domain_relevant_cves:    domainNVD,
      exploitation_trend:      ransomwareKEV.length > 10 ? 'INCREASING' : 'STABLE',
    },
    threat_actor_profiles: threatActors.map(a => ({
      ...a,
      industry_relevance:   industryCtx.key_actors.some(n => a.name?.includes(n.split(' ')[0])) ? 'HIGH' : 'MEDIUM',
      recommended_mitigations: [
        `Block ${a.origin_country || 'unknown'}-based TOR exit nodes and anonymization services`,
        `Monitor for ${a.actor_id} TTPs using MITRE ATT&CK framework`,
        `Implement threat-specific detection rules based on ${a.actor_id} IOCs`,
      ],
    })),
    target_exposure: {
      domain:      cleanDomain || 'N/A',
      ip:          shodanData?.ip || null,
      open_ports:  shodanData?.ports || [],
      known_vulns: shodanData?.vulns || [],
      tags:        shodanData?.tags || [],
    },
    ioc_collection: {
      total_iocs:       recentIOCs.length,
      malicious_count:  recentIOCs.filter(i => i.verdict === 'malicious').length,
      suspicious_count: recentIOCs.filter(i => i.verdict === 'suspicious').length,
      recent_samples:   recentIOCs.slice(0, 10),
    },
    attack_vector_mapping: industryCtx.attack_vectors.map((vec, i) => ({
      vector:          vec,
      likelihood:      i < 2 ? 'HIGH' : 'MEDIUM',
      mitre_technique: getMitreTechnique(vec),
      mitigation:      getMitigation(vec),
    })),
    '30_day_roadmap': [
      { week: 1, priority: 'CRITICAL', actions: ['Patch all CISA KEV CVEs', 'Audit all remote access entry points', 'Enable MFA everywhere'] },
      { week: 2, priority: 'HIGH',     actions: ['Deploy threat-specific detection rules', 'Review privileged access controls', 'Conduct phishing simulation'] },
      { week: 3, priority: 'MEDIUM',   actions: ['Implement security header improvements', 'Conduct threat hunting exercise', 'Review third-party vendor risk'] },
      { week: 4, priority: 'MEDIUM',   actions: ['Document IR playbooks for identified threats', 'Review and update SIEM detections', 'Report to leadership on posture improvement'] },
    ],
    recommendations: [
      { priority: 1, category: 'Vulnerability Management', action: `Immediately patch ${ransomwareKEV.length} ransomware-linked CVEs`, effort: 'Medium', impact: 'Critical' },
      { priority: 2, category: 'Identity Security', action: 'Enforce MFA for all privileged and remote access', effort: 'Low', impact: 'High' },
      { priority: 3, category: 'Detection', action: 'Deploy industry-specific SIEM detection rules', effort: 'Medium', impact: 'High' },
      { priority: 4, category: 'Threat Hunting', action: 'Hunt for indicators of compromise from top threat actors', effort: 'Medium', impact: 'High' },
      { priority: 5, category: 'Third-Party Risk', action: 'Audit all third-party integrations and vendors', effort: 'High', impact: 'Medium' },
    ],
  };

  if (env?.DB && orderId) {
    await storeAssessmentResult(env.DB, orderId, 'CDB-TIR-001', cleanDomain || industry, report, riskScore, report.executive_summary.risk_grade);
  }

  return report;
}

function getMitreTechnique(vector) {
  const map = {
    'Spear-phishing': 'T1566.001 — Spearphishing Attachment',
    'Phishing': 'T1566 — Phishing',
    'Supply chain': 'T1195 — Supply Chain Compromise',
    'Credential': 'T1078 — Valid Accounts',
    'Ransomware': 'T1486 — Data Encrypted for Impact',
    'API abuse': 'T1190 — Exploit Public-Facing Application',
  };
  for (const [k, v] of Object.entries(map)) {
    if (vector.toLowerCase().includes(k.toLowerCase())) return v;
  }
  return 'T1059 — Command and Scripting Interpreter';
}

function getMitigation(vector) {
  const map = {
    'Phishing': 'Deploy email security gateway with sandboxing + security awareness training',
    'Supply chain': 'Software composition analysis (SCA) + vendor security assessments',
    'Credential': 'MFA + privileged access management (PAM) + zero trust',
    'Ransomware': 'Immutable backups + EDR + network segmentation',
    'API': 'API gateway + rate limiting + OWASP API Top 10 controls',
    'Remote': 'VPN with certificate auth + privileged session management',
  };
  for (const [k, v] of Object.entries(map)) {
    if (vector.toLowerCase().includes(k.toLowerCase())) return v;
  }
  return 'Defense-in-depth with monitoring and patch management';
}

async function storeAssessmentResult(db, orderId, serviceRef, target, report, riskScore, riskGrade) {
  const assessId = crypto.randomUUID();
  try {
    await db.prepare(
      `INSERT INTO service_assessments
       (id, order_id, service_ref, target, status, risk_score, risk_grade,
        findings_count, report_json, engine_version, started_at, completed_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      assessId, orderId, serviceRef, target, 'complete',
      riskScore, riskGrade, 0,
      JSON.stringify(report), '1.0',
      report.meta.generated_at, new Date().toISOString()
    ).run();
    await db.prepare(
      `UPDATE service_orders SET order_status='delivered', updated_at=datetime('now') WHERE id=?`
    ).bind(orderId).run();
  } catch (e) {
    console.error('[CTI-Engine] DB store error:', e.message);
  }
}
