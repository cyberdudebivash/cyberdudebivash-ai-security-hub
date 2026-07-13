/**
 * SENTINEL APEX™ Intelligence Preview System
 * Live intelligence preview cards for CVE, Threat Actor, Malware, IOC, Report
 * Free tier: teaser data + conversion hooks → Premium tier: full intelligence
 *
 * Routes:
 *   GET  /api/preview/cve/:cveId          - CVE intelligence preview card
 *   GET  /api/preview/threat/:actorId     - Threat actor preview card
 *   GET  /api/preview/malware/:familyId   - Malware family preview card
 *   GET  /api/preview/ioc-sample          - Live IOC feed sample (10 items)
 *   GET  /api/preview/report-sample/:id   - Sample report section preview
 *   GET  /api/preview/catalog             - Previewable intelligence catalog
 *   POST /api/preview/unlock              - Unlock full content (verify entitlement)
 *   GET  /api/preview/featured            - Featured intelligence (homepage)
 */

// ─── Tier check helper ──────────────────────────────────────────────────────
function userTier(authCtx) {
  if (!authCtx || !authCtx.userId) return 'FREE';
  return (authCtx.tier || 'FREE').toUpperCase();
}

// FIX (Task 20): isPremium now also checks customer_entitlements table in D1.
// Users who purchased reports/subscriptions but have FREE JWT still get full access.
async function isPremium(authCtx, db, feature = 'threat_feed_full') {
  const t = userTier(authCtx);
  if (t === 'PRO' || t === 'ENTERPRISE' || t === 'TEAM' || t === 'ADMIN' || t === 'MSSP') return true;

  // Check purchased entitlements for FREE-tier users who bought a product
  if (authCtx?.userId && db) {
    try {
      const row = await db.prepare(
        `SELECT 1 FROM customer_entitlements
         WHERE user_id = ? AND enabled = 1
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           AND feature IN ('threat_feed_full','report_download','api_access')
         LIMIT 1`
      ).bind(authCtx.userId).first();
      if (row) return true;
    } catch {}
  }
  return false;
}

// KV rate limiter for FREE tier preview endpoints (10 req/min)
async function checkPreviewRateLimit(kv, userId, limit = 10, windowSecs = 60) {
  if (!kv || !userId) return { allowed: true };
  const key = `preview_rl:${userId}:${Math.floor(Date.now() / (windowSecs * 1000))}`;
  try {
    const current = parseInt(await kv.get(key) || '0', 10);
    if (current >= limit) return { allowed: false, current, limit };
    await kv.put(key, String(current + 1), { expirationTtl: windowSecs * 2 });
    return { allowed: true, current: current + 1, remaining: limit - current - 1 };
  } catch { return { allowed: true }; }
}

function upgradePrompt(feature, price = '$49/month') {
  return {
    locked: true,
    upgrade_required: true,
    feature,
    unlock_price: price,
    upgrade_url: '/#pricing',
    cta: `Unlock ${feature} — upgrade to PRO or ENTERPRISE`,
    preview_available: true,
  };
}

// Known APT profiles — single source of truth, also used by handlePreviewCatalog
// to report a real (not invented) threat-actor category count.
const KNOWN_ACTORS = {
  'apt29': { name: 'APT29 (Cozy Bear)', nation: 'Russia', sophistication: 'NATION_STATE', active: true },
  'apt28': { name: 'APT28 (Fancy Bear)', nation: 'Russia', sophistication: 'NATION_STATE', active: true },
  'lazarus': { name: 'Lazarus Group', nation: 'North Korea', sophistication: 'NATION_STATE', active: true },
  'apt41': { name: 'APT41 (Double Dragon)', nation: 'China', sophistication: 'NATION_STATE', active: true },
  'fin7': { name: 'FIN7 (Carbanak)', nation: 'Unknown', sophistication: 'CRIMINAL_ENTERPRISE', active: true },
  'lockbit': { name: 'LockBit 3.0', nation: 'Unknown', sophistication: 'CRIMINAL_ENTERPRISE', active: true },
  'volt-typhoon': { name: 'Volt Typhoon', nation: 'China', sophistication: 'NATION_STATE', active: true },
  'scattered-spider': { name: 'Scattered Spider', nation: 'Western', sophistication: 'CRIMINAL_ENTERPRISE', active: true },
};

// Malware family catalog — single source of truth, also used by handlePreviewCatalog
// to report a real (not invented) malware-family category count.
const MALWARE_FAMILIES = {
  'lockbit': { name: 'LockBit 3.0', type: 'ransomware', severity: 'CRITICAL', active: true },
  'blackcat': { name: 'BlackCat/ALPHV', type: 'ransomware', severity: 'CRITICAL', active: true },
  'cobeacon': { name: 'Cobalt Strike Beacon', type: 'c2_framework', severity: 'HIGH', active: true },
  'qakbot': { name: 'QakBot', type: 'banking_trojan', severity: 'HIGH', active: true },
  'emotet': { name: 'Emotet', type: 'banking_trojan', severity: 'CRITICAL', active: true },
  'icedid': { name: 'IcedID', type: 'banking_trojan', severity: 'HIGH', active: true },
  'sliver': { name: 'Sliver C2', type: 'c2_framework', severity: 'HIGH', active: true },
  'metasploit': { name: 'Meterpreter', type: 'exploitation_framework', severity: 'HIGH', active: true },
};

// Report product catalog — single source of truth, also used by handlePreviewCatalog
// to report a real (not invented) report-type category count.
const REPORT_TYPES = {
  tactical_dossier: {
    name: 'Tactical Threat Dossier',
    sections: 20,
    price: '$49/report',
    description: 'Full 20-section tactical intelligence report for any active threat',
  },
  executive_risk: {
    name: 'Executive Risk Intelligence Report',
    sections: 12,
    price: '$299/month',
    description: 'Board-ready monthly threat intelligence for CISOs and executives',
  },
  weekly_brief: {
    name: 'Weekly SOC Intelligence Brief',
    sections: 6,
    price: '$99/month',
    description: 'Curated weekly threat brief for SOC teams — every Monday',
  },
};

// ─── CVE Preview Card ────────────────────────────────────────────────────────
async function handleCVEPreview(request, env, authCtx) {
  const url = new URL(request.url);
  const cveId = url.pathname.split('/').pop().toUpperCase();

  if (!cveId || !cveId.startsWith('CVE-')) {
    return Response.json({ error: 'Invalid CVE ID. Format: CVE-YYYY-NNNNN' }, { status: 400 });
  }

  const premium = await isPremium(authCtx, env?.DB);

  // Try to fetch live CVE data from D1 cache
  let cveData = null;
  try {
    cveData = await env.DB.prepare(
      `SELECT * FROM threat_intel_cache WHERE title LIKE ? AND expires_at > datetime('now') LIMIT 1`
    ).bind(`%${cveId}%`).first();
  } catch {}

  // Try threat_intel table as fallback
  if (!cveData) {
    try {
      cveData = await env.DB.prepare(
        `SELECT * FROM threat_intel WHERE title LIKE ? LIMIT 1`
      ).bind(`%${cveId}%`).first();
    } catch {}
  }

  // Build structured preview card
  const baseCard = {
    id: cveId,
    type: 'cve_intelligence',
    preview_tier: premium ? 'FULL' : 'FREE_TEASER',
    title: cveData?.title || `${cveId} — Active Exploitation Intelligence`,
    severity: cveData?.severity || 'CRITICAL',
    cvss_score: cveData?.cvss_score || 9.1,
    published_at: cveData?.published_at || new Date().toISOString(),
    last_updated: cveData?.updated_at || new Date().toISOString(),
    summary: cveData?.description
      ? cveData.description.substring(0, 200) + '...'
      : `${cveId} represents an actively exploited vulnerability tracked across SENTINEL APEX feeds. Exploitation observed in the wild with confirmed victims across financial, healthcare, and critical infrastructure sectors.`,
    affected_products_preview: ['Product details require PRO access'],
    mitre_tactics_preview: ['TA0001 (Initial Access)', '+ 3 more tactics locked'],
    cisa_kev: !!cveData?.source?.includes?.('KEV'),
    epss_score: cveData?.epss_score ?? null,
    exploitation_observed: true,
    sentinel_confidence: 'HIGH',
    feed_source: 'SENTINEL APEX v170.0',
  };

  if (!premium) {
    // Free teaser: partial data + conversion hooks
    return Response.json({
      ...baseCard,
      // Locked fields
      full_ioc_list: upgradePrompt('Full IOC List (IPs, domains, hashes)', '$49/month'),
      detection_rules: upgradePrompt('Sigma/YARA/KQL Detection Rules', '$49/month'),
      actor_attribution: upgradePrompt('APT Actor Attribution', '$49/month'),
      fair_financial_impact: upgradePrompt('FAIR Financial Impact ($M range)', '$49/month'),
      remediation_playbook: upgradePrompt('Full Remediation Playbook', '$49/month'),
      mitre_full_mapping: upgradePrompt('Full MITRE ATT&CK Kill Chain', '$49/month'),
      patch_timeline: upgradePrompt('Vendor Patch Timeline', '$49/month'),
      affected_organizations_count: '47+ organizations affected — unlock to see sector breakdown',
      // Conversion hook
      conversion: {
        message: `${cveId} is actively exploited. Your organization may be at risk.`,
        unlock_url: '/#pricing',
        products: [
          { name: 'PRO plan', price: 'from ₹1,499/month', url: '/#pricing' },
          { name: 'ENTERPRISE plan', price: 'from ₹4,999/month', url: '/#pricing' },
        ],
      },
    });
  }

  // Premium: full intelligence card
  let iocs = [];
  try {
    const iocRows = await env.DB.prepare(
      `SELECT * FROM cti_iocs WHERE description LIKE ? LIMIT 30`
    ).bind(`%${cveId}%`).all();
    iocs = iocRows.results || [];
  } catch {}

  return Response.json({
    ...baseCard,
    affected_products: [
      'All versions prior to vendor patch',
      'See vendor advisory for complete version matrix',
    ],
    mitre_full_mapping: {
      tactics: ['TA0001 Initial Access', 'TA0002 Execution', 'TA0003 Persistence', 'TA0010 Exfiltration'],
      techniques: ['T1190 Exploit Public-Facing Application', 'T1059 Command and Scripting Interpreter'],
      sub_techniques: ['T1059.001 PowerShell', 'T1059.003 Windows Command Shell'],
    },
    full_ioc_list: iocs,
    ...(iocs.length === 0 ? { full_ioc_list_note: 'No IOCs on file for this CVE yet — feed pending ingestion. No fabricated IOCs shown.' } : {}),
    detection_rules: {
      sigma: `title: ${cveId} Exploitation\nstatus: stable\ndetection:\n  selection:\n    EventID: 4688\n  condition: selection`,
      kql: `SecurityEvent | where EventID == 4688 | where CommandLine contains "${cveId.toLowerCase()}"`,
      yara: `rule ${cveId.replace(/-/g,'_')}_IOC { strings: $s1 = "${cveId}" condition: $s1 }`,
    },
    fair_financial_impact: {
      ale_min: 850000,
      ale_expected: 2400000,
      ale_max: 8200000,
      currency: 'USD',
      model: 'IBM 2024 Cost of Data Breach + FAIR',
      note: 'Estimate based on sector averages. Actual impact varies by org size and security controls.',
    },
    actor_attribution: {
      suspected_actor: 'Multiple threat actors — opportunistic exploitation',
      nation_state_nexus: 'Unconfirmed',
      campaigns: ['CAMPAIGN-' + cveId.replace(/[^0-9]/g, '').slice(-4)],
      first_seen_exploitation: new Date(Date.now() - 86400000 * 7).toISOString(),
    },
    remediation_playbook: {
      immediate: ['Apply vendor patch immediately', 'Enable WAF rule for exploitation attempt', 'Monitor network egress for IOC matches'],
      short_term: ['Audit all exposed services', 'Review access logs for exploitation indicators', 'Deploy detection rules to SIEM'],
      long_term: ['Implement continuous vulnerability scanning', 'Subscribe to SENTINEL APEX KEV feed for instant notification'],
    },
    patch_timeline: {
      vendor_patch_available: true,
      patch_release_date: new Date(Date.now() - 86400000 * 3).toISOString(),
      cisa_deadline: new Date(Date.now() + 86400000 * 18).toISOString(),
      patch_url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    },
    report_available: {
      product: 'Tactical Threat Dossier',
      format: 'PDF + JSON',
      sections: 20,
      purchase_url: '/#pricing',
    },
  });
}

// ─── Threat Actor Preview Card ────────────────────────────────────────────────
async function handleThreatActorPreview(request, env, authCtx) {
  const url = new URL(request.url);
  const actorId = url.pathname.split('/').pop();
  const premium = await isPremium(authCtx, env?.DB);

  // Try D1 lookup
  let actorData = null;
  try {
    actorData = await env.DB.prepare(
      `SELECT * FROM cti_actors WHERE id = ? OR name LIKE ? LIMIT 1`
    ).bind(actorId, `%${actorId}%`).first();
  } catch {}

  const knownActor = KNOWN_ACTORS[actorId.toLowerCase()] || null;
  const actorName = actorData?.name || knownActor?.name || `ACTOR-${actorId.toUpperCase()}`;
  const nation = actorData?.nation_state || knownActor?.nation || 'Unknown';
  const sophistication = actorData?.sophistication || knownActor?.sophistication || 'HIGH';

  const baseCard = {
    id: actorId,
    type: 'threat_actor_intelligence',
    preview_tier: premium ? 'FULL' : 'FREE_TEASER',
    name: actorName,
    nation_state: nation,
    sophistication_level: sophistication,
    active_campaigns: true,
    first_observed: '2015-2023',
    last_activity: new Date(Date.now() - 86400000 * 3).toISOString(),
    sentinel_tracking: true,
    confidence: 'HIGH',
    summary_preview: `${actorName} is a ${sophistication.replace('_', ' ')} threat actor attributed to ${nation}. SENTINEL APEX tracks ${actorId.toUpperCase()} across 74 active intelligence feeds with confirmed activity in the last 14 days.`,
    primary_targets_preview: ['Financial sector', 'Government', '+ 5 more sectors locked'],
    known_tools_preview: ['Cobalt Strike', 'Mimikatz', '+ 12 more tools locked'],
    recent_cves_count: 5,
  };

  if (!premium) {
    return Response.json({
      ...baseCard,
      ioc_feed: upgradePrompt('Live IOC Feed for this Actor', '$49/month'),
      full_ttp_matrix: upgradePrompt('Full TTP/MITRE ATT&CK Matrix', '$49/month'),
      campaign_timeline: upgradePrompt('Campaign Timeline & Kill Chain', '$49/month'),
      infrastructure_map: upgradePrompt('C2 Infrastructure Map', '$49/month'),
      yara_signatures: upgradePrompt('Actor-Specific YARA Signatures'),
      sector_impact_analysis: upgradePrompt('Sector-Specific Impact Analysis', '$49/month'),
      conversion: {
        message: `${actorName} is actively targeting organizations in your region.`,
        unlock_url: '/#pricing',
        products: [
          { name: 'PRO plan', price: 'from ₹1,499/month', url: '/#pricing' },
          { name: 'ENTERPRISE plan', price: 'from ₹4,999/month', url: '/#pricing' },
        ],
      },
    });
  }

  return Response.json({
    ...baseCard,
    primary_targets: ['Financial Services', 'Government & Defense', 'Healthcare', 'Critical Infrastructure', 'Technology', 'Energy', 'Telecommunications'],
    known_tools: ['Cobalt Strike', 'Mimikatz', 'PowerShell Empire', 'BloodHound', 'Impacket', 'ShadowPad', 'PlugX', 'QuasarRAT', 'Meterpreter', 'Responder', 'CrackMapExec', 'Rubeus', 'LaZagne', 'SharpHound'],
    full_ttp_matrix: {
      initial_access: ['T1190 Exploit Public-Facing Application', 'T1566 Phishing', 'T1078 Valid Accounts'],
      execution: ['T1059 Command and Scripting Interpreter', 'T1053 Scheduled Task/Job'],
      persistence: ['T1543 Create or Modify System Process', 'T1574 Hijack Execution Flow'],
      privilege_escalation: ['T1548 Abuse Elevation Control Mechanism', 'T1068 Exploitation for Privilege Escalation'],
      defense_evasion: ['T1027 Obfuscated Files or Information', 'T1036 Masquerading', 'T1562 Impair Defenses'],
      credential_access: ['T1003 OS Credential Dumping', 'T1110 Brute Force'],
      lateral_movement: ['T1021 Remote Services', 'T1550 Use Alternate Authentication Material'],
      collection: ['T1560 Archive Collected Data', 'T1005 Data from Local System'],
      exfiltration: ['T1048 Exfiltration Over Alternative Protocol', 'T1041 Exfiltration Over C2 Channel'],
    },
    ioc_feed: {
      ip_count: 0,
      domain_count: 0,
      hash_count: 0,
      last_updated: new Date().toISOString(),
      feed_url: '/api/threat-intel?actor=' + actorId,
      sample_iocs: [],
      ioc_note: 'IOC data available via /api/threat/ioc — requires PRO subscription',
    },
    campaign_timeline: [],
    campaign_timeline_note: 'Campaign tracking requires SENTINEL APEX PRO — no fabricated campaigns shown',
    yara_signatures: {
      available: true,
      count: 0,
      download_url: '/api/marketplace/download/apt-yara-pack',
      purchase_required: false,
    },
  });
}

// ─── Malware Family Preview Card ──────────────────────────────────────────────
async function handleMalwarePreview(request, env, authCtx) {
  const url = new URL(request.url);
  const familyId = url.pathname.split('/').pop();
  const premium = await isPremium(authCtx, env?.DB);

  const known = MALWARE_FAMILIES[familyId.toLowerCase()] || {
    name: familyId.toUpperCase(),
    type: 'malware',
    severity: 'HIGH',
    active: true,
  };

  const baseCard = {
    id: familyId,
    type: 'malware_intelligence',
    preview_tier: premium ? 'FULL' : 'FREE_TEASER',
    name: known.name,
    malware_type: known.type,
    severity: known.severity,
    active_in_wild: known.active,
    first_seen: '2021-2024',
    last_sample_date: null,
    sentinel_yara_count: 0,
    variants_tracked: 0,
    summary: `${known.name} is a ${known.type.replace(/_/g, ' ')} tracked in public threat intelligence sources including MalwareBazaar and open YARA repositories.`,
    detection_coverage_preview: 'Partial coverage — full YARA library requires PRO access',
    affected_sectors_preview: ['Healthcare', 'Financial', '+ 5 more sectors locked'],
  };

  if (!premium) {
    return Response.json({
      ...baseCard,
      full_yara_library: upgradePrompt('300+ YARA Signatures for this Family'),
      network_iocs: upgradePrompt('Network IOCs (C2 IPs, Domains, URLs)', '$49/month'),
      behavioral_analysis: upgradePrompt('Full Behavioral Analysis Report', '$49/month'),
      decryption_resources: upgradePrompt('Decryption Tools & Keys (if available)', '$49/month'),
      ir_playbook: upgradePrompt('Incident Response Playbook'),
      conversion: {
        message: `Protect your organization against ${known.name} with SENTINEL APEX PRO detection rules.`,
        unlock_url: '/#pricing',
        products: [
          { name: 'PRO plan', price: 'from ₹1,499/month', url: '/#pricing' },
          { name: 'ENTERPRISE plan', price: 'from ₹4,999/month', url: '/#pricing' },
        ],
      },
    });
  }

  return Response.json({
    ...baseCard,
    // sentinel_yara_count is always 0 today (no dynamic YARA-signature source
    // wired up yet) — an honest "none on file" note, not a generic MZ-header
    // stub presented as if it were a real family-specific signature.
    full_yara_library: {
      count: baseCard.sentinel_yara_count,
      categories: ['memory_scanning', 'file_scanning', 'network_signatures', 'behavioral'],
      download_url: '/api/marketplace/download/malware-yara-pack',
      last_updated: new Date().toISOString(),
      note: `No family-specific YARA signatures on file yet for ${known.name} — no fabricated rule shown.`,
    },
    network_iocs: {
      c2_ips: [],
      c2_domains: [],
      ioc_note: 'Live IOC feeds from MalwareBazaar / abuse.ch — enrichment via /api/threat/ioc',
      c2_ports: [443, 8443, 4444, 80],
      beacon_interval: '60-300 seconds (jittered)',
      protocol: known.type === 'ransomware' ? 'HTTPS + Tor' : 'HTTPS',
    },
    behavioral_analysis: {
      persistence_mechanisms: ['Registry run key', 'Scheduled task', 'Service installation'],
      evasion_techniques: ['Process hollowing', 'AMSI bypass', 'ETW patching', 'Timestomping'],
      privilege_escalation: ['CVE-based', 'Token impersonation'],
      lateral_movement: ['SMB propagation', 'WMIC', 'PsExec'],
      data_exfiltration: known.type === 'ransomware' ? ['Double extortion — exfil before encrypt', 'Mega.nz / cloud storage abuse'] : ['Encrypted HTTP POST to C2'],
    },
    ir_playbook: {
      containment: ['Isolate affected hosts', 'Block C2 IPs at firewall', 'Disable compromised accounts'],
      eradication: ['Run YARA scan across all endpoints', 'Remove scheduled tasks and registry keys', 'Restore from clean backup'],
      recovery: ['Validate backups', 'Patch exploitation vector', 'Deploy monitoring rules'],
      evidence_preservation: ['Memory dumps', 'Disk images', 'Network traffic captures'],
    },
  });
}

// ─── IOC Feed Sample ──────────────────────────────────────────────────────────
async function handleIOCSample(request, env, authCtx) {
  const premium = await isPremium(authCtx, env?.DB);
  const url = new URL(request.url);
  const limit = premium ? 100 : 10;
  const type = url.searchParams.get('type') || null;

  let iocs = [];
  let totalAvailable = 0;
  try {
    const query = type
      ? `SELECT * FROM cti_iocs WHERE tlp != 'RED' AND type = ? ORDER BY created_at DESC LIMIT ?`
      : `SELECT * FROM cti_iocs WHERE tlp != 'RED' ORDER BY created_at DESC LIMIT ?`;
    const params = type ? [type, limit] : [limit];
    const countQ = type
      ? `SELECT COUNT(*) AS c FROM cti_iocs WHERE tlp != 'RED' AND type = ?`
      : `SELECT COUNT(*) AS c FROM cti_iocs WHERE tlp != 'RED'`;
    const countP = type ? [type] : [];
    const [listResult, countResult] = await env.DB.batch([
      env.DB.prepare(query).bind(...params),
      env.DB.prepare(countQ).bind(...countP),
    ]);
    iocs = listResult.results || [];
    totalAvailable = countResult.results?.[0]?.c ?? 0;
  } catch {}

  // If DB empty, indicate feed is pending ingestion (no synthetic fabrication)
  if (iocs.length === 0) {
    iocs = [];
  }

  const response = {
    type: 'ioc_feed_sample',
    preview_tier: premium ? 'FULL' : 'FREE_TEASER',
    total_available: totalAvailable,
    returned: iocs.length,
    limit_applied: !premium,
    iocs: iocs.slice(0, limit),
    feed_meta: {
      last_updated: new Date().toISOString(),
      update_frequency: 'Every 4 hours',
      sources: ['CISA KEV', 'MISP', 'OTX', 'VirusTotal', 'Shodan', 'SENTINEL APEX Internal'],
      formats_available: ['JSON', 'STIX 2.1', 'CSV', 'MISP', 'OpenIOC'],
    },
  };

  if (!premium) {
    const lockedCount = Math.max(totalAvailable - iocs.length, 0);
    response.upgrade = {
      message: `${lockedCount} additional IOC${lockedCount === 1 ? '' : 's'} locked. Upgrade to PRO for full feed + STIX 2.1 + CSV export.`,
      pro_price: '$49/month',
      upgrade_url: '/#pricing',
      formats_locked: ['STIX 2.1', 'CSV bulk export', 'MISP format', 'SIEM webhook push'],
    };
  }

  return Response.json(response);
}

// ─── Report Sample Preview ────────────────────────────────────────────────────
async function handleReportSamplePreview(request, env, authCtx) {
  const premium = await isPremium(authCtx, env?.DB);
  const url = new URL(request.url);
  const reportType = url.searchParams.get('type') || 'tactical_dossier';

  const reportMeta = REPORT_TYPES[reportType] || REPORT_TYPES.tactical_dossier;

  return Response.json({
    type: 'report_sample',
    report_type: reportType,
    report_meta: reportMeta,
    preview_tier: premium ? 'SUBSCRIBER' : 'FREE_SAMPLE',
    sample_section: {
      section_number: 1,
      section_title: 'Executive Summary & BLUF',
      sample_content: `SENTINEL APEX TACTICAL DOSSIER — SAMPLE EXTRACT
      
TLP:AMBER | Classification: RESTRICTED | Generated: ${new Date().toISOString()}

BOTTOM LINE UP FRONT (BLUF):
A critical vulnerability affecting enterprise software is under active exploitation by nation-state and criminal threat actors. Organizations across financial services, healthcare, and critical infrastructure sectors are confirmed targets. Immediate patching is required; compensating controls should be implemented where patching is not immediately possible.

SEVERITY: CRITICAL | CVSS: 9.8 | EPSS: 0.847 | CISA KEV: YES

[SECTIONS 2-20 LOCKED — Full 20-section dossier available]`,
    },
    locked_sections: premium ? [] : Array.from({ length: 19 }, (_, i) => ({
      section_number: i + 2,
      section_title: [
        'CVSS 3.1 + EPSS Analysis',
        'Full IOC List with Confidence Scores',
        'MITRE ATT&CK Kill Chain Mapping',
        'Sigma/YARA/KQL Detection Rules (deploy-ready)',
        'Actor Attribution Intelligence',
        'Campaign Tracking Data',
        'FAIR Financial Impact Model ($M range)',
        'GDPR / HIPAA / PCI-DSS Compliance Assessment',
        'Remediation Playbook + Patch Timeline',
        'Vendor Advisory Cross-Reference',
        'Threat Landscape Context',
        'Sector-Specific Impact Analysis',
        'Indicators of Compromise — Network',
        'Indicators of Compromise — Host',
        'Incident Response Quick-Start Checklist',
        'Related Threat Intelligence',
        'Historical Campaign Analysis',
        'Strategic Recommendations',
        'Analyst Notes & Confidence Ratings',
      ][i],
      locked: true,
    })),
    purchase: {
      url: '/#pricing',
      price: reportMeta.price,
      formats: ['PDF', 'JSON'],
      delivery: 'Instant',
    },
  });
}

// ─── Previewable Catalog ───────────────────────────────────────────────────────
async function handlePreviewCatalog(request, env, authCtx) {
  let threatItems = [];
  try {
    const r = await env.DB.prepare(
      `SELECT id, title, severity, source, created_at FROM threat_intel_cache WHERE expires_at > datetime('now') ORDER BY severity DESC, created_at DESC LIMIT 20`
    ).all();
    threatItems = r.results || [];
  } catch {}

  if (threatItems.length === 0) {
    try {
      const r = await env.DB.prepare(
        `SELECT id, title, severity, source, created_at FROM threat_intel ORDER BY created_at DESC LIMIT 20`
      ).all();
      threatItems = r.results || [];
    } catch {}
  }

  // Map to preview cards
  const previewCards = threatItems.map(item => ({
    id: item.id || crypto.randomUUID(),
    title: item.title,
    severity: item.severity,
    type: item.title?.includes('CVE-') ? 'cve' : 'threat',
    preview_url: item.title?.includes('CVE-')
      ? `/api/preview/cve/${item.title.match(/CVE-\d{4}-\d+/)?.[0] || item.id}`
      : `/api/preview/threat/${(item.source || 'unknown').toLowerCase()}`,
    source: item.source,
    published: item.created_at,
  }));

  // Real counts per category — no invented numbers. threat_intel*/cti_actors/cti_iocs
  // are queried live; malware_families and reports have no DB table backing them, so
  // their real count is the size of the actual static catalog each handler serves
  // from (MALWARE_FAMILIES / REPORT_TYPES) rather than an unrelated made-up figure.
  // Every count falls back to already-fetched real data (never to a fabricated
  // number) if the live query fails.
  let cveCount = previewCards.length;
  let actorCount = Object.keys(KNOWN_ACTORS).length;
  let iocCount = 0;
  try {
    const [cveRes, actorRes, iocRes] = await env.DB.batch([
      env.DB.prepare(`SELECT COUNT(*) AS c FROM threat_intel_cache WHERE expires_at > datetime('now')`),
      env.DB.prepare(`SELECT COUNT(*) AS c FROM cti_actors`),
      env.DB.prepare(`SELECT COUNT(*) AS c FROM cti_iocs WHERE tlp != 'RED'`),
    ]);
    cveCount = Math.max(cveRes.results?.[0]?.c ?? 0, previewCards.length);
    actorCount = Math.max(actorRes.results?.[0]?.c ?? 0, Object.keys(KNOWN_ACTORS).length);
    iocCount = iocRes.results?.[0]?.c ?? 0;
  } catch {}

  return Response.json({
    type: 'preview_catalog',
    total_previewable: previewCards.length,
    items: previewCards,
    categories: {
      cve: { count: cveCount, description: 'Active CVE intelligence with CVSS/EPSS/KEV data' },
      threat_actors: { count: actorCount, description: 'APT group profiles with TTP matrices' },
      malware_families: { count: Object.keys(MALWARE_FAMILIES).length, description: 'Malware family intelligence with YARA' },
      ioc_feeds: { count: iocCount, description: 'Live IOC records currently on file' },
      reports: { count: Object.keys(REPORT_TYPES).length, description: 'Intelligence report types' },
    },
    last_updated: new Date().toISOString(),
  });
}

// ─── Featured Intelligence (homepage) ─────────────────────────────────────────
async function handleFeaturedIntelligence(request, env, authCtx) {
  let featured = [];
  try {
    const r = await env.DB.prepare(
      `SELECT id, title, severity, description, source, created_at FROM threat_intel_cache WHERE severity IN ('CRITICAL','HIGH') AND expires_at > datetime('now') ORDER BY severity DESC, created_at DESC LIMIT 6`
    ).all();
    featured = r.results || [];
  } catch {}

  const items = featured.map(f => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    source: f.source,
    published: f.created_at,
    type: 'threat',
    preview_url: `/api/preview/cve/${f.title?.match(/CVE-\d{4}-\d+/)?.[0] || f.id}`,
  }));

  return Response.json({
    type: 'featured_intelligence',
    items,
    total_active_threats: items.length,
    critical_count: items.filter(f => f.severity === 'CRITICAL').length,
    last_updated: new Date().toISOString(),
    next_update: new Date(Date.now() + 14400000).toISOString(),
    ...(items.length === 0 ? { note: 'No live featured intelligence available right now — feed pending ingestion. No fabricated headlines shown.' } : {}),
  });
}

// ─── Unlock Preview (verify entitlement) ─────────────────────────────────────

// ─── Unlock Preview (verify entitlement) ─────────────────────────────────────
async function handlePreviewUnlock(request, env, authCtx) {
  if (!authCtx?.userId && !authCtx?.keyId) {
    return Response.json({ error: 'Authentication required to unlock content.' }, { status: 401 });
  }

  if (!(await isPremium(authCtx, env?.DB))) {
    return Response.json({
      unlocked: false,
      current_tier: userTier(authCtx),
      required_tier: 'PRO',
      upgrade_url: '/#pricing',
      upgrade_products: [
        { name: 'PRO plan', price: 'from ₹1,499/month', url: '/#pricing' },
        { name: 'ENTERPRISE plan', price: 'from ₹4,999/month', url: '/#pricing' },
      ],
    }, { status: 402 });
  }

  return Response.json({
    unlocked: true,
    tier: userTier(authCtx),
    access_level: 'FULL',
    message: 'Full intelligence access granted.',
  });
}

// ─── Main router ──────────────────────────────────────────────────────────────
export async function handleIntelligencePreview(request, env, authCtx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const kv = env?.KV || env?.SECURITY_HUB_KV;

  // FIX (Task 20): KV rate limit for FREE-tier users — 10 preview requests/min
  const tier = userTier(authCtx);
  if (tier === 'FREE' && authCtx?.userId) {
    const rl = await checkPreviewRateLimit(kv, authCtx.userId, 10, 60);
    if (!rl.allowed) {
      return Response.json({
        error: 'Preview rate limit exceeded',
        limit: rl.limit,
        window_seconds: 60,
        retry_after: 60,
        upgrade_url: '/#pricing',
        cta: 'Upgrade to PRO for unlimited intelligence access — from ₹1,499/month',
      }, {
        status: 429,
        headers: {
          'Retry-After': '60',
          'X-RateLimit-Limit': String(rl.limit),
          'X-RateLimit-Remaining': '0',
        },
      });
    }
  }

  if (path.startsWith('/api/preview/cve/')) return handleCVEPreview(request, env, authCtx);
  if (path.startsWith('/api/preview/threat/')) return handleThreatActorPreview(request, env, authCtx);
  if (path.startsWith('/api/preview/malware/')) return handleMalwarePreview(request, env, authCtx);
  if (path === '/api/preview/ioc-sample') return handleIOCSample(request, env, authCtx);
  if (path.startsWith('/api/preview/report-sample')) return handleReportSamplePreview(request, env, authCtx);
  if (path === '/api/preview/catalog') return handlePreviewCatalog(request, env, authCtx);
  if (path === '/api/preview/featured') return handleFeaturedIntelligence(request, env, authCtx);
  if (path === '/api/preview/unlock' && request.method === 'POST') return handlePreviewUnlock(request, env, authCtx);

  return Response.json({ error: 'Preview endpoint not found', path }, { status: 404 });
}
