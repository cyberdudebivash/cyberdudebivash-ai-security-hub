/**
 * CYBERDUDEBIVASH AI Security Hub — Correlation Engine v1.0
 * Sentinel APEX Phase 2: AI Threat Correlation
 *
 * Correlates:
 *   CVE ↔ CVE    (same vendor/product/CWE family)
 *   CVE ↔ IOC    (CVE ID appears in IOC registry; IOC IPs/domains linked to CVE)
 *   CVE ↔ Actor  (static APT/threat actor mapping by product + technique)
 *
 * Output: { related_cves, related_iocs, threat_actor, campaign, confidence }
 */

// ─── Static APT → product/technique mapping ───────────────────────────────────
const THREAT_ACTOR_MAP = [
  {
    actor: 'APT29 (Cozy Bear)',
    campaign: 'SolarWinds Supply Chain / Cloud Credential Theft',
    keywords: ['solarwinds', 'microsoft', 'azure', 'exchange', 'outlook', 'teams', 'oauth'],
    cwe_triggers: ['CWE-287', 'CWE-522', 'CWE-306'],
    mitre: ['T1078', 'T1550', 'T1190'],
  },
  {
    actor: 'APT41 (Double Dragon)',
    campaign: 'Dual espionage + financial crime via supply chain',
    keywords: ['teamcity', 'jetbrains', 'citrix', 'vmware', 'cisco', 'f5', 'ivanti'],
    cwe_triggers: ['CWE-288', 'CWE-78', 'CWE-77', 'CWE-89'],
    mitre: ['T1190', 'T1059', 'T1505'],
  },
  {
    actor: 'Cl0p Ransomware Group',
    campaign: 'MOVEit / GoAnywhere MFT mass exploitation',
    keywords: ['moveit', 'goanywhere', 'fortra', 'progress', 'mft', 'fileshare'],
    cwe_triggers: ['CWE-89', 'CWE-22', 'CWE-434'],
    mitre: ['T1190', 'T1486', 'T1041'],
  },
  {
    actor: 'LockBit Ransomware',
    campaign: 'RDP/VPN exploitation → ransomware deployment',
    keywords: ['connectwise', 'screenconnect', 'citrix', 'fortinet', 'palo alto', 'vpn', 'rdp'],
    cwe_triggers: ['CWE-22', 'CWE-287', 'CWE-787'],
    mitre: ['T1133', 'T1486', 'T1078'],
  },
  {
    actor: 'Volt Typhoon (China-nexus)',
    campaign: 'Critical infrastructure pre-positioning (LOTL)',
    keywords: ['cisco', 'netscaler', 'asa', 'fortios', 'router', 'firewall', 'iot'],
    cwe_triggers: ['CWE-78', 'CWE-77', 'CWE-120'],
    mitre: ['T1190', 'T1021', 'T1070'],
  },
  {
    actor: 'Lazarus Group (DPRK)',
    campaign: 'Financial theft + crypto heist + supply chain attacks',
    keywords: ['npm', 'pypi', 'github', 'node', 'python', 'chrome', 'browser'],
    cwe_triggers: ['CWE-94', 'CWE-1321', 'CWE-79'],
    mitre: ['T1195', 'T1059', 'T1566'],
  },
  {
    actor: 'ALPHV/BlackCat Ransomware',
    campaign: 'Healthcare + critical infra ransomware (ChangeHealthcare)',
    keywords: ['changehealth', 'healthcare', 'hospital', 'citrix', 'bleed', 'netscaler'],
    cwe_triggers: ['CWE-22', 'CWE-287', 'CWE-306'],
    mitre: ['T1190', 'T1486', 'T1078'],
  },
  {
    actor: 'UNC3944 / Scattered Spider',
    campaign: 'Social engineering + MFA bypass + cloud lateral movement',
    keywords: ['okta', 'azure', 'aws', 'microsoft', 'mfa', 'sso', 'identity'],
    cwe_triggers: ['CWE-287', 'CWE-306', 'CWE-522'],
    mitre: ['T1078', 'T1621', 'T1556'],
  },
];

// ─── Vendor family grouping for CVE↔CVE correlation ──────────────────────────
const VENDOR_FAMILIES = {
  paloalto: ['palo alto', 'panos', 'pan-os', 'globalprotect', 'cortex'],
  fortinet: ['fortinet', 'fortios', 'fortigate', 'fortiweb', 'fortimanager'],
  cisco: ['cisco', 'ios xe', 'asa', 'ftd', 'webex', 'meraki', 'nexus'],
  microsoft: ['microsoft', 'windows', 'exchange', 'azure', 'office', 'sharepoint', 'teams', 'edge'],
  vmware: ['vmware', 'vsphere', 'vcenter', 'esxi', 'aria', 'workspace'],
  ivanti: ['ivanti', 'pulse', 'connect secure', 'mobileiron'],
  citrix: ['citrix', 'netscaler', 'adc', 'workspace'],
  connectwise: ['connectwise', 'screenconnect', 'automate'],
  apache: ['apache', 'log4j', 'log4shell', 'struts', 'solr', 'kafka'],
  linux: ['linux', 'kernel', 'ubuntu', 'debian', 'rhel', 'centos'],
  chrome: ['chrome', 'chromium', 'v8', 'blink'],
};

// ─── CWE family grouping ───────────────────────────────────────────────────────
const CWE_FAMILIES = {
  injection: ['CWE-77', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94'],
  memory:    ['CWE-120', 'CWE-122', 'CWE-125', 'CWE-190', 'CWE-787'],
  auth:      ['CWE-287', 'CWE-288', 'CWE-306', 'CWE-522', 'CWE-798'],
  path:      ['CWE-22', 'CWE-23', 'CWE-36', 'CWE-434'],
  crypto:    ['CWE-327', 'CWE-330', 'CWE-338'],
};

// ─── Utility: parse JSON tags safely ─────────────────────────────────────────
function parseTags(entry) {
  try { return JSON.parse(entry.tags || '[]'); } catch { return []; }
}
function parseWeaknesses(entry) {
  try { return JSON.parse(entry.weakness_types || '[]'); } catch { return []; }
}
function parseAffected(entry) {
  try { return JSON.parse(entry.affected_products || '[]'); } catch { return []; }
}

// ─── Get vendor family for an entry ──────────────────────────────────────────
function getVendorFamily(entry) {
  const text = `${entry.title} ${entry.description} ${parseAffected(entry).join(' ')}`.toLowerCase();
  for (const [family, keywords] of Object.entries(VENDOR_FAMILIES)) {
    if (keywords.some(k => text.includes(k))) return family;
  }
  return null;
}

// ─── Get CWE family ───────────────────────────────────────────────────────────
function getCWEFamily(weaknesses) {
  for (const [family, cwes] of Object.entries(CWE_FAMILIES)) {
    if (weaknesses.some(w => cwes.includes(w))) return family;
  }
  return null;
}

// ─── CVE ↔ CVE correlation ───────────────────────────────────────────────────
function correlateCVEtoCVE(target, allEntries) {
  const targetFamily   = getVendorFamily(target);
  const targetWeakness = parseWeaknesses(target);
  const targetCWEFam   = getCWEFamily(targetWeakness);
  const targetTags     = parseTags(target);

  const related = [];

  for (const entry of allEntries) {
    if (entry.id === target.id) continue;

    let score = 0;
    const reasons = [];

    // Same vendor family
    const entryFamily = getVendorFamily(entry);
    if (targetFamily && entryFamily === targetFamily) {
      score += 40;
      reasons.push(`same_vendor_family:${targetFamily}`);
    }

    // Same CWE family
    const entryWeakness = parseWeaknesses(entry);
    const entryCWEFam   = getCWEFamily(entryWeakness);
    if (targetCWEFam && entryCWEFam === targetCWEFam) {
      score += 25;
      reasons.push(`same_cwe_family:${targetCWEFam}`);
    }

    // Shared CWE exact match
    const sharedCWEs = targetWeakness.filter(w => entryWeakness.includes(w));
    if (sharedCWEs.length > 0) {
      score += sharedCWEs.length * 15;
      reasons.push(`shared_cwe:${sharedCWEs.join(',')}`);
    }

    // Shared tags
    const entryTags  = parseTags(entry);
    const sharedTags = targetTags.filter(t => entryTags.includes(t));
    if (sharedTags.length > 0) {
      score += sharedTags.length * 10;
      reasons.push(`shared_tags:${sharedTags.join(',')}`);
    }

    // Both exploited in the wild
    if (target.exploit_status === 'confirmed' && entry.exploit_status === 'confirmed') {
      score += 20;
      reasons.push('both_actively_exploited');
    }

    // Both in KEV
    if (target.known_ransomware && entry.known_ransomware) {
      score += 15;
      reasons.push('both_ransomware_linked');
    }

    if (score >= 25) {
      related.push({
        id:         entry.id,
        title:      entry.title,
        severity:   entry.severity,
        cvss:       entry.cvss,
        score,
        reasons,
      });
    }
  }

  return related
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);
}

// ─── CVE ↔ IOC correlation (from D1 ioc_registry) ────────────────────────────
async function correlateCVEtoIOCs(env, cveId) {
  if (!env?.DB) return [];
  try {
    const rows = await env.DB.prepare(
      `SELECT i.value, i.type, i.defanged
       FROM ioc_registry i
       JOIN threat_intel t ON i.intel_id = t.id
       WHERE t.id = ? OR i.raw_context LIKE ?
       LIMIT 20`
    ).bind(cveId, `%${cveId}%`).all();
    return (rows?.results || []).map(r => ({
      value:    r.defanged || r.value,
      type:     r.type,
      defanged: !!r.defanged,
    }));
  } catch {
    return [];
  }
}

// ─── CVE ↔ Threat Actor mapping ──────────────────────────────────────────────
function matchThreatActor(entry) {
  const text      = `${entry.title} ${entry.description} ${parseAffected(entry).join(' ')}`.toLowerCase();
  const weaknesses = parseWeaknesses(entry);

  let bestMatch   = null;
  let bestScore   = 0;

  for (const actor of THREAT_ACTOR_MAP) {
    let score = 0;

    // Keyword match
    const kwMatches = actor.keywords.filter(k => text.includes(k));
    score += kwMatches.length * 20;

    // CWE trigger match
    const cweMatches = actor.cwe_triggers.filter(c => weaknesses.includes(c));
    score += cweMatches.length * 15;

    if (score > bestScore) {
      bestScore = score;
      bestMatch = { ...actor, match_score: score, kw_matches: kwMatches, cwe_matches: cweMatches };
    }
  }

  if (bestScore >= 20) return bestMatch;
  return null;
}

// ─── Master correlate function ─────────────────────────────────────────────────
export async function correlateEntry(entry, allEntries, env) {
  const [relatedIOCs, actorMatch] = await Promise.all([
    correlateCVEtoIOCs(env, entry.id),
    Promise.resolve(matchThreatActor(entry)),
  ]);

  const relatedCVEs = correlateCVEtoCVE(entry, allEntries);

  return {
    cve_id:        entry.id,
    related_cves:  relatedCVEs,
    related_iocs:  relatedIOCs,
    threat_actor:  actorMatch?.actor  || null,
    campaign:      actorMatch?.campaign || null,
    mitre_tactics: actorMatch?.mitre  || [],
    confidence:    actorMatch?.match_score ? Math.min(100, actorMatch.match_score) : 0,
    correlated_at: new Date().toISOString(),
  };
}

// ─── Batch correlate (used during ingestion) ───────────────────────────────────
export async function correlateBatch(entries, env) {
  const results = [];
  for (const entry of entries) {
    const correlation = await correlateEntry(entry, entries, env);
    results.push(correlation);
  }
  return results;
}

// ─── Quick actor lookup by CVE ID (for API responses) ─────────────────────────
export function getActorForCVE(cveId, entry) {
  if (!entry) return null;
  return matchThreatActor(entry);
}

// ─── Build correlation summary for a feed ─────────────────────────────────────
export function buildCorrelationSummary(entries) {
  const actorMap  = {};
  const familyMap = {};

  for (const entry of entries) {
    const actor  = matchThreatActor(entry);
    const family = getVendorFamily(entry);

    if (actor) {
      actorMap[actor.actor] = (actorMap[actor.actor] || 0) + 1;
    }
    if (family) {
      familyMap[family] = (familyMap[family] || 0) + 1;
    }
  }

  const topActors   = Object.entries(actorMap).sort((a,b) => b[1]-a[1]).slice(0, 5)
    .map(([actor, count]) => ({ actor, count }));
  const topFamilies = Object.entries(familyMap).sort((a,b) => b[1]-a[1]).slice(0, 5)
    .map(([family, count]) => ({ family, count }));

  return { top_threat_actors: topActors, top_vendor_families: topFamilies };
}
