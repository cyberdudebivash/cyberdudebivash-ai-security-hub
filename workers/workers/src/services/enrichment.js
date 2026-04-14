/**
 * CYBERDUDEBIVASH AI Security Hub — Enrichment Engine v1.0
 * Enhances raw threat intel entries with CVSS scores, exploit status,
 * threat categories, MITRE ATT&CK mappings, and severity normalization.
 *
 * Runs entirely at the edge (no external calls in hot path).
 * CVSS lookup uses an embedded curated database for known high-impact CVEs.
 */

// ─── Embedded CVSS lookup table (real scores for known CVEs) ─────────────────
// Prevents needing live NVD API calls during enrichment pass.
const CVSS_DB = {
  'CVE-2024-3400':   { cvss: 10.0, severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
  'CVE-2024-21762':  { cvss: 9.6,  severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-27198':  { cvss: 9.8,  severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-1709':   { cvss: 10.0, severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
  'CVE-2024-21893':  { cvss: 8.2,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' },
  'CVE-2024-4577':   { cvss: 9.8,  severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-38094':  { cvss: 7.2,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-21626':  { cvss: 8.6,  severity: 'HIGH',     vector: 'AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H' },
  'CVE-2024-6387':   { cvss: 8.1,  severity: 'HIGH',     vector: 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-30078':  { cvss: 8.8,  severity: 'HIGH',     vector: 'AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-23897':  { cvss: 9.8,  severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-20353':  { cvss: 8.6,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H' },
  'CVE-2024-20359':  { cvss: 6.0,  severity: 'MEDIUM',   vector: 'AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N' },
  'CVE-2024-0519':   { cvss: 8.8,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' },
  'CVE-2024-29988':  { cvss: 8.8,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' },
  'CVE-2025-21444':  { cvss: 7.8,  severity: 'HIGH',     vector: 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2025-24085':  { cvss: 7.8,  severity: 'HIGH',     vector: 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2025-22457':  { cvss: 9.0,  severity: 'CRITICAL', vector: 'AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H' },
  'CVE-2025-29824':  { cvss: 7.8,  severity: 'HIGH',     vector: 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2023-44487':  { cvss: 7.5,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }, // HTTP/2 Rapid Reset
  'CVE-2023-4966':   { cvss: 9.4,  severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, // Citrix Bleed
  'CVE-2023-36884':  { cvss: 8.3,  severity: 'HIGH',     vector: 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H' },
  'CVE-2023-34362':  { cvss: 9.8,  severity: 'CRITICAL', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, // MoveIT Transfer SQLi
};

// ─── MITRE ATT&CK technique mapping by weakness type ─────────────────────────
const CWE_TO_MITRE = {
  'CWE-78':  { id: 'T1059', name: 'Command and Scripting Interpreter' },
  'CWE-77':  { id: 'T1059', name: 'Command and Scripting Interpreter' },
  'CWE-89':  { id: 'T1190', name: 'Exploit Public-Facing Application (SQLi)' },
  'CWE-79':  { id: 'T1189', name: 'Drive-by Compromise (XSS)' },
  'CWE-22':  { id: 'T1083',  name: 'File and Directory Discovery (Path Traversal)' },
  'CWE-416': { id: 'T1203',  name: 'Exploitation for Client Execution (UAF)' },
  'CWE-787': { id: 'T1190',  name: 'Exploit Public-Facing Application (Buffer Overflow)' },
  'CWE-121': { id: 'T1190',  name: 'Exploit Public-Facing Application (Stack Overflow)' },
  'CWE-502': { id: 'T1059',  name: 'Command and Scripting Interpreter (Deserialization)' },
  'CWE-918': { id: 'T1090',  name: 'Proxy (SSRF)' },
  'CWE-288': { id: 'T1078',  name: 'Valid Accounts (Auth Bypass)' },
  'CWE-362': { id: 'T1499',  name: 'Endpoint Denial of Service (Race Condition)' },
  'CWE-269': { id: 'T1548',  name: 'Abuse Elevation Control Mechanism (PrivEsc)' },
  'CWE-200': { id: 'T1552',  name: 'Unsecured Credentials (Info Disclosure)' },
  'CWE-306': { id: 'T1078',  name: 'Valid Accounts (Missing Auth)' },
  'CWE-20':  { id: 'T1190',  name: 'Exploit Public-Facing Application (Input Validation)' },
  'CWE-94':  { id: 'T1059',  name: 'Command and Scripting Interpreter (Code Injection)' },
  'CWE-88':  { id: 'T1059',  name: 'Command and Scripting Interpreter (Arg Injection)' },
  'CWE-434': { id: 'T1190',  name: 'Exploit Public-Facing Application (File Upload)' },
  'CWE-798': { id: 'T1552',  name: 'Unsecured Credentials (Hard-coded)' },
};

// ─── Tag → threat category mapping ───────────────────────────────────────────
const TAG_CATEGORIES = {
  'RCE':           'Remote Code Execution',
  'SQLi':          'SQL Injection',
  'XSS':           'Cross-Site Scripting',
  'PrivEsc':       'Privilege Escalation',
  'DoS':           'Denial of Service',
  'AuthBypass':    'Authentication Bypass',
  'PathTraversal': 'Path Traversal',
  'BufferOverflow':'Memory Corruption',
  'UseAfterFree':  'Memory Corruption',
  'SSRF':          'Server-Side Request Forgery',
  'CmdInjection':  'Command Injection',
  'Deserialization':'Insecure Deserialization',
  'ZeroDay':       'Zero-Day Exploit',
  'SupplyChain':   'Supply Chain Attack',
  'Ransomware':    'Ransomware',
  'CloudSecurity': 'Cloud / Container Security',
  'ContainerEscape':'Container Escape',
  'ActiveExploitation': 'Actively Exploited (CISA KEV)',
};

// ─── Determine severity from CVSS score ──────────────────────────────────────
export function cvssToSeverity(score) {
  if (score === null || score === undefined) return 'MEDIUM';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

// ─── Compute exploit probability from metadata ────────────────────────────────
export function computeExploitProbability(entry) {
  let prob = 0.05; // base probability

  // Confirmed exploitation → very high
  if (entry.exploit_status === 'confirmed') prob += 0.60;
  else if (entry.exploit_status === 'poc_available') prob += 0.30;

  // CVSS score contribution
  const cvss = entry.cvss || 0;
  if (cvss >= 9.0) prob += 0.25;
  else if (cvss >= 7.0) prob += 0.15;
  else if (cvss >= 4.0) prob += 0.05;

  // Known ransomware usage
  if (entry.known_ransomware) prob += 0.20;

  // Tags
  const tags = typeof entry.tags === 'string' ? JSON.parse(entry.tags || '[]') : (entry.tags || []);
  if (tags.includes('ZeroDay'))        prob += 0.10;
  if (tags.includes('RCE'))            prob += 0.10;
  if (tags.includes('AuthBypass'))     prob += 0.08;
  if (tags.includes('PrivEsc'))        prob += 0.05;

  return Math.min(0.99, prob);
}

// ─── Get MITRE technique from weakness types ──────────────────────────────────
function getMitreTechnique(weaknessTypes = []) {
  const cwes = typeof weaknessTypes === 'string'
    ? JSON.parse(weaknessTypes || '[]')
    : weaknessTypes;

  for (const cwe of cwes) {
    const mapped = CWE_TO_MITRE[cwe];
    if (mapped) return mapped;
  }
  return null;
}

// ─── Get primary threat category from tags ────────────────────────────────────
function getPrimaryCategory(tags = []) {
  const tagArr = typeof tags === 'string' ? JSON.parse(tags || '[]') : tags;
  for (const tag of tagArr) {
    const cat = TAG_CATEGORIES[tag];
    if (cat) return cat;
  }
  return 'Security Vulnerability';
}

// ─── Enrich a single threat intel entry ──────────────────────────────────────
export function enrichEntry(entry) {
  const enriched = { ...entry };

  // 1. CVSS lookup from embedded DB
  if (!enriched.cvss && enriched.id) {
    const known = CVSS_DB[enriched.id];
    if (known) {
      enriched.cvss        = known.cvss;
      enriched.cvss_vector = known.vector;
      enriched.severity    = known.severity;
    }
  }

  // 2. Normalize severity from CVSS if still missing
  if (!enriched.severity || enriched.severity === 'MEDIUM') {
    enriched.severity = cvssToSeverity(enriched.cvss);
  }

  // 3. Upgrade CISA KEV entries to at least HIGH
  if (enriched.source === 'cisa_kev' && enriched.exploit_status === 'confirmed') {
    if (enriched.severity === 'MEDIUM' || enriched.severity === 'LOW') {
      enriched.severity = 'HIGH';
    }
    // Confirmed exploitation → add ActiveExploitation tag
    const tags = typeof enriched.tags === 'string' ? JSON.parse(enriched.tags || '[]') : (enriched.tags || []);
    if (!tags.includes('ActiveExploitation')) {
      tags.push('ActiveExploitation');
      enriched.tags = JSON.stringify(tags);
    }
  }

  // 4. MITRE ATT&CK technique mapping
  const technique = getMitreTechnique(enriched.weakness_types || enriched.weaknessTypes);
  if (technique) {
    enriched.mitre_technique = technique;
  }

  // 5. Primary threat category
  enriched.threat_category = getPrimaryCategory(enriched.tags);

  // 6. Exploit probability
  enriched.exploit_probability = computeExploitProbability(enriched);

  // 7. Priority score (0–10) for dashboard sorting
  let priority = 0;
  const cvss = enriched.cvss || 0;
  priority += cvss * 0.5; // max 5 from CVSS
  if (enriched.exploit_status === 'confirmed') priority += 3;
  else if (enriched.exploit_status === 'poc_available') priority += 1.5;
  if (enriched.known_ransomware) priority += 2;
  const tags = typeof enriched.tags === 'string' ? JSON.parse(enriched.tags || '[]') : (enriched.tags || []);
  if (tags.includes('ZeroDay')) priority += 1;
  enriched.priority_score = Math.min(10, Math.round(priority * 10) / 10);

  // 8. Mark as enriched
  enriched.enriched = 1;

  return enriched;
}

// ─── Batch enrich a list of entries ──────────────────────────────────────────
export function enrichBatch(entries = []) {
  return entries.map(e => enrichEntry(e));
}

// ─── Build dashboard summary stats from entries ───────────────────────────────
export function buildFeedSummary(entries = []) {
  const total     = entries.length;
  const critical  = entries.filter(e => e.severity === 'CRITICAL').length;
  const high      = entries.filter(e => e.severity === 'HIGH').length;
  const confirmed = entries.filter(e => e.exploit_status === 'confirmed').length;
  const ransomware= entries.filter(e => e.known_ransomware).length;
  const zeroDay   = entries.filter(e => {
    const tags = typeof e.tags === 'string' ? JSON.parse(e.tags || '[]') : (e.tags || []);
    return tags.includes('ZeroDay');
  }).length;
  const avgCVSS   = total > 0
    ? (entries.reduce((sum, e) => sum + (e.cvss || 0), 0) / total).toFixed(1)
    : 0;

  const alertLevel = critical >= 5 ? 'CRITICAL' :
                     critical >= 1 ? 'HIGH' :
                     high >= 3     ? 'ELEVATED' : 'MODERATE';

  // Top tags frequency
  const tagFreq = {};
  for (const e of entries) {
    const tags = typeof e.tags === 'string' ? JSON.parse(e.tags || '[]') : (e.tags || []);
    for (const t of tags) tagFreq[t] = (tagFreq[t] || 0) + 1;
  }
  const topTags = Object.entries(tagFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([tag, count]) => ({ tag, count, category: TAG_CATEGORIES[tag] || tag }));

  return {
    total,
    critical,
    high,
    medium:   entries.filter(e => e.severity === 'MEDIUM').length,
    low:      entries.filter(e => e.severity === 'LOW').length,
    confirmed_exploited: confirmed,
    ransomware_linked:   ransomware,
    zero_days:           zeroDay,
    average_cvss:        parseFloat(avgCVSS),
    alert_level:         alertLevel,
    top_attack_types:    topTags,
  };
}
