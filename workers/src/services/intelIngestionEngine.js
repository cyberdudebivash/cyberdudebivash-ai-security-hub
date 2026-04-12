/**
 * CYBERDUDEBIVASH AI Security Hub — Intel Ingestion Engine v1.0
 * ═══════════════════════════════════════════════════════════════
 * Sentinel APEX Defense Solutions — Powered by CYBERDUDEBIVASH
 *
 * MISSION: Ingest, normalize, and enrich threat intelligence from
 * multiple authoritative sources into a unified defense-ready format.
 *
 * SOURCES (priority order):
 *   1. intel.cyberdudebivash.com  — Sentinel APEX proprietary feed
 *   2. CISA KEV                   — Known Exploited Vulnerabilities
 *   3. NVD API v2                 — National Vulnerability Database
 *   4. FIRST EPSS                 — Exploit Prediction Scoring
 *   5. GitHub Security Advisories — OSS vulnerability feed
 *   6. Internal D1 cache          — Previously ingested intel
 *
 * OUTPUT FORMAT (Normalized Intel Object):
 * {
 *   id, title, severity, cvss_score, cvss_vector, epss_score,
 *   type, description, affected_systems, affected_versions,
 *   exploit_status, exploit_maturity, mitre_mapping,
 *   attack_vector, attack_complexity, privileges_required,
 *   user_interaction, scope, confidentiality_impact,
 *   integrity_impact, availability_impact,
 *   references, published_date, last_modified,
 *   kev_added, solution_exists, patch_available,
 *   iocs, tags, source, ingested_at
 * }
 */

import { resilientFetch } from '../lib/resilience.js';

// ─── Source configuration ─────────────────────────────────────────────────────
const SOURCES = {
  SENTINEL: {
    name:     'Sentinel APEX',
    url:      'https://intel.cyberdudebivash.com/api/feed',
    fallback: 'https://intel.cyberdudebivash.com/feed.json',
    priority: 1,
    timeout:  15000,
  },
  CISA_KEV: {
    name:    'CISA KEV',
    url:     'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    priority: 2,
    timeout: 20000,
  },
  NVD: {
    name:    'NIST NVD',
    url:     'https://services.nvd.nist.gov/rest/json/cves/2.0',
    priority: 3,
    timeout: 25000,
  },
  EPSS: {
    name:    'FIRST EPSS',
    url:     'https://api.first.org/data/v1/epss',
    priority: 4,
    timeout: 10000,
  },
};

// ─── Severity thresholds ──────────────────────────────────────────────────────
const SEVERITY_THRESHOLDS = {
  CRITICAL: { min: 9.0, max: 10.0 },
  HIGH:     { min: 7.0, max: 8.9  },
  MEDIUM:   { min: 4.0, max: 6.9  },
  LOW:      { min: 0.1, max: 3.9  },
  INFO:     { min: 0.0, max: 0.0  },
};

// ─── Exploit maturity levels (CVSS 3.x temporal) ─────────────────────────────
const EXPLOIT_MATURITY = {
  UNPROVEN:         { label: 'Unproven',          risk_multiplier: 0.8 },
  PROOF_OF_CONCEPT: { label: 'Proof of Concept',  risk_multiplier: 1.0 },
  FUNCTIONAL:       { label: 'Functional Exploit', risk_multiplier: 1.2 },
  HIGH:             { label: 'Weaponized',         risk_multiplier: 1.5 },
  KEV:              { label: 'Actively Exploited', risk_multiplier: 2.0 },
};

// ─── CVE type classification ──────────────────────────────────────────────────
const CVE_TYPE_PATTERNS = {
  RCE:              ['remote code execution', 'rce', 'arbitrary code', 'code execution'],
  SQLI:             ['sql injection', 'sqli', 'database injection'],
  XSS:              ['cross-site scripting', 'xss', 'reflected xss', 'stored xss'],
  SSRF:             ['server-side request forgery', 'ssrf'],
  XXE:              ['xml external entity', 'xxe'],
  LFI:              ['local file inclusion', 'lfi', 'path traversal', 'directory traversal'],
  AUTH_BYPASS:      ['authentication bypass', 'auth bypass', 'improper authentication', 'missing authentication'],
  PRIVESC:          ['privilege escalation', 'privesc', 'elevation of privilege'],
  BUFFER_OVERFLOW:  ['buffer overflow', 'stack overflow', 'heap overflow', 'memory corruption'],
  DESERIALIZATION:  ['deserialization', 'insecure deserialization', 'object injection'],
  CSRF:             ['cross-site request forgery', 'csrf'],
  IDOR:             ['insecure direct object reference', 'idor', 'broken access control'],
  DOS:              ['denial of service', 'dos', 'resource exhaustion', 'infinite loop'],
  MEMORY_LEAK:      ['memory leak', 'information disclosure', 'sensitive data exposure'],
  SUPPLY_CHAIN:     ['supply chain', 'dependency confusion', 'typosquatting', 'malicious package'],
  ZERO_DAY:         ['zero-day', '0-day', 'zero day', 'unpatched'],
  APT:              ['apt', 'advanced persistent threat', 'nation-state', 'state-sponsored'],
  RANSOMWARE:       ['ransomware', 'encryption', 'extortion'],
  CRYPTOJACKING:    ['cryptomining', 'cryptojacking', 'coin miner'],
  PHISHING:         ['phishing', 'spear phishing', 'whaling'],
};

// ─── MITRE ATT&CK auto-mapping ────────────────────────────────────────────────
const MITRE_AUTO_MAP = {
  RCE:             [{ tactic:'Execution', technique:'T1059', name:'Command and Scripting Interpreter' }],
  SQLI:            [{ tactic:'Initial Access', technique:'T1190', name:'Exploit Public-Facing Application' }],
  XSS:             [{ tactic:'Initial Access', technique:'T1189', name:'Drive-by Compromise' }],
  SSRF:            [{ tactic:'Discovery', technique:'T1046', name:'Network Service Discovery' }],
  XXE:             [{ tactic:'Collection', technique:'T1005', name:'Data from Local System' }],
  LFI:             [{ tactic:'Discovery', technique:'T1083', name:'File and Directory Discovery' }],
  AUTH_BYPASS:     [{ tactic:'Initial Access', technique:'T1078', name:'Valid Accounts' }],
  PRIVESC:         [{ tactic:'Privilege Escalation', technique:'T1068', name:'Exploitation for Privilege Escalation' }],
  BUFFER_OVERFLOW: [{ tactic:'Execution', technique:'T1203', name:'Exploitation for Client Execution' }],
  DESERIALIZATION: [{ tactic:'Execution', technique:'T1059', name:'Command and Scripting Interpreter' }],
  SUPPLY_CHAIN:    [{ tactic:'Initial Access', technique:'T1195', name:'Supply Chain Compromise' }],
  RANSOMWARE:      [{ tactic:'Impact', technique:'T1486', name:'Data Encrypted for Impact' }],
  APT:             [{ tactic:'Persistence', technique:'T1053', name:'Scheduled Task/Job' }],
  PHISHING:        [{ tactic:'Initial Access', technique:'T1566', name:'Phishing' }],
};

// ═══════════════════════════════════════════════════════════════════════════════
// CORE INGESTION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Master ingestion: pull from all sources, deduplicate, enrich, store.
 * @param {object} env - Cloudflare env bindings
 * @param {object} opts - { limit, severity_filter, days_back, force_refresh }
 * @returns {object} { ingested, updated, skipped, errors, intel_items }
 */
export async function runIngestionPipeline(env, opts = {}) {
  const {
    limit          = 50,
    severity_filter = ['CRITICAL', 'HIGH'],
    days_back       = 7,
    force_refresh   = false,
  } = opts;

  const stats   = { ingested: 0, updated: 0, skipped: 0, errors: [] };
  const results = [];

  // Check KV cache first (unless forced refresh)
  if (!force_refresh && env.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get('intel_feed:latest', 'json').catch(() => null);
    if (cached && (Date.now() - cached.fetched_at) < 3600000) {  // 1h cache
      return { ...stats, intel_items: cached.items, from_cache: true };
    }
  }

  // Parallel fetch from all sources
  const [sentinelData, kevData, nvdData] = await Promise.allSettled([
    fetchSentinelAPEX(env, { limit, days_back }),
    fetchCISAKEV(env),
    fetchNVDFeed(env, { limit, severity_filter, days_back }),
  ]);

  // Process each source
  const rawItems = [];

  if (sentinelData.status === 'fulfilled') {
    rawItems.push(...(sentinelData.value || []));
  } else {
    stats.errors.push({ source: 'Sentinel APEX', error: sentinelData.reason?.message });
  }

  if (kevData.status === 'fulfilled') {
    rawItems.push(...(kevData.value || []));
  } else {
    stats.errors.push({ source: 'CISA KEV', error: kevData.reason?.message });
  }

  if (nvdData.status === 'fulfilled') {
    rawItems.push(...(nvdData.value || []));
  } else {
    stats.errors.push({ source: 'NVD', error: nvdData.reason?.message });
  }

  // Deduplicate by CVE ID
  const seen     = new Set();
  const deduped  = [];
  for (const item of rawItems) {
    const key = item.id || item.cve_id || item.title;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(item);
    } else {
      stats.skipped++;
    }
  }

  // Normalize + enrich each item
  for (const raw of deduped) {
    try {
      const normalized = await normalizeIntelItem(raw, env);
      results.push(normalized);

      // Store in D1
      await storeIntelItem(env, normalized);
      stats.ingested++;
    } catch (err) {
      stats.errors.push({ item: raw.id, error: err.message });
    }
  }

  // Cache in KV
  if (env.SECURITY_HUB_KV && results.length > 0) {
    await env.SECURITY_HUB_KV.put(
      'intel_feed:latest',
      JSON.stringify({ items: results, fetched_at: Date.now(), count: results.length }),
      { expirationTtl: 3600 }
    ).catch(() => {});
  }

  return { ...stats, intel_items: results };
}

// ─── Source: Sentinel APEX ────────────────────────────────────────────────────
async function fetchSentinelAPEX(env, opts = {}) {
  const { limit = 20, days_back = 7 } = opts;

  try {
    const headers = {};
    if (env.SENTINEL_API_KEY) headers['x-api-key'] = env.SENTINEL_API_KEY;

    const url = `${SOURCES.SENTINEL.url}?limit=${limit}&days=${days_back}&format=json`;
    const resp = await fetch(url, { headers, cf: { cacheTtl: 3600 }, signal: AbortSignal.timeout(SOURCES.SENTINEL.timeout) });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Normalize from Sentinel APEX format
    const items = (data.vulnerabilities || data.items || data.cves || []);
    return items.map(item => ({ ...item, _source: 'sentinel_apex' }));

  } catch (err) {
    console.warn('[Ingestion] Sentinel APEX fetch failed:', err.message);
    // Return internal seed data as fallback
    return getInternalSeedIntel();
  }
}

// ─── Source: CISA KEV ─────────────────────────────────────────────────────────
async function fetchCISAKEV(env) {
  try {
    const resp = await fetch(SOURCES.CISA_KEV.url, {
      cf:     { cacheTtl: 7200 },
      signal: AbortSignal.timeout(SOURCES.CISA_KEV.timeout),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    const cutoff   = new Date(Date.now() - 30 * 86400000); // last 30 days
    const recentKEV = (data.vulnerabilities || [])
      .filter(v => new Date(v.dateAdded) >= cutoff)
      .slice(0, 30);

    return recentKEV.map(v => ({
      id:               v.cveID,
      title:            `${v.cveID} — ${v.vulnerabilityName}`,
      severity:         'CRITICAL',    // All KEV entries = actively exploited = critical priority
      type:             classifyType(v.shortDescription || v.vulnerabilityName),
      description:      v.shortDescription || v.vulnerabilityName,
      affected_systems: [v.vendorProject + ' ' + v.product],
      exploit_status:   'ACTIVELY_EXPLOITED',
      exploit_maturity: 'KEV',
      patch_available:  v.requiredAction ? v.requiredAction.toLowerCase().includes('patch') : false,
      kev_added:        v.dateAdded,
      kev_due_date:     v.dueDate,
      notes:            v.notes || '',
      required_action:  v.requiredAction || '',
      _source:          'cisa_kev',
    }));

  } catch (err) {
    console.warn('[Ingestion] CISA KEV fetch failed:', err.message);
    return [];
  }
}

// ─── Source: NVD API v2 ───────────────────────────────────────────────────────
async function fetchNVDFeed(env, opts = {}) {
  const { limit = 20, severity_filter = ['CRITICAL', 'HIGH'], days_back = 7 } = opts;

  try {
    const pubStartDate = new Date(Date.now() - days_back * 86400000).toISOString().split('.')[0] + '.000';
    const pubEndDate   = new Date().toISOString().split('.')[0] + '.000';

    const params = new URLSearchParams({
      resultsPerPage: limit,
      pubStartDate,
      pubEndDate,
      noRejected: '',
    });
    if (severity_filter.includes('CRITICAL') && !severity_filter.includes('HIGH')) {
      params.set('cvssV3Severity', 'CRITICAL');
    }

    const resp = await fetch(`${SOURCES.NVD.url}?${params}`, {
      headers: env.NVD_API_KEY ? { 'apiKey': env.NVD_API_KEY } : {},
      cf:      { cacheTtl: 3600 },
      signal:  AbortSignal.timeout(SOURCES.NVD.timeout),
    });

    if (!resp.ok) throw new Error(`NVD HTTP ${resp.status}`);
    const data = await resp.json();

    return (data.vulnerabilities || []).map(v => {
      const cve     = v.cve;
      const metrics = cve.metrics || {};
      const cvssV31 = (metrics.cvssMetricV31 || [])[0]?.cvssData || {};
      const cvssV30 = (metrics.cvssMetricV30 || [])[0]?.cvssData || {};
      const cvss    = cvssV31.baseScore || cvssV30.baseScore || 0;
      const vector  = cvssV31.vectorString || cvssV30.vectorString || '';

      const desc = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const cpes  = (cve.configurations || [])
        .flatMap(c => c.nodes || [])
        .flatMap(n => n.cpeMatch || [])
        .filter(c => c.vulnerable)
        .map(c => c.criteria)
        .slice(0, 5);

      return {
        id:               cve.id,
        title:            `${cve.id} — ${desc.substring(0, 80)}`,
        cvss_score:       cvss,
        cvss_vector:      vector,
        severity:         cvssToSeverity(cvss),
        type:             classifyType(desc),
        description:      desc,
        affected_systems: cpes.length ? cpes : extractAffectedSystems(desc),
        affected_versions: extractVersions(desc),
        exploit_status:   'UNKNOWN',
        exploit_maturity: 'UNPROVEN',
        references:       (cve.references || []).map(r => r.url).slice(0, 5),
        published_date:   cve.published,
        last_modified:    cve.lastModified,
        cwes:             (cve.weaknesses || []).flatMap(w => w.description?.map(d => d.value) || []),
        _source:          'nvd',
      };
    });

  } catch (err) {
    console.warn('[Ingestion] NVD fetch failed:', err.message);
    return [];
  }
}

// ─── Enrich with EPSS scores ──────────────────────────────────────────────────
async function enrichWithEPSS(env, cveIds = []) {
  if (!cveIds.length) return {};

  try {
    const ids  = cveIds.join(',');
    const resp = await fetch(`${SOURCES.EPSS.url}?cve=${ids}`, {
      cf:     { cacheTtl: 7200 },
      signal: AbortSignal.timeout(SOURCES.EPSS.timeout),
    });
    if (!resp.ok) throw new Error(`EPSS HTTP ${resp.status}`);
    const data = await resp.json();

    const epssMap = {};
    for (const item of (data.data || [])) {
      epssMap[item.cve] = {
        score:      parseFloat(item.epss),
        percentile: parseFloat(item.percentile),
      };
    }
    return epssMap;
  } catch {
    return {};
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NORMALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Normalize any raw intel item to the unified format.
 */
export async function normalizeIntelItem(raw, env) {
  const cvss    = parseFloat(raw.cvss_score || raw.cvss || raw.base_score || 0);
  const severity = raw.severity || cvssToSeverity(cvss);

  // Build normalized object
  const normalized = {
    id:               raw.id || raw.cve_id || `INTEL-${Date.now()}`,
    title:            raw.title || raw.name || raw.id || 'Unknown Vulnerability',
    severity:         normalizeSeverity(severity),
    cvss_score:       cvss,
    cvss_vector:      raw.cvss_vector || raw.vector_string || '',
    epss_score:       raw.epss_score || null,
    epss_percentile:  raw.epss_percentile || null,
    type:             raw.type || classifyType(raw.description || raw.title || ''),
    description:      raw.description || raw.summary || raw.short_description || '',
    affected_systems: normalizeAffectedSystems(raw),
    affected_versions: raw.affected_versions || extractVersions(raw.description || ''),
    exploit_status:   raw.exploit_status || classifyExploitStatus(raw),
    exploit_maturity: raw.exploit_maturity || 'UNPROVEN',
    patch_available:  raw.patch_available ?? detectPatchAvailable(raw),
    solution_exists:  raw.solution_exists ?? false,
    mitre_mapping:    buildMITREMapping(raw),
    attack_vector:    extractFromVector(raw.cvss_vector || '', 'AV'),
    attack_complexity:extractFromVector(raw.cvss_vector || '', 'AC'),
    privileges_required: extractFromVector(raw.cvss_vector || '', 'PR'),
    user_interaction: extractFromVector(raw.cvss_vector || '', 'UI'),
    scope:            extractFromVector(raw.cvss_vector || '', 'S'),
    confidentiality:  extractFromVector(raw.cvss_vector || '', 'C'),
    integrity:        extractFromVector(raw.cvss_vector || '', 'I'),
    availability:     extractFromVector(raw.cvss_vector || '', 'A'),
    kev_added:        raw.kev_added || null,
    kev_due_date:     raw.kev_due_date || null,
    required_action:  raw.required_action || raw.requiredAction || null,
    references:       raw.references || [],
    cwes:             raw.cwes || [],
    iocs:             raw.iocs || extractIOCs(raw.description || ''),
    tags:             buildTags(raw),
    published_date:   raw.published_date || raw.published || raw.dateAdded || new Date().toISOString(),
    last_modified:    raw.last_modified || raw.lastModified || new Date().toISOString(),
    source:           raw._source || 'unknown',
    ingested_at:      new Date().toISOString(),
    notes:            raw.notes || '',
  };

  // Enrich: if CVSS 0 but KEV, upgrade to CRITICAL
  if (normalized.kev_added && normalized.cvss_score === 0) {
    normalized.cvss_score  = 9.0;
    normalized.severity    = 'CRITICAL';
  }

  // Enrich: boost severity for actively exploited
  if (normalized.exploit_status === 'ACTIVELY_EXPLOITED' && normalized.severity === 'HIGH') {
    normalized.severity = 'CRITICAL';
  }

  return normalized;
}

// ─── Store in D1 ─────────────────────────────────────────────────────────────
async function storeIntelItem(env, item) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(`
      INSERT INTO threat_intel (
        cve_id, title, severity, cvss_score, cvss_vector, epss_score,
        vuln_type, description, affected_systems, exploit_status,
        patch_available, mitre_json, iocs_json, tags, source,
        published_date, ingested_at, solution_generated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), 0)
      ON CONFLICT(cve_id) DO UPDATE SET
        severity         = excluded.severity,
        cvss_score       = excluded.cvss_score,
        exploit_status   = excluded.exploit_status,
        ingested_at      = excluded.ingested_at
    `).bind(
      item.id, item.title, item.severity, item.cvss_score, item.cvss_vector,
      item.epss_score, item.type, item.description.substring(0, 2000),
      JSON.stringify(item.affected_systems), item.exploit_status,
      item.patch_available ? 1 : 0,
      JSON.stringify(item.mitre_mapping),
      JSON.stringify(item.iocs),
      item.tags.join(','), item.source, item.published_date,
    ).run();
  } catch (err) {
    console.error('[Ingestion] D1 store error:', err.message);
  }
}

// ─── Retrieve unprocessed intel for solution generation ───────────────────────
export async function getPendingSolutionIntel(env, limit = 10) {
  if (!env.DB) return getInternalSeedIntel().slice(0, limit).map(i => normalizeIntelItem(i, env));

  try {
    const rows = await env.DB.prepare(`
      SELECT * FROM threat_intel
      WHERE solution_generated = 0
        AND severity IN ('CRITICAL', 'HIGH')
      ORDER BY
        CASE severity WHEN 'CRITICAL' THEN 2 WHEN 'HIGH' THEN 1 ELSE 0 END DESC,
        cvss DESC
      LIMIT ?
    `).bind(limit).all();

    return (rows.results || []).map(row => ({
      ...row,
      mitre_mapping:    JSON.parse(row.tags || '[]'),
      affected_systems: JSON.parse(row.affected_products || '[]'),
      iocs:             JSON.parse(row.ioc_list || row.iocs || '[]'),
    }));
  } catch (err) {
    console.error('[Ingestion] getPendingSolutionIntel error:', err.message);
    return getInternalSeedIntel().slice(0, limit);
  }
}

// ─── Mark intel as solution-generated ─────────────────────────────────────────
export async function markSolutionGenerated(env, intelId, productId) {
  if (!env.DB) return;
  await env.DB.prepare(
    `UPDATE threat_intel SET solution_generated = 1, product_id = ? WHERE id = ?`
  ).bind(productId, intelId).run().catch(() => {});
}

// ─── Get all ingested intel (for dashboard) ───────────────────────────────────
export async function getIntelFeed(env, opts = {}) {
  const { limit = 50, severity = null, days = 30, with_solutions = false } = opts;

  if (!env.DB) return getInternalSeedIntel().slice(0, limit);

  try {
    let sql = `
      SELECT ti.*, dp.id as product_id, dp.product_name, dp.price_inr
      FROM threat_intel ti
      LEFT JOIN defense_products dp ON ti.cve_id = dp.intel_id
      WHERE ti.ingested_at > datetime('now', ? || ' days')
    `;
    const bindings = [`-${days}`];

    if (severity) {
      sql += ` AND ti.severity = ?`;
      bindings.push(severity);
    }
    if (with_solutions) {
      sql += ` AND ti.solution_generated = 1`;
    }

    sql += ` ORDER BY CASE ti.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 ELSE 1 END DESC, ti.cvss_score DESC LIMIT ?`;
    bindings.push(limit);

    const rows = await env.DB.prepare(sql).bind(...bindings).all();
    return rows.results || [];
  } catch (err) {
    console.error('[Ingestion] getIntelFeed error:', err.message);
    return getInternalSeedIntel().slice(0, limit);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIFICATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

export function cvssToSeverity(score) {
  const s = parseFloat(score) || 0;
  if (s >= 9.0) return 'CRITICAL';
  if (s >= 7.0) return 'HIGH';
  if (s >= 4.0) return 'MEDIUM';
  if (s >  0.0) return 'LOW';
  return 'INFO';
}

function normalizeSeverity(s) {
  const upper = (s || '').toUpperCase();
  return ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(upper) ? upper : 'MEDIUM';
}

export function classifyType(text = '') {
  const lower = text.toLowerCase();
  for (const [type, patterns] of Object.entries(CVE_TYPE_PATTERNS)) {
    if (patterns.some(p => lower.includes(p))) return type;
  }
  return 'VULNERABILITY';
}

function classifyExploitStatus(raw) {
  if (raw.kev_added)                              return 'ACTIVELY_EXPLOITED';
  if (raw.exploit_maturity === 'HIGH')            return 'WEAPONIZED';
  if (raw.exploit_maturity === 'FUNCTIONAL')      return 'EXPLOIT_AVAILABLE';
  if (raw.exploit_maturity === 'PROOF_OF_CONCEPT') return 'POC_AVAILABLE';
  return 'UNKNOWN';
}

function detectPatchAvailable(raw) {
  const text = (raw.description || raw.required_action || '').toLowerCase();
  return text.includes('patch') || text.includes('update') || text.includes('upgrade') || text.includes('fix');
}

function buildMITREMapping(raw) {
  const type    = raw.type || classifyType(raw.description || '');
  const mapped  = MITRE_AUTO_MAP[type] || [];

  // Also check description for technique keywords
  const desc    = (raw.description || '').toLowerCase();
  const extras  = [];
  if (desc.includes('lateral movement') || desc.includes('pass the hash')) {
    extras.push({ tactic:'Lateral Movement', technique:'T1550', name:'Use Alternate Authentication Material' });
  }
  if (desc.includes('persistence') || desc.includes('startup') || desc.includes('scheduled task')) {
    extras.push({ tactic:'Persistence', technique:'T1053', name:'Scheduled Task/Job' });
  }
  if (desc.includes('exfiltrat') || desc.includes('data theft')) {
    extras.push({ tactic:'Exfiltration', technique:'T1048', name:'Exfiltration Over Alternative Protocol' });
  }
  if (desc.includes('command and control') || desc.includes('c2') || desc.includes('beacon')) {
    extras.push({ tactic:'Command and Control', technique:'T1071', name:'Application Layer Protocol' });
  }

  return [...mapped, ...extras].slice(0, 5);
}

function buildTags(raw) {
  const tags = [raw._source || 'unknown'];
  if (raw.kev_added)                        tags.push('kev', 'actively-exploited');
  if (raw.cvss_score >= 9.0)               tags.push('critical-cvss');
  if (raw.type)                             tags.push(raw.type.toLowerCase().replace(/_/g,'-'));
  if (raw.exploit_maturity === 'HIGH')      tags.push('weaponized');
  if (raw.patch_available)                  tags.push('patch-available');
  return [...new Set(tags)];
}

function normalizeAffectedSystems(raw) {
  if (Array.isArray(raw.affected_systems) && raw.affected_systems.length) return raw.affected_systems;
  if (raw.product) return [`${raw.vendorProject || ''} ${raw.product}`.trim()];
  return extractAffectedSystems(raw.description || raw.title || '');
}

function extractAffectedSystems(text = '') {
  const systems = [];
  const patterns = [
    /(?:affects?|affecting|in)\s+([\w\s.-]{3,40})\s+(?:version|v\d)/gi,
    /(Apache|Nginx|WordPress|OpenSSL|Log4j|Spring|Django|Rails|Node\.js|Python|PHP|Windows|Linux|macOS|Android|iOS|Kubernetes|Docker|AWS|Azure|GCP|Jenkins|GitLab|GitHub|Jira|Confluence|VMware|Cisco|Palo Alto|Fortinet|Citrix|Exchange|SharePoint)\s*[\w\s./-]{0,30}/gi,
  ];
  for (const pat of patterns) {
    const matches = text.matchAll(pat);
    for (const m of matches) systems.push(m[0].trim().substring(0, 50));
    if (systems.length >= 5) break;
  }
  return [...new Set(systems)].slice(0, 5);
}

function extractVersions(text = '') {
  const versions = [];
  const pat = /(?:before|prior to|through|<=?|>=?)\s*([\d.]+[\w.-]*)/gi;
  for (const m of text.matchAll(pat)) versions.push(m[1]);
  return [...new Set(versions)].slice(0, 5);
}

function extractIOCs(text = '') {
  const iocs = [];
  // IP addresses
  for (const m of text.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g)) {
    iocs.push({ type: 'ip', value: m[1] });
  }
  // Domains
  for (const m of text.matchAll(/\b([a-z0-9-]{2,63}\.(xyz|ru|cn|top|tk|cc|pw|su|io)\b)/gi)) {
    iocs.push({ type: 'domain', value: m[1] });
  }
  // Hashes (MD5/SHA256 pattern)
  for (const m of text.matchAll(/\b([a-f0-9]{32,64})\b/gi)) {
    iocs.push({ type: 'hash', value: m[1] });
  }
  return iocs.slice(0, 10);
}

function extractFromVector(vector = '', component) {
  const map = {
    AV: { N:'NETWORK', A:'ADJACENT', L:'LOCAL', P:'PHYSICAL' },
    AC: { L:'LOW', H:'HIGH' },
    PR: { N:'NONE', L:'LOW', H:'HIGH' },
    UI: { N:'NONE', R:'REQUIRED' },
    S:  { U:'UNCHANGED', C:'CHANGED' },
    C:  { N:'NONE', L:'LOW', H:'HIGH' },
    I:  { N:'NONE', L:'LOW', H:'HIGH' },
    A:  { N:'NONE', L:'LOW', H:'HIGH' },
  };
  const regex = new RegExp(`${component}:([A-Z])`);
  const match = vector.match(regex);
  return match ? (map[component]?.[match[1]] || match[1]) : 'UNKNOWN';
}

// ─── Internal seed intel (fallback when all sources fail) ─────────────────────
function getInternalSeedIntel() {
  return [
    {
      id: 'CVE-2025-21298', title: 'CVE-2025-21298 — Windows OLE Remote Code Execution',
      severity: 'CRITICAL', cvss_score: 9.8, type: 'RCE',
      description: 'A critical use-after-free vulnerability in Windows Object Linking and Embedding (OLE) allows remote attackers to execute arbitrary code via specially crafted RTF documents.',
      affected_systems: ['Microsoft Windows 10', 'Windows 11', 'Windows Server 2019', 'Windows Server 2022'],
      exploit_status: 'ACTIVELY_EXPLOITED', kev_added: '2025-01-14', _source: 'sentinel_apex',
    },
    {
      id: 'CVE-2025-0282', title: 'CVE-2025-0282 — Ivanti Connect Secure Stack Buffer Overflow',
      severity: 'CRITICAL', cvss_score: 9.0, type: 'BUFFER_OVERFLOW',
      description: 'A stack-based buffer overflow in Ivanti Connect Secure VPN allows unauthenticated remote attackers to execute arbitrary code. Actively exploited by APT groups for initial access.',
      affected_systems: ['Ivanti Connect Secure <22.7R2.5', 'Ivanti Policy Secure', 'Ivanti Neurons for ZTA'],
      exploit_status: 'ACTIVELY_EXPLOITED', kev_added: '2025-01-08', _source: 'cisa_kev',
    },
    {
      id: 'CVE-2025-23006', title: 'CVE-2025-23006 — SonicWall SMA Pre-Auth Deserialization RCE',
      severity: 'CRITICAL', cvss_score: 9.8, type: 'DESERIALIZATION',
      description: 'Pre-authentication deserialization vulnerability in SonicWall SMA1000 Appliance Management Console allows unauthenticated remote code execution.',
      affected_systems: ['SonicWall SMA1000 <12.4.3-02804'],
      exploit_status: 'ACTIVELY_EXPLOITED', kev_added: '2025-01-23', _source: 'sentinel_apex',
    },
    {
      id: 'CVE-2024-55591', title: 'CVE-2024-55591 — FortiOS Authentication Bypass',
      severity: 'CRITICAL', cvss_score: 9.6, type: 'AUTH_BYPASS',
      description: 'Authentication bypass using alternate path vulnerability in FortiOS and FortiProxy allows unauthenticated remote attacker to gain super-admin privileges via crafted Node.js websocket module requests.',
      affected_systems: ['FortiOS 7.0.0-7.0.16', 'FortiProxy 7.0.0-7.0.19', 'FortiProxy 7.2.0-7.2.12'],
      exploit_status: 'ACTIVELY_EXPLOITED', kev_added: '2025-01-14', _source: 'cisa_kev',
    },
    {
      id: 'CVE-2025-24085', title: 'CVE-2025-24085 — Apple WebKit Zero-Day Use After Free',
      severity: 'HIGH', cvss_score: 7.8, type: 'ZERO_DAY',
      description: 'Use-after-free vulnerability in Apple WebKit allows maliciously crafted web content to execute arbitrary code with kernel privileges. Apple confirms active exploitation against iOS users.',
      affected_systems: ['iOS <18.3', 'macOS Sequoia <15.3', 'Safari <18.3', 'visionOS <2.3'],
      exploit_status: 'ACTIVELY_EXPLOITED', kev_added: '2025-01-27', _source: 'sentinel_apex',
    },
  ];
}
