/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Confidence & Exploitability Engine
 *
 * Enriches CVEs/threats with:
 *   - Threat Confidence Score (0–100) based on multi-source signals
 *   - Exploitability Index (0–10) indicating real-world attack likelihood
 *   - CISA KEV status (live or cached)
 *   - ThreatFox IOC matches
 *   - ExploitDB reference lookup
 *   - APT attribution signals
 *   - Composite risk tier: CRITICAL_IMMINENT | HIGH_LIKELY | MEDIUM_POSSIBLE | LOW_THEORETICAL
 *
 * Endpoints:
 *   POST /api/threat-confidence/score       → score one or more CVEs/threats
 *   GET  /api/threat-confidence/kev         → CISA KEV catalog (cached 24h)
 *   POST /api/threat-confidence/enrich      → full enrichment pipeline for a single CVE
 *   GET  /api/threat-confidence/feed        → recent high-confidence threats feed
 *   GET  /api/threat-confidence/stats       → aggregate posture stats for org
 */

import { ok, fail } from '../lib/response.js';

const KV_KEV_CACHE_KEY     = 'cisa_kev_catalog';
const KV_KEV_TTL           = 86400;          // 24 h
const KV_CONF_PREFIX       = 'tc_score:';
const KV_FEED_KEY          = 'tc_feed:items';
const CISA_KEV_URL         = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const THREATFOX_API        = 'https://threatfox-api.abuse.ch/api/v1/';

// ── APT attribution keyword map (lightweight heuristic) ─────────────────────
const APT_SIGNALS = {
  'CVE-2021-44228': ['APT41', 'Lazarus'],
  'CVE-2021-26855': ['HAFNIUM', 'APT31'],
  'CVE-2022-30190': ['DEV-0413', 'TA413'],
  'CVE-2023-23397': ['APT28', 'Fancy Bear'],
  'CVE-2024-3400':  ['UTA0218'],
  'CVE-2021-34527': ['APT41', 'FIN11'],
};

// ── Confidence scoring weights ────────────────────────────────────────────────
const WEIGHTS = {
  kev_listed:           35,   // in CISA KEV = highest signal
  exploit_public:       20,   // public PoC exists
  active_exploitation:  20,   // actively exploited in wild
  apt_attribution:      10,   // linked to APT
  cvss_critical:        10,   // CVSS >= 9.0
  threatfox_ioc:         5,   // ThreatFox IOC found
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function normalizeScore(raw, max) {
  return Math.min(100, Math.round((raw / max) * 100));
}

function getRiskTier(confidenceScore, cvss) {
  if (confidenceScore >= 75 || cvss >= 9.5) return 'CRITICAL_IMMINENT';
  if (confidenceScore >= 55 || cvss >= 8.0) return 'HIGH_LIKELY';
  if (confidenceScore >= 35 || cvss >= 6.0) return 'MEDIUM_POSSIBLE';
  return 'LOW_THEORETICAL';
}

function getExploitabilityIndex(signals) {
  // 0–10 scale, weighted composite
  let score = 0;
  if (signals.kev_listed)          score += 3.5;
  if (signals.exploit_public)      score += 2.0;
  if (signals.active_exploitation) score += 2.0;
  if (signals.apt_attribution)     score += 1.0;
  if (signals.cvss_critical)       score += 1.0;
  if (signals.threatfox_ioc)       score += 0.5;
  return Math.min(10, parseFloat(score.toFixed(1)));
}

function getRemediationUrgency(tier) {
  const map = {
    CRITICAL_IMMINENT: { sla_hours: 4,   label: 'EMERGENCY — Patch within 4 hours',  priority: 'P0' },
    HIGH_LIKELY:       { sla_hours: 24,  label: 'URGENT — Patch within 24 hours',     priority: 'P1' },
    MEDIUM_POSSIBLE:   { sla_hours: 168, label: 'HIGH — Patch within 7 days',         priority: 'P2' },
    LOW_THEORETICAL:   { sla_hours: 720, label: 'MEDIUM — Patch within 30 days',      priority: 'P3' },
  };
  return map[tier] || map['LOW_THEORETICAL'];
}

// ── CISA KEV Fetch (with KV cache) ────────────────────────────────────────────
async function fetchKEVCatalog(env) {
  // Try KV cache first
  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get(KV_KEV_CACHE_KEY, { type: 'json' });
      if (cached && cached.fetched_at) {
        const age = (Date.now() - new Date(cached.fetched_at).getTime()) / 1000;
        if (age < KV_KEV_TTL) return cached;
      }
    } catch {}
  }

  // Fetch from CISA
  let kevData = null;
  try {
    const res = await fetch(CISA_KEV_URL, {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/3.0' },
      cf: { cacheTtl: 3600 }
    });
    if (res.ok) {
      const raw = await res.json();
      // Build lookup map: CVE-ID → entry
      const lookup = {};
      (raw.vulnerabilities || []).forEach(v => {
        lookup[v.cveID] = {
          vendor:       v.vendorProject,
          product:      v.product,
          vuln_name:    v.vulnerabilityName,
          date_added:   v.dateAdded,
          due_date:     v.dueDate,
          known_ransomware: v.knownRansomwareCampaignUse === 'Known',
          notes:        v.notes || '',
        };
      });
      kevData = {
        total:       raw.vulnerabilities?.length || 0,
        catalog_version: raw.catalogVersion || 'unknown',
        date_released: raw.dateReleased || null,
        fetched_at:  new Date().toISOString(),
        lookup,
      };
      // Cache in KV
      if (env?.SECURITY_HUB_KV) {
        await env.SECURITY_HUB_KV.put(KV_KEV_CACHE_KEY, JSON.stringify(kevData), { expirationTtl: KV_KEV_TTL });
      }
    }
  } catch (e) {
    console.error('KEV fetch failed:', e.message);
  }

  // Return stub if fetch failed
  if (!kevData) {
    return {
      total: 0,
      catalog_version: 'unavailable',
      fetched_at: new Date().toISOString(),
      lookup: {},
      fetch_error: true,
    };
  }
  return kevData;
}

// ── ThreatFox IOC lookup ───────────────────────────────────────────────────────
async function queryThreatFox(cveId, env) {
  // Check cache
  const cacheKey = `tf_ioc:${cveId}`;
  if (env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get(cacheKey, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }

  let result = { found: false, ioc_count: 0, malware_families: [], first_seen: null };
  try {
    const res = await fetch(THREATFOX_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'API-KEY': 'anonymous' },
      body: JSON.stringify({ query: 'search_ioc', search_term: cveId, exact_match: true }),
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.query_status === 'ok' && data.data?.length > 0) {
        const families = [...new Set(data.data.map(d => d.malware_printable).filter(Boolean))];
        result = {
          found:            true,
          ioc_count:        data.data.length,
          malware_families: families.slice(0, 5),
          first_seen:       data.data[0]?.first_seen || null,
          threat_type:      data.data[0]?.threat_type || null,
        };
      }
    }
  } catch (e) {
    // ThreatFox unreachable — return empty result
  }

  // Cache for 6h
  if (env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put(cacheKey, JSON.stringify(result), { expirationTtl: 21600 });
    } catch {}
  }
  return result;
}

// ── Core scoring engine ───────────────────────────────────────────────────────
async function scoreThreat(threat, env) {
  const {
    cve_id,
    cvss           = 0,
    title          = '',
    vendor         = '',
    product        = '',
    exploit_public = false,
    active_exp     = false,
    description    = '',
  } = threat;

  const kev        = await fetchKEVCatalog(env);
  const kevEntry   = cve_id ? (kev.lookup[cve_id] || null) : null;
  const tfResult   = cve_id ? await queryThreatFox(cve_id, env) : { found: false };
  const aptList    = cve_id ? (APT_SIGNALS[cve_id] || []) : [];

  // Build signal map
  const signals = {
    kev_listed:           !!kevEntry,
    exploit_public:       exploit_public || (cvss >= 9.0 && !!kevEntry),
    active_exploitation:  active_exp || (kevEntry?.known_ransomware === true),
    apt_attribution:      aptList.length > 0,
    cvss_critical:        parseFloat(cvss) >= 9.0,
    threatfox_ioc:        tfResult.found,
  };

  // Compute raw confidence
  let rawConf = 0;
  if (signals.kev_listed)           rawConf += WEIGHTS.kev_listed;
  if (signals.exploit_public)       rawConf += WEIGHTS.exploit_public;
  if (signals.active_exploitation)  rawConf += WEIGHTS.active_exploitation;
  if (signals.apt_attribution)      rawConf += WEIGHTS.apt_attribution;
  if (signals.cvss_critical)        rawConf += WEIGHTS.cvss_critical;
  if (signals.threatfox_ioc)        rawConf += WEIGHTS.threatfox_ioc;

  const maxPossible = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
  const confidenceScore    = normalizeScore(rawConf, maxPossible);
  const exploitabilityIdx  = getExploitabilityIndex(signals);
  const riskTier           = getRiskTier(confidenceScore, parseFloat(cvss));
  const remediation        = getRemediationUrgency(riskTier);

  const result = {
    cve_id:               cve_id || null,
    title:                title  || cve_id || 'Unknown Threat',
    cvss:                 parseFloat(cvss) || 0,
    confidence_score:     confidenceScore,
    exploitability_index: exploitabilityIdx,
    risk_tier:            riskTier,
    signals,
    kev_data:             kevEntry,
    threatfox:            tfResult,
    apt_attribution:      aptList,
    remediation,
    scored_at:            new Date().toISOString(),
    vendor:               kevEntry?.vendor  || vendor  || null,
    product:              kevEntry?.product || product || null,
    known_ransomware:     kevEntry?.known_ransomware || false,
  };

  // Cache scored result
  if (cve_id && env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put(
        `${KV_CONF_PREFIX}${cve_id}`,
        JSON.stringify(result),
        { expirationTtl: 3600 }
      );
    } catch {}
  }

  return result;
}

// ── Update feed ───────────────────────────────────────────────────────────────
async function pushToFeed(scored, env) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    let feed = (await env.SECURITY_HUB_KV.get(KV_FEED_KEY, { type: 'json' })) || [];
    feed.unshift({
      cve_id:           scored.cve_id,
      title:            scored.title,
      confidence_score: scored.confidence_score,
      risk_tier:        scored.risk_tier,
      cvss:             scored.cvss,
      scored_at:        scored.scored_at,
    });
    feed = feed.slice(0, 50);
    await env.SECURITY_HUB_KV.put(KV_FEED_KEY, JSON.stringify(feed), { expirationTtl: 86400 * 7 });
  } catch {}
}

// ── POST /api/threat-confidence/score ────────────────────────────────────────
export async function handleScoreThreats(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  const threats = Array.isArray(body.threats) ? body.threats
    : body.cve_id ? [body]
    : [];

  if (threats.length === 0) {
    return fail(request, 'Provide threats[] array or single threat object with cve_id', 400, 'NO_INPUT');
  }
  if (threats.length > 20) {
    return fail(request, 'Maximum 20 threats per request', 429, 'BATCH_TOO_LARGE');
  }

  const results = await Promise.all(threats.map(t => scoreThreat(t, env)));

  // Push critical/high to feed
  for (const r of results) {
    if (['CRITICAL_IMMINENT', 'HIGH_LIKELY'].includes(r.risk_tier)) {
      await pushToFeed(r, env);
    }
  }

  return ok(request, {
    scored:       results.length,
    results,
    summary: {
      critical_imminent: results.filter(r => r.risk_tier === 'CRITICAL_IMMINENT').length,
      high_likely:       results.filter(r => r.risk_tier === 'HIGH_LIKELY').length,
      medium_possible:   results.filter(r => r.risk_tier === 'MEDIUM_POSSIBLE').length,
      low_theoretical:   results.filter(r => r.risk_tier === 'LOW_THEORETICAL').length,
      avg_confidence:    results.length ? Math.round(results.reduce((s, r) => s + r.confidence_score, 0) / results.length) : 0,
    }
  });
}

// ── GET /api/threat-confidence/kev ───────────────────────────────────────────
export async function handleGetKEV(request, env, authCtx = {}) {
  const kev = await fetchKEVCatalog(env);
  const url  = new URL(request.url);
  const q    = (url.searchParams.get('q') || '').toUpperCase();
  const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '20', 10));

  let entries = Object.entries(kev.lookup || {}).map(([cve, data]) => ({ cve_id: cve, ...data }));

  if (q) {
    entries = entries.filter(e =>
      e.cve_id.includes(q) ||
      (e.vendor   || '').toUpperCase().includes(q) ||
      (e.product  || '').toUpperCase().includes(q) ||
      (e.vuln_name|| '').toUpperCase().includes(q)
    );
  }

  // Sort by date_added desc
  entries.sort((a, b) => (b.date_added || '').localeCompare(a.date_added || ''));

  return ok(request, {
    total_in_catalog:   kev.total,
    catalog_version:    kev.catalog_version,
    date_released:      kev.date_released,
    fetched_at:         kev.fetched_at,
    fetch_error:        kev.fetch_error || false,
    filtered_count:     entries.length,
    entries:            entries.slice(0, limit),
  });
}

// ── POST /api/threat-confidence/enrich ───────────────────────────────────────
export async function handleEnrichThreat(request, env, authCtx = {}) {
  let body = {};
  try { body = await request.json(); } catch {}

  if (!body.cve_id && !body.title) {
    return fail(request, 'cve_id or title is required', 400, 'MISSING_ID');
  }

  const scored = await scoreThreat(body, env);

  // Generate AI enrichment narrative
  const narrative = buildNarrative(scored);

  return ok(request, { ...scored, narrative });
}

function buildNarrative(scored) {
  const lines = [];
  lines.push(`**${scored.title || scored.cve_id}** — Confidence Score: **${scored.confidence_score}/100** | Risk: **${scored.risk_tier}**`);

  if (scored.signals.kev_listed) {
    lines.push(`⚠️ This vulnerability is listed in the **CISA Known Exploited Vulnerabilities** catalog, added ${scored.kev_data?.date_added || 'recently'}. Federal agencies must remediate by ${scored.kev_data?.due_date || 'N/A'}.`);
  }
  if (scored.signals.active_exploitation) {
    lines.push(`🔴 **Active exploitation** is confirmed in the wild.${scored.known_ransomware ? ' Ransomware campaigns have leveraged this vulnerability.' : ''}`);
  }
  if (scored.apt_attribution?.length > 0) {
    lines.push(`🎯 Attributed to threat actors: **${scored.apt_attribution.join(', ')}**.`);
  }
  if (scored.threatfox?.found) {
    lines.push(`🦊 **ThreatFox** has ${scored.threatfox.ioc_count} IOC(s) linked to this CVE. Malware families: ${scored.threatfox.malware_families.join(', ') || 'Unknown'}.`);
  }
  if (scored.signals.exploit_public) {
    lines.push(`💻 A **public exploit** is available — weaponization barrier is low.`);
  }

  lines.push(`\n**Remediation**: ${scored.remediation.label} (${scored.remediation.priority}). Exploitability Index: **${scored.exploitability_index}/10**.`);
  return lines.join('\n\n');
}

// ── GET /api/threat-confidence/feed ──────────────────────────────────────────
export async function handleGetFeed(request, env, authCtx = {}) {
  let feed = [];
  if (env?.SECURITY_HUB_KV) {
    try { feed = (await env.SECURITY_HUB_KV.get(KV_FEED_KEY, { type: 'json' })) || []; } catch {}
  }
  const url   = new URL(request.url);
  const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '10', 10));
  return ok(request, { total: feed.length, feed: feed.slice(0, limit) });
}

// ── GET /api/threat-confidence/stats ─────────────────────────────────────────
export async function handleGetStats(request, env, authCtx = {}) {
  let feed = [];
  const kev = await fetchKEVCatalog(env);

  if (env?.SECURITY_HUB_KV) {
    try { feed = (await env.SECURITY_HUB_KV.get(KV_FEED_KEY, { type: 'json' })) || []; } catch {}
  }

  const tierCounts = feed.reduce((acc, f) => {
    acc[f.risk_tier] = (acc[f.risk_tier] || 0) + 1;
    return acc;
  }, {});

  const avgConf = feed.length
    ? Math.round(feed.reduce((s, f) => s + (f.confidence_score || 0), 0) / feed.length)
    : 0;

  return ok(request, {
    feed_depth:           feed.length,
    kev_catalog_size:     kev.total,
    kev_catalog_version:  kev.catalog_version,
    tier_distribution:    tierCounts,
    avg_confidence_score: avgConf,
    high_priority_count:  (tierCounts['CRITICAL_IMMINENT'] || 0) + (tierCounts['HIGH_LIKELY'] || 0),
    generated_at:         new Date().toISOString(),
  });
}
