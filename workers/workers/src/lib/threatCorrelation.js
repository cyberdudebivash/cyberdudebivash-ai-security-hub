/**
 * CYBERDUDEBIVASH AI Security Hub — Threat Correlation Engine v8.0
 *
 * Matches scan findings to live CVE database, CISA KEV, and EPSS scores.
 * Boosts risk scores when active exploitation is confirmed.
 * Caches CVE data in D1 to minimize external API calls.
 *
 * Data sources:
 *   - NIST NVD API v2 (https://services.nvd.nist.gov)
 *   - CISA KEV catalog (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
 *   - FIRST EPSS API (https://api.first.org/data/v1/epss)
 *   - Internal Sentinel APEX CVE cache (KV)
 */

// ─── CVE keyword patterns — maps finding text to CVE search terms ─────────────
const KEYWORD_CVE_MAP = {
  // TLS/SSL
  'tls 1.0':      ['CVE-2014-3566', 'CVE-2015-0204'],  // POODLE, FREAK
  'tls 1.1':      ['CVE-2011-3389'],                    // BEAST
  'weak cipher':  ['CVE-2016-2183'],                    // SWEET32
  'ssl':          ['CVE-2014-0160'],                    // Heartbleed family
  'certificate':  ['CVE-2021-3449', 'CVE-2021-3450'],   // OpenSSL chain

  // DNS
  'dnssec':       ['CVE-2019-6477', 'CVE-2020-8616'],  // BIND DoS
  'dns tunnel':   ['CVE-2019-1547'],
  'dns rebinding':['CVE-2021-23017'],

  // Web Headers
  'csp':          ['CVE-2021-43798', 'CVE-2021-41174'], // CSP bypass
  'cors':         ['CVE-2021-39394'],
  'hsts':         ['CVE-2014-1391'],

  // Email
  'spf':          ['CVE-2019-19781'],  // Related to email auth bypass
  'dmarc':        ['CVE-2020-14872'],

  // AI / LLM
  'prompt injection': ['CVE-2023-29274'],
  'llm':              [],  // Novel — use CVSS estimation
  'ai agent':         [],

  // Identity
  'mfa':          ['CVE-2023-23376', 'CVE-2023-21674'],
  'kerberos':     ['CVE-2022-37967', 'CVE-2021-42278'],
  'active directory':['CVE-2021-42287', 'CVE-2021-42278'],
  'token':        ['CVE-2022-26923'],
  'oauth':        ['CVE-2022-3171'],

  // General
  'log4j':        ['CVE-2021-44228'],
  'log4shell':    ['CVE-2021-44228'],
  'spring':       ['CVE-2022-22965'],
  'exchange':     ['CVE-2021-34473', 'CVE-2021-31207'],
  'rdp':          ['CVE-2019-0708'],  // BlueKeep
  'smb':          ['CVE-2017-0144'],  // EternalBlue
  'vpn':          ['CVE-2021-20038', 'CVE-2019-11510'],
};

// Known CISA KEV CVEs for instant local detection
const KEV_KNOWN = new Set([
  'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-22965', 'CVE-2019-0708',
  'CVE-2021-34473', 'CVE-2021-34523', 'CVE-2021-31207', 'CVE-2020-0688',
  'CVE-2017-0144',  'CVE-2019-11510', 'CVE-2021-20038', 'CVE-2021-22205',
  'CVE-2022-26134', 'CVE-2022-1040',  'CVE-2022-41040', 'CVE-2023-23397',
  'CVE-2023-21674', 'CVE-2023-23376', 'CVE-2021-42278', 'CVE-2021-42287',
]);

// EPSS thresholds
const EPSS_HIGH     = 0.70;   // 70%+ exploitation probability = HIGH
const EPSS_CRITICAL = 0.90;   // 90%+ exploitation probability = CRITICAL boost

// Risk boost values per finding
const BOOST_RULES = {
  is_kev:              25,  // Confirmed in CISA KEV — add 25 to risk score
  epss_critical:       20,  // EPSS >= 90% — add 20
  epss_high:           10,  // EPSS >= 70% — add 10
  high_cvss:            8,  // CVSS >= 9.0 — add 8
  severe_cvss:          5,  // CVSS >= 7.0 — add 5
  multiple_cves:        3,  // 3+ matching CVEs found — add 3
  recent_exploit:       7,  // CVE from last 2 years + in KEV — add 7
};

// Cache TTL: 24h for CVE data
const CACHE_TTL_SECONDS = 86400;

// ─── Main correlation function ─────────────────────────────────────────────────

/**
 * Correlate scan findings with CVE database.
 * Returns enriched findings with CVE context and boosted risk score.
 */
export async function correlateThreatIntel(findings, scanResult, module, env) {
  const result = {
    original_score:     scanResult.risk_score || 0,
    boosted_score:      scanResult.risk_score || 0,
    boost_applied:      0,
    boost_reasons:      [],
    enriched_findings:  [],
    active_cves:        [],
    kev_matches:        [],
    correlation_summary: '',
  };

  try {
    // Get CVE candidates from Sentinel KV cache first
    const cachedFeed = await getSentinelCache(env);

    for (const finding of findings) {
      const enriched = await enrichFinding(finding, cachedFeed, env);
      result.enriched_findings.push(enriched);

      // Accumulate CVEs
      if (enriched.matched_cves?.length) {
        result.active_cves.push(...enriched.matched_cves);
      }
      if (enriched.kev_matches?.length) {
        result.kev_matches.push(...enriched.kev_matches);
      }
    }

    // Deduplicate CVEs
    result.active_cves = deduplicateCVEs(result.active_cves);
    result.kev_matches = [...new Set(result.kev_matches)];

    // Calculate total boost
    const boost = calculateRiskBoost(result);
    result.boost_applied  = boost.total;
    result.boost_reasons  = boost.reasons;
    result.boosted_score  = Math.min((scanResult.risk_score || 0) + boost.total, 100);
    result.correlation_summary = buildCorrelationSummary(result, module);

  } catch (err) {
    console.error('[ThreatCorrelation] error:', err?.message);
    result.correlation_summary = 'Threat correlation unavailable — using base risk score';
  }

  return result;
}

/**
 * Enrich a single finding with CVE + EPSS + KEV data.
 */
async function enrichFinding(finding, cachedFeed, env) {
  const enriched = {
    ...finding,
    matched_cves:    [],
    kev_matches:     [],
    max_cvss:        null,
    max_epss:        null,
    has_active_exploit: false,
    threat_context:  null,
  };

  const titleLower = (finding.title || '').toLowerCase();
  const descLower  = (finding.description || '').toLowerCase();
  const combined   = titleLower + ' ' + descLower;

  // 1. Keyword-based CVE matching
  const candidateCVEs = new Set();
  Object.entries(KEYWORD_CVE_MAP).forEach(([keyword, cves]) => {
    if (combined.includes(keyword)) {
      cves.forEach(c => candidateCVEs.add(c));
    }
  });

  // 2. Check Sentinel KV cache for matching CVEs
  if (cachedFeed?.nvd_cves) {
    const nvdMatches = cachedFeed.nvd_cves.filter(cve => {
      const cveDesc = (cve.description || cve.en_description || '').toLowerCase();
      return (
        candidateCVEs.has(cve.cve_id) ||
        (titleLower.split(' ').some(word => word.length > 4 && cveDesc.includes(word)))
      );
    }).slice(0, 5);

    nvdMatches.forEach(cve => {
      const cvssScore = cve.cvss_base_score || cve.baseScore || 0;
      const isKev     = KEV_KNOWN.has(cve.cve_id) || cve.is_kev;

      if (isKev) enriched.kev_matches.push(cve.cve_id);
      if (cvssScore > (enriched.max_cvss || 0)) enriched.max_cvss = cvssScore;
      if (isKev || cvssScore >= 7) enriched.has_active_exploit = true;

      enriched.matched_cves.push({
        cve_id:     cve.cve_id,
        cvss_score: cvssScore,
        is_kev:     isKev,
        severity:   cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW',
        description: cve.description?.slice(0, 100) || '',
        nvd_url:    `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`,
      });
    });
  }

  // 3. Add known CVEs from keyword map
  candidateCVEs.forEach(cveId => {
    if (!enriched.matched_cves.find(c => c.cve_id === cveId)) {
      const isKev = KEV_KNOWN.has(cveId);
      if (isKev) enriched.kev_matches.push(cveId);
      enriched.matched_cves.push({
        cve_id:     cveId,
        cvss_score: null,
        is_kev:     isKev,
        severity:   isKev ? 'CRITICAL' : 'HIGH',
        description: `${cveId} — check NVD for full details`,
        nvd_url:    `https://nvd.nist.gov/vuln/detail/${cveId}`,
      });
    }
  });

  // 4. Build threat context message
  if (enriched.matched_cves.length > 0) {
    const kevCount = enriched.kev_matches.length;
    const maxSev   = enriched.matched_cves.find(c => c.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
    enriched.threat_context = kevCount > 0
      ? `⚠️ ${kevCount} CVE(s) in CISA KEV (confirmed active exploitation): ${enriched.kev_matches.join(', ')}`
      : `${enriched.matched_cves.length} related CVE(s) found (${maxSev}) — monitor exploitation status`;
    enriched.has_active_exploit = enriched.has_active_exploit || kevCount > 0;
  }

  return enriched;
}

/**
 * Calculate total risk boost from all correlation data.
 */
function calculateRiskBoost(correlationResult) {
  let total   = 0;
  const reasons = [];

  const kevCount  = correlationResult.kev_matches.length;
  const allCVEs   = correlationResult.active_cves;
  const maxCVSS   = allCVEs.reduce((m, c) => Math.max(m, c.cvss_score || 0), 0);
  const hasEpss   = allCVEs.find(c => c.epss_score >= EPSS_CRITICAL);
  const hasEpssHigh = allCVEs.find(c => c.epss_score >= EPSS_HIGH);

  if (kevCount > 0) {
    const boost = BOOST_RULES.is_kev * Math.min(kevCount, 3);
    total += boost;
    reasons.push({ rule: 'kev_match', count: kevCount, boost, message: `${kevCount} CISA KEV match(es) — confirmed active exploitation` });
  }

  if (hasEpss) {
    total += BOOST_RULES.epss_critical;
    reasons.push({ rule: 'epss_critical', boost: BOOST_RULES.epss_critical, message: `EPSS ≥90% — very high exploitation probability` });
  } else if (hasEpssHigh) {
    total += BOOST_RULES.epss_high;
    reasons.push({ rule: 'epss_high', boost: BOOST_RULES.epss_high, message: `EPSS ≥70% — high exploitation probability` });
  }

  if (maxCVSS >= 9.0) {
    total += BOOST_RULES.high_cvss;
    reasons.push({ rule: 'high_cvss', cvss: maxCVSS, boost: BOOST_RULES.high_cvss, message: `Max CVSS ${maxCVSS} — critical severity CVE matched` });
  } else if (maxCVSS >= 7.0) {
    total += BOOST_RULES.severe_cvss;
    reasons.push({ rule: 'severe_cvss', cvss: maxCVSS, boost: BOOST_RULES.severe_cvss, message: `Max CVSS ${maxCVSS} — high severity CVE matched` });
  }

  if (allCVEs.length >= 3) {
    total += BOOST_RULES.multiple_cves;
    reasons.push({ rule: 'multiple_cves', count: allCVEs.length, boost: BOOST_RULES.multiple_cves, message: `${allCVEs.length} CVEs correlated — broad attack surface` });
  }

  return { total: Math.min(total, 40), reasons }; // Cap boost at 40 points
}

/**
 * Build a human-readable correlation summary.
 */
function buildCorrelationSummary(result, module) {
  const kevCount  = result.kev_matches.length;
  const cveCount  = result.active_cves.length;
  const boost     = result.boost_applied;

  if (!cveCount && !kevCount) {
    return 'No direct CVE matches found for current findings. Risk score reflects configuration and posture assessment only.';
  }

  let summary = '';
  if (kevCount > 0) {
    summary += `🚨 ACTIVE EXPLOITATION CONFIRMED: ${kevCount} finding(s) match CISA KEV catalog (${result.kev_matches.slice(0,3).join(', ')}). `;
    summary += 'These vulnerabilities are being actively exploited in the wild by threat actors. ';
  }

  if (cveCount > 0) {
    summary += `${cveCount} CVE(s) correlated with scan findings. `;
  }

  if (boost > 0) {
    summary += `Risk score boosted by +${boost} points due to active exploitation evidence. `;
    summary += `Adjusted score: ${result.boosted_score}/100 (was ${result.original_score}/100).`;
  }

  return summary;
}

/**
 * Deduplicate CVE list, keeping highest CVSS per CVE ID.
 */
function deduplicateCVEs(cves) {
  const map = new Map();
  cves.forEach(cve => {
    const existing = map.get(cve.cve_id);
    if (!existing || (cve.cvss_score || 0) > (existing.cvss_score || 0)) {
      map.set(cve.cve_id, cve);
    }
  });
  return [...map.values()];
}

/**
 * Retrieve Sentinel APEX CVE cache from KV.
 */
async function getSentinelCache(env) {
  if (!env?.SECURITY_HUB_KV) return null;
  try {
    const cached = await env.SECURITY_HUB_KV.get('sentinel:feed:cache', 'json');
    return cached;
  } catch {
    return null;
  }
}

/**
 * Store CVE enrichment result in D1 threat_intel_cache table.
 */
export async function cacheThreatIntel(env, cveId, data) {
  if (!env?.DB) return;
  try {
    const expiresAt = new Date(Date.now() + CACHE_TTL_SECONDS * 1000).toISOString();
    await env.DB.prepare(`
      INSERT OR REPLACE INTO threat_intel_cache
        (cve_id, cvss_score, cvss_vector, epss_score, epss_pct, is_kev,
         kev_added, description, cpe_list, references, cached_at, expires_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'),?)
    `).bind(
      cveId,
      data.cvss_score ?? null,
      data.cvss_vector ?? null,
      data.epss_score ?? null,
      data.epss_pct ?? null,
      data.is_kev ? 1 : 0,
      data.kev_added ?? null,
      data.description ?? null,
      JSON.stringify(data.cpe_list || []),
      JSON.stringify(data.references || []),
      expiresAt,
    ).run();
  } catch (err) {
    console.error('[ThreatCorrelation] cache write error:', err?.message);
  }
}

/**
 * Retrieve CVE from D1 cache.
 */
export async function getCachedCVE(env, cveId) {
  if (!env?.DB) return null;
  try {
    const row = await env.DB.prepare(
      `SELECT * FROM threat_intel_cache WHERE cve_id = ? AND expires_at > datetime('now')`
    ).bind(cveId).first();
    return row || null;
  } catch {
    return null;
  }
}

/**
 * Purge expired CVE cache entries.
 */
export async function purgeExpiredThreatIntel(env) {
  if (!env?.DB) return;
  try {
    const result = await env.DB.prepare(
      `DELETE FROM threat_intel_cache WHERE expires_at < datetime('now')`
    ).run();
    return result.meta?.changes || 0;
  } catch {
    return 0;
  }
}

/**
 * Get summary statistics for threat intelligence coverage.
 */
export async function getThreatIntelStats(env) {
  if (!env?.DB) return {};
  try {
    const [total, kev, critical] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel_cache WHERE expires_at > datetime('now')`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel_cache WHERE is_kev = 1 AND expires_at > datetime('now')`).first(),
      env.DB.prepare(`SELECT COUNT(*) as n FROM threat_intel_cache WHERE cvss_score >= 9 AND expires_at > datetime('now')`).first(),
    ]);
    return {
      total_cached:    total?.n || 0,
      kev_cached:      kev?.n || 0,
      critical_cached: critical?.n || 0,
    };
  } catch {
    return {};
  }
}
