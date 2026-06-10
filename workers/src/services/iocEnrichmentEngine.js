/**
 * CYBERDUDEBIVASH AI Security Hub — IOC Enrichment Engine v1.0
 * ─────────────────────────────────────────────────────────────
 * Multi-source IOC reputation lookup with D1 caching.
 *
 * Sources (all free / key-optional):
 *   1. Internal: cross-reference threat_intel table
 *   2. AbuseIPDB: IP reputation  (env.ABUSEIPDB_API_KEY — optional)
 *   3. VirusTotal: hash/domain/IP/URL (env.VIRUSTOTAL_API_KEY — optional)
 *   4. Shodan InternetDB: IP open ports/vulns (free, no key)
 *   5. DNSBL: DNS blacklist checks for IPs
 *   6. DNS resolution: domain → IP + reverse lookup
 *
 * All results cached in D1 ioc_enrichment_cache for 24h (IPs) / 6h (domains).
 */

const CACHE_TTL = {
  ip:     86400,  // 24h
  domain: 21600,  // 6h
  hash:   604800, // 7 days
  email:  21600,  // 6h
  url:    21600,  // 6h
};

const SAFE_FETCH_TIMEOUT = 8000;

// ─── Utility ─────────────────────────────────────────────────────────────────
async function safeFetch(url, opts = {}) {
  try {
    const res = await fetch(url, {
      ...opts,
      signal: AbortSignal.timeout(SAFE_FETCH_TIMEOUT),
    });
    if (!res.ok) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('json')) return await res.json();
    return await res.text();
  } catch { return null; }
}

function sha256Hex(str) {
  // Simple hash for cache key (deterministic, not cryptographic)
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return 'ioc_' + Math.abs(hash).toString(36) + '_' + str.length;
}

function isValidIP(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) ||
         /^[0-9a-f:]{7,39}$/i.test(value);
}

function isValidDomain(value) {
  return /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i.test(value);
}

function isValidHash(value) {
  return /^[a-f0-9]{32}$/i.test(value) ||  // MD5
         /^[a-f0-9]{40}$/i.test(value) ||  // SHA1
         /^[a-f0-9]{64}$/i.test(value);    // SHA256
}

function detectType(value) {
  if (isValidIP(value))     return 'ip';
  if (isValidHash(value))   return 'hash';
  if (value.includes('@'))  return 'email';
  if (value.startsWith('http')) return 'url';
  if (isValidDomain(value)) return 'domain';
  return 'unknown';
}

// ─── Source 1: Internal threat_intel cross-reference ─────────────────────────
async function checkInternalThreatIntel(env, value) {
  if (!env.DB) return { hits: 0, details: [] };
  try {
    const rows = await env.DB.prepare(`
      SELECT id, title, severity, exploit_status, tags, source
      FROM threat_intel
      WHERE iocs LIKE ? OR ioc_list LIKE ?
      LIMIT 5
    `).bind(`%${value}%`, `%${value}%`).all();

    const results = rows.results || [];
    return {
      hits: results.length,
      details: results.map(r => ({
        cve: r.id,
        title: r.title,
        severity: r.severity,
        exploit_status: r.exploit_status,
      })),
    };
  } catch { return { hits: 0, details: [] }; }
}

// ─── Source 2: AbuseIPDB ──────────────────────────────────────────────────────
async function checkAbuseIPDB(env, ip) {
  const apiKey = env.ABUSEIPDB_API_KEY;
  if (!apiKey) return null;

  const data = await safeFetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
    { headers: { Key: apiKey, Accept: 'application/json' } }
  );
  if (!data?.data) return null;

  const d = data.data;
  return {
    confidence_score: d.abuseConfidenceScore,
    total_reports:    d.totalReports,
    last_reported:    d.lastReportedAt,
    country:          d.countryCode,
    isp:              d.isp,
    domain:           d.domain,
    is_whitelisted:   d.isWhitelisted,
    usage_type:       d.usageType,
    categories:       d.reports?.slice(0, 3).map(r => r.categories).flat() || [],
  };
}

// ─── Source 3: VirusTotal (free tier: 4 req/min) ─────────────────────────────
async function checkVirusTotal(env, value, type) {
  const apiKey = env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;

  let url;
  if (type === 'ip')     url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
  else if (type === 'domain') url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
  else if (type === 'hash')   url = `https://www.virustotal.com/api/v3/files/${value}`;
  else if (type === 'url') {
    const id = btoa(value).replace(/=/g, '');
    url = `https://www.virustotal.com/api/v3/urls/${id}`;
  }
  else return null;

  const data = await safeFetch(url, { headers: { 'x-apikey': apiKey } });
  if (!data?.data?.attributes) return null;

  const attrs = data.data.attributes;
  const stats = attrs.last_analysis_stats || {};
  return {
    malicious:     stats.malicious || 0,
    suspicious:    stats.suspicious || 0,
    undetected:    stats.undetected || 0,
    harmless:      stats.harmless || 0,
    reputation:    attrs.reputation || 0,
    tags:          attrs.tags || [],
    categories:    attrs.categories ? Object.values(attrs.categories).slice(0, 5) : [],
    last_analysis: attrs.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
  };
}

// ─── Source 4: Shodan InternetDB (free, no key) ───────────────────────────────
async function checkShodanInternetDB(ip) {
  const data = await safeFetch(`https://internetdb.shodan.io/${ip}`);
  if (!data || typeof data !== 'object') return null;
  return {
    open_ports:  data.ports || [],
    hostnames:   data.hostnames || [],
    vulns:       data.vulns || [],
    tags:        data.tags || [],
    cpes:        data.cpes || [],
  };
}

// ─── Source 5: DNSBL checks for IPs ──────────────────────────────────────────
async function checkDNSBL(ip) {
  const reversedIP = ip.split('.').reverse().join('.');
  const dnsblZones = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'b.barracudacentral.org',
  ];

  const checks = await Promise.allSettled(
    dnsblZones.map(zone =>
      safeFetch(`https://cloudflare-dns.com/dns-query?name=${reversedIP}.${zone}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      })
    )
  );

  const listed = [];
  for (let i = 0; i < checks.length; i++) {
    const result = checks[i];
    if (result.status === 'fulfilled' && result.value?.Answer?.length > 0) {
      listed.push(dnsblZones[i]);
    }
  }

  return { listed_on: listed, blacklisted: listed.length > 0 };
}

// ─── Source 6: DNS resolution for domains ────────────────────────────────────
async function resolveDomain(domain) {
  try {
    const [aRecords, mxRecords] = await Promise.allSettled([
      safeFetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      }),
      safeFetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`, {
        headers: { Accept: 'application/dns-json' },
      }),
    ]);

    const ips = aRecords.status === 'fulfilled'
      ? (aRecords.value?.Answer || []).map(r => r.data).filter(Boolean)
      : [];
    const hasMX = mxRecords.status === 'fulfilled'
      ? (mxRecords.value?.Answer || []).length > 0
      : false;

    return { resolves: ips.length > 0, ips, has_mx: hasMX };
  } catch { return { resolves: false, ips: [], has_mx: false }; }
}

// ─── Calculate risk score ─────────────────────────────────────────────────────
function calculateRiskScore(sources) {
  let score = 0;

  // Internal threat intel hits
  if ((sources.internal?.hits || 0) > 0) score += 30;

  // AbuseIPDB
  const abuseCon = sources.abuseipdb?.confidence_score || 0;
  score += Math.round(abuseCon * 0.4);  // max 40 points

  // VirusTotal
  const vtMal = sources.virustotal?.malicious || 0;
  const vtSus = sources.virustotal?.suspicious || 0;
  if (vtMal > 0) score += Math.min(vtMal * 5, 40);
  if (vtSus > 0) score += Math.min(vtSus * 2, 15);

  // DNSBL
  if (sources.dnsbl?.blacklisted) score += 25;

  // Shodan vulns
  if ((sources.shodan?.vulns || []).length > 0) score += 20;

  return Math.min(score, 100);
}

function scoreToVerdict(score) {
  if (score >= 70) return 'malicious';
  if (score >= 40) return 'suspicious';
  if (score >= 10) return 'low_risk';
  return 'clean';
}

function extractTags(sources, type) {
  const tags = new Set();

  if (sources.abuseipdb?.confidence_score > 50) tags.add('Reported-Abuse');
  if (sources.virustotal?.malicious > 3) tags.add('Multi-AV-Detected');
  if (sources.virustotal?.categories?.includes('malware')) tags.add('Malware');
  if (sources.virustotal?.categories?.some(c => c.toLowerCase().includes('phish'))) tags.add('Phishing');
  if (sources.dnsbl?.blacklisted) tags.add('DNSBL-Listed');
  if ((sources.shodan?.vulns || []).length > 0) tags.add('Known-CVEs');
  if ((sources.shodan?.open_ports || []).includes(22)) tags.add('SSH-Open');
  if ((sources.shodan?.open_ports || []).includes(3389)) tags.add('RDP-Open');
  if (sources.internal?.hits > 0) tags.add('In-Threat-Intel');

  if (type === 'domain' && sources.dns?.has_mx) tags.add('Has-MX');
  if (type === 'hash') tags.add('File-Hash');

  return [...tags];
}

// ─── Main enrichment function ─────────────────────────────────────────────────
export async function enrichIOC(env, value, typeHint = null) {
  const type = typeHint || detectType(value);
  if (type === 'unknown') {
    return { error: 'Cannot determine IOC type', value, type: 'unknown' };
  }

  const cacheKey = sha256Hex(`${type}:${value.toLowerCase()}`);

  // Check D1 cache
  if (env.DB) {
    try {
      const cached = await env.DB.prepare(`
        SELECT * FROM ioc_enrichment_cache
        WHERE id = ? AND ttl_expires > datetime('now')
      `).bind(cacheKey).first();

      if (cached) {
        return {
          value, type,
          verdict:       cached.verdict,
          risk_score:    cached.risk_score,
          tags:          JSON.parse(cached.tags || '[]'),
          raw_data:      JSON.parse(cached.raw_data || '{}'),
          country:       cached.country,
          asn:           cached.asn,
          org:           cached.org,
          abuse_score:   cached.abuse_score,
          vt_positives:  cached.vt_positives,
          internal_hits: cached.internal_hits,
          sources_hit:   JSON.parse(cached.sources_hit || '[]'),
          from_cache:    true,
          cached_at:     cached.created_at,
        };
      }
    } catch {}
  }

  // Parallel enrichment from all sources
  const startTime = Date.now();
  const sources = {};
  const sourcesHit = [];

  // Always check internal
  sources.internal = await checkInternalThreatIntel(env, value);
  if (sources.internal.hits > 0) sourcesHit.push('internal_threat_intel');

  // Type-specific external checks
  if (type === 'ip') {
    const [abuse, shodan, dnsbl] = await Promise.allSettled([
      checkAbuseIPDB(env, value),
      checkShodanInternetDB(value),
      checkDNSBL(value),
    ]);

    if (abuse.status === 'fulfilled' && abuse.value) {
      sources.abuseipdb = abuse.value;
      sourcesHit.push('abuseipdb');
    }
    if (shodan.status === 'fulfilled' && shodan.value) {
      sources.shodan = shodan.value;
      sourcesHit.push('shodan_internetdb');
    }
    if (dnsbl.status === 'fulfilled' && dnsbl.value) {
      sources.dnsbl = dnsbl.value;
      if (dnsbl.value.blacklisted) sourcesHit.push('dnsbl');
    }

    // VirusTotal for IP
    const vt = await checkVirusTotal(env, value, 'ip');
    if (vt) { sources.virustotal = vt; sourcesHit.push('virustotal'); }
  }

  else if (type === 'domain') {
    const [dns, vt] = await Promise.allSettled([
      resolveDomain(value),
      checkVirusTotal(env, value, 'domain'),
    ]);

    if (dns.status === 'fulfilled' && dns.value) {
      sources.dns = dns.value;
      sourcesHit.push('dns_resolution');
    }
    if (vt.status === 'fulfilled' && vt.value) {
      sources.virustotal = vt.value;
      sourcesHit.push('virustotal');
    }
  }

  else if (type === 'hash') {
    const vt = await checkVirusTotal(env, value, 'hash');
    if (vt) { sources.virustotal = vt; sourcesHit.push('virustotal'); }
  }

  else if (type === 'url') {
    const vt = await checkVirusTotal(env, value, 'url');
    if (vt) { sources.virustotal = vt; sourcesHit.push('virustotal'); }
  }

  // Calculate verdict
  const riskScore = calculateRiskScore(sources);
  const verdict   = scoreToVerdict(riskScore);
  const tags      = extractTags(sources, type);

  const result = {
    value, type, verdict, risk_score: riskScore, tags,
    sources_hit:   sourcesHit,
    sources:       sources,
    country:       sources.abuseipdb?.country || null,
    asn:           sources.abuseipdb?.isp || null,
    org:           sources.abuseipdb?.isp || null,
    abuse_score:   sources.abuseipdb?.confidence_score || 0,
    vt_positives:  sources.virustotal?.malicious || 0,
    internal_hits: sources.internal?.hits || 0,
    open_ports:    sources.shodan?.open_ports || [],
    known_vulns:   sources.shodan?.vulns || [],
    dns_resolves:  sources.dns?.resolves,
    enriched_in_ms: Date.now() - startTime,
    from_cache:    false,
  };

  // Store in D1 cache
  if (env.DB) {
    try {
      const ttl = CACHE_TTL[type] || 3600;
      const expires = new Date(Date.now() + ttl * 1000).toISOString();
      await env.DB.prepare(`
        INSERT OR REPLACE INTO ioc_enrichment_cache
          (id, ioc_type, ioc_value, verdict, risk_score, sources_hit, raw_data,
           tags, country, asn, org, abuse_score, vt_positives, internal_hits,
           ttl_expires, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        cacheKey, type, value.toLowerCase(), verdict, riskScore,
        JSON.stringify(sourcesHit),
        JSON.stringify(sources),
        JSON.stringify(tags),
        result.country, result.asn, result.org,
        result.abuse_score, result.vt_positives, result.internal_hits,
        expires,
      ).run();
    } catch {}
  }

  return result;
}

// ─── Batch enrichment ─────────────────────────────────────────────────────────
export async function enrichIOCBatch(env, iocs) {
  const limit = 10;
  const batch = iocs.slice(0, limit);
  const results = await Promise.allSettled(
    batch.map(({ value, type }) => enrichIOC(env, value, type))
  );
  return results.map((r, i) => ({
    input: batch[i],
    result: r.status === 'fulfilled' ? r.value : { error: r.reason?.message },
  }));
}
