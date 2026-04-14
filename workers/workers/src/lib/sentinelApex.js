/**
 * CYBERDUDEBIVASH AI Security Hub — Sentinel APEX v1.0
 * Real-time CVE & threat intelligence feed engine
 * Sources: NVD (NIST) API v2 | CISA KEV | GitHub Advisory
 * Runs on Cloudflare Workers cron (every 6h) — cached in KV
 * Public endpoint: GET /api/sentinel/feed
 */

const NVD_API_BASE   = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV_URL   = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const FEED_CACHE_KEY = 'sentinel:apex:feed:v1';
const FEED_TTL       = 21600; // 6 hours — matches cron frequency
const FETCH_TIMEOUT  = 8000;

// ─── Safe fetch with timeout ──────────────────────────────────────────────────
async function safeFetch(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ─── NVD CVE Fetch (last N days, filtered by severity) ────────────────────────
async function fetchNVDCVEs(daysBack = 3) {
  const now      = new Date();
  const start    = new Date(now.getTime() - daysBack * 86400 * 1000);
  const pubStart = start.toISOString().replace(/\.\d+Z$/, '.000 UTC/00:00');
  const pubEnd   = now.toISOString().replace(/\.\d+Z$/, '.000 UTC/00:00');

  // Filter for HIGH and CRITICAL CVSSv3 (cvssV3Severity=HIGH,CRITICAL)
  const url = `${NVD_API_BASE}?pubStartDate=${encodeURIComponent(pubStart)}&pubEndDate=${encodeURIComponent(pubEnd)}&cvssV3Severity=CRITICAL&resultsPerPage=20`;
  const criticalData = await safeFetch(url, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/1.0' },
  });

  const url2 = `${NVD_API_BASE}?pubStartDate=${encodeURIComponent(pubStart)}&pubEndDate=${encodeURIComponent(pubEnd)}&cvssV3Severity=HIGH&resultsPerPage=15`;
  const highData = await safeFetch(url2, {
    headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/1.0' },
  });

  const parseCVE = (item) => {
    const cve        = item.cve;
    const id         = cve.id;
    const desc       = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
    const metrics    = cve.metrics;
    const cvssV3     = metrics?.cvssMetricV31?.[0]?.cvssData || metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssV2     = metrics?.cvssMetricV2?.[0]?.cvssData;
    const score      = cvssV3?.baseScore ?? cvssV2?.baseScore ?? null;
    const severity   = cvssV3?.baseSeverity ?? cvssV2?.baseSeverity ?? 'UNKNOWN';
    const vector     = cvssV3?.vectorString ?? cvssV2?.vectorString ?? null;
    const published  = cve.published;
    const modified   = cve.lastModified;
    const refs       = (cve.references || []).slice(0, 3).map(r => r.url);
    const cpes       = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.slice(0, 3).map(c => c.criteria) || [];
    const weaknesses = cve.weaknesses?.map(w => w.description?.[0]?.value).filter(Boolean) || [];

    return {
      id, severity, score, vector,
      description: desc.length > 300 ? desc.slice(0, 297) + '...' : desc,
      published:   published ? published.split('T')[0] : null,
      modified:    modified  ? modified.split('T')[0]  : null,
      references:  refs,
      affected_products: cpes,
      weakness_types:    weaknesses,
      nvd_url: `https://nvd.nist.gov/vuln/detail/${id}`,
      tags: buildTags(desc, cpes, weaknesses),
    };
  };

  const critical = (criticalData?.vulnerabilities || []).map(parseCVE);
  const high     = (highData?.vulnerabilities || []).map(parseCVE);

  // Deduplicate
  const seen = new Set();
  const all  = [...critical, ...high].filter(c => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });

  return { critical, high, all, total: all.length, source: 'nvd_nist' };
}

// ─── CISA KEV (Known Exploited Vulnerabilities) ──────────────────────────────
async function fetchCISAKEV() {
  const data = await safeFetch(CISA_KEV_URL);
  if (!data?.vulnerabilities) return { vulnerabilities: [], total: 0, source: 'cisa_kev' };

  // Return the 15 most recently added KEVs
  const recent = [...data.vulnerabilities]
    .sort((a,b) => new Date(b.dateAdded || 0) - new Date(a.dateAdded || 0))
    .slice(0, 15)
    .map(v => ({
      cve_id:             v.cveID,
      vendor:             v.vendorProject,
      product:            v.product,
      vulnerability_name: v.vulnerabilityName,
      date_added:         v.dateAdded,
      short_description:  v.shortDescription?.slice(0, 200) || '',
      required_action:    v.requiredAction || '',
      due_date:           v.dueDate || null,
      known_ransomware:   v.knownRansomwareCampaignUse === 'Known',
      nvd_url:            `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
    }));

  return {
    vulnerabilities: recent,
    total_in_catalog: data.count ?? data.vulnerabilities.length,
    catalog_version:  data.catalogVersion ?? null,
    source: 'cisa_kev',
    note: 'These CVEs are actively exploited in the wild per CISA. Treat as P0.',
  };
}

// ─── Tag builder ─────────────────────────────────────────────────────────────
function buildTags(desc, cpes, weaknesses) {
  const tags = [];
  const d = desc.toLowerCase();
  if (d.includes('remote code execution') || d.includes('rce')) tags.push('RCE');
  if (d.includes('sql injection'))                              tags.push('SQLi');
  if (d.includes('cross-site scripting') || d.includes('xss')) tags.push('XSS');
  if (d.includes('privilege escalation'))                       tags.push('PrivEsc');
  if (d.includes('denial of service') || d.includes('dos'))     tags.push('DoS');
  if (d.includes('authentication bypass'))                      tags.push('AuthBypass');
  if (d.includes('path traversal'))                             tags.push('PathTraversal');
  if (d.includes('buffer overflow'))                            tags.push('BufferOverflow');
  if (d.includes('zero-day') || d.includes('0-day'))           tags.push('ZeroDay');
  if (cpes.some(c => c.includes('apache') || c.includes('nginx'))) tags.push('WebServer');
  if (cpes.some(c => c.includes('linux') || c.includes('windows'))) tags.push('OS');
  if (weaknesses.some(w => w.includes('CWE-79')))              tags.push('XSS');
  if (weaknesses.some(w => w.includes('CWE-89')))              tags.push('SQLi');
  if (weaknesses.some(w => w.includes('CWE-78')))              tags.push('CmdInjection');
  return [...new Set(tags)];
}

// ─── Threat Trend Analysis ────────────────────────────────────────────────────
function buildThreatTrends(nvdData) {
  const all = nvdData.all || [];
  const tagFreq = {};
  all.forEach(c => (c.tags || []).forEach(t => { tagFreq[t] = (tagFreq[t] || 0) + 1; }));

  const topTags = Object.entries(tagFreq)
    .sort((a,b) => b[1] - a[1])
    .slice(0, 8)
    .map(([tag, count]) => ({ tag, count }));

  const avgScore = all.length
    ? (all.reduce((s, c) => s + (c.score || 0), 0) / all.length).toFixed(1)
    : 0;

  return {
    top_attack_types: topTags,
    average_cvss:     parseFloat(avgScore),
    critical_count:   nvdData.critical?.length ?? 0,
    high_count:       nvdData.high?.length ?? 0,
    period: 'Last 3 days',
  };
}

// ─── Build Full Feed Payload ──────────────────────────────────────────────────
async function buildFeed() {
  const [nvd, kev] = await Promise.all([
    fetchNVDCVEs(3),
    fetchCISAKEV(),
  ]);

  const trends = buildThreatTrends(nvd);

  return {
    feed_name:    'CYBERDUDEBIVASH Sentinel APEX',
    feed_version: '1.0',
    feed_url:     'https://t.me/cyberdudebivashSentinelApex',
    generated_at: new Date().toISOString(),
    ttl_seconds:  FEED_TTL,
    alert_level:  nvd.critical?.length > 5 ? 'CRITICAL' : nvd.critical?.length > 0 ? 'HIGH' : 'MEDIUM',
    summary: {
      total_new_cves:     nvd.total,
      critical_cves:      nvd.critical?.length ?? 0,
      high_cves:          nvd.high?.length ?? 0,
      actively_exploited: kev.vulnerabilities?.filter(v => v.known_ransomware).length ?? 0,
      kev_additions:      kev.vulnerabilities?.length ?? 0,
    },
    threat_trends:       trends,
    critical_cves:       nvd.critical?.slice(0, 10) ?? [],
    high_cves:           nvd.high?.slice(0, 8) ?? [],
    actively_exploited:  kev.vulnerabilities ?? [],
    sources: {
      nvd:  { name:'NIST NVD', url:'https://nvd.nist.gov/', status: nvd.total > 0 ? 'ok' : 'unavailable' },
      kev:  { name:'CISA KEV', url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', status: kev.total_in_catalog > 0 ? 'ok' : 'unavailable' },
    },
    telegram_channel: {
      name:  'Sentinel APEX',
      url:   'https://t.me/cyberdudebivashSentinelApex',
      note:  'Subscribe for real-time threat alerts, CVE analysis, and PoC coverage',
    },
  };
}

// ─── Cron Handler — called from Workers scheduled event ─────────────────────
export async function runSentinelCron(env) {
  if (!env?.SECURITY_HUB_KV) return { skipped: true, reason: 'KV unavailable' };
  try {
    const feed = await buildFeed();
    await env.SECURITY_HUB_KV.put(FEED_CACHE_KEY, JSON.stringify(feed), { expirationTtl: FEED_TTL });
    // Store the last run metadata
    await env.SECURITY_HUB_KV.put('sentinel:apex:last_run', JSON.stringify({
      ran_at:      feed.generated_at,
      alert_level: feed.alert_level,
      total_cves:  feed.summary.total_new_cves,
      kev_added:   feed.summary.kev_additions,
    }), { expirationTtl: FEED_TTL * 2 });
    return { success: true, generated_at: feed.generated_at, total_cves: feed.summary.total_new_cves };
  } catch (e) {
    return { success: false, error: e?.message || 'Unknown error' };
  }
}

// ─── HTTP Handler — GET /api/sentinel/feed ────────────────────────────────────
export async function handleSentinelFeed(request, env, authCtx = {}) {
  const url    = new URL(request.url);
  const nocache = url.searchParams.get('nocache') === '1';

  // Try KV cache first
  if (!nocache && env?.SECURITY_HUB_KV) {
    try {
      const cached = await env.SECURITY_HUB_KV.get(FEED_CACHE_KEY);
      if (cached) {
        const feed = JSON.parse(cached);
        return Response.json(feed, {
          status: 200,
          headers: { 'X-Cache': 'HIT', 'X-Feed-Generated': feed.generated_at, 'Cache-Control': `public, max-age=${FEED_TTL}` },
        });
      }
    } catch {}
  }

  // Cache miss or nocache — fetch live
  try {
    const feed = await buildFeed();

    // Store in KV for subsequent requests
    if (env?.SECURITY_HUB_KV) {
      env.SECURITY_HUB_KV.put(FEED_CACHE_KEY, JSON.stringify(feed), { expirationTtl: FEED_TTL }).catch(() => {});
    }

    return Response.json(feed, {
      status: 200,
      headers: { 'X-Cache': 'MISS', 'X-Feed-Generated': feed.generated_at, 'Cache-Control': `public, max-age=3600` },
    });
  } catch (e) {
    return Response.json({
      error: 'Feed temporarily unavailable',
      hint: 'The Sentinel APEX feed is refreshing. Try again in 60 seconds.',
      fallback: 'https://t.me/cyberdudebivashSentinelApex',
    }, { status: 503 });
  }
}

// ─── GET /api/sentinel/status ─────────────────────────────────────────────────
export async function handleSentinelStatus(request, env) {
  let lastRun = null;
  if (env?.SECURITY_HUB_KV) {
    try {
      const raw = await env.SECURITY_HUB_KV.get('sentinel:apex:last_run');
      if (raw) lastRun = JSON.parse(raw);
    } catch {}
  }

  return Response.json({
    service:       'Sentinel APEX',
    status:        lastRun ? 'operational' : 'initializing',
    last_run:      lastRun,
    feed_url:      'https://cyberdudebivash-security-hub.workers.dev/api/sentinel/feed',
    telegram:      'https://t.me/cyberdudebivashSentinelApex',
    refresh_every: '6 hours (cron)',
    sources:       ['NIST NVD CVE API v2', 'CISA Known Exploited Vulnerabilities'],
  }, { status: 200 });
}
