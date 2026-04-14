/**
 * CYBERDUDEBIVASH AI Security Hub — Federation Engine v1.0
 * Sentinel APEX v3 Phase 1: Global Threat Intelligence Network
 *
 * Responsibilities:
 *   1. Multi-source ingestion orchestration (NVD, CISA, GitHub, ExploitDB, RSS, VT)
 *   2. Global deduplication with conflict resolution (prefer higher severity + confirmed exploit)
 *   3. Source reliability scoring (0–100 per source, based on freshness + coverage)
 *   4. Node identity system (this Worker = CDB node with region + status)
 *   5. Feed normalization into unified GlobalThreatEntry schema
 *
 * Output:
 *   { global_feed: [...], source_scores: {}, confidence: 'HIGH'|'MED'|'LOW', node_identity }
 */

// ─── Node Identity (this edge node) ──────────────────────────────────────────
const NODE_IDENTITY = {
  node_id:     'CDB-IND-01',
  platform:    'CYBERDUDEBIVASH AI Security Hub',
  region:      'India',
  dc:          'Cloudflare Edge (Asia-South1)',
  version:     'sentinel-apex-v3',
  status:      'active',
  capabilities: ['ingest', 'correlate', 'hunt', 'alert', 'defend'],
};

// ─── Source reliability baseline (adjusted dynamically) ──────────────────────
const SOURCE_BASELINES = {
  nvd:         { name: 'NIST NVD',              base_score: 95, type: 'authoritative' },
  cisa_kev:    { name: 'CISA KEV',              base_score: 98, type: 'authoritative' },
  github:      { name: 'GitHub Advisories',      base_score: 82, type: 'community'     },
  exploitdb:   { name: 'Exploit-DB',             base_score: 88, type: 'technical'     },
  rss_blog:    { name: 'Security RSS Feeds',     base_score: 65, type: 'informational' },
  virustotal:  { name: 'VirusTotal Intel',        base_score: 91, type: 'technical'     },
  seed:        { name: 'Internal Seed DB',        base_score: 90, type: 'curated'       },
};

// ─── RSS Security feed sources ────────────────────────────────────────────────
const RSS_FEEDS = [
  { url: 'https://feeds.feedburner.com/TheHackersNews',  name: 'TheHackerNews'  },
  { url: 'https://krebsonsecurity.com/feed/',            name: 'KrebsOnSecurity' },
  { url: 'https://www.schneier.com/feed/atom/',          name: 'Schneier'        },
  { url: 'https://www.bleepingcomputer.com/feed/',       name: 'BleepingComputer'},
  { url: 'https://www.darkreading.com/rss.xml',          name: 'DarkReading'     },
];

// ─── Fetch with timeout ───────────────────────────────────────────────────────
async function timedFetch(url, options = {}, timeoutMs = 8000) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('json')) return { data: await res.json(), ct };
    return { data: await res.text(), ct };
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ─── Normalize severity ───────────────────────────────────────────────────────
function normSev(raw) {
  const s = (raw || '').toUpperCase();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH')     return 'HIGH';
  if (s === 'MEDIUM')   return 'MEDIUM';
  if (s === 'LOW')      return 'LOW';
  return 'MEDIUM';
}

// ─── MODULE: Fetch ExploitDB via SHODAN search export / RSS clone ─────────────
// ExploitDB provides a CSV at https://www.exploit-db.com/gitlab-explore/
// We scrape the public search API (no auth needed for basic list)
export async function fetchExploitDB(limit = 20) {
  // ExploitDB JSON search API endpoint
  const url = `https://www.exploit-db.com/search?action=search&type=webapps&platform=php&order_by=date_published&order=desc&draw=1&columns[0][data]=id&start=0&length=${limit}`;

  const result = await timedFetch(url, {
    headers: {
      'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/3.0 (research@cyberdudebivash.in)',
      'Accept':     'application/json',
      'Referer':    'https://www.exploit-db.com/',
      'X-Requested-With': 'XMLHttpRequest',
    },
  }, 10000);

  if (!result?.data?.data) return [];

  return result.data.data.slice(0, limit).map(item => {
    const id    = item.id || '';
    const title = (item.description || item.title || `ExploitDB-${id}`).slice(0, 200);
    const date  = (item.date_published || item.date_added || '').split('T')[0];
    const cveId = (item.codes || '').match(/CVE-\d{4}-\d{4,}/)?.[0] || null;
    const edbId = `EDB-${id}`;

    return {
      id:               cveId || edbId,
      title,
      severity:         'HIGH',       // EDB entries are exploitable by definition
      cvss:             null,
      description:      `ExploitDB exploit: ${title}. Platform: ${item.platform || 'multiple'}. Type: ${item.type || 'exploit'}.`,
      source:           'exploitdb',
      source_url:       `https://www.exploit-db.com/exploits/${id}`,
      published_at:     date || null,
      exploit_status:   'confirmed',  // exists in EDB = exploit available
      exploit_available: true,
      actively_exploited: false,
      known_ransomware: 0,
      tags:             JSON.stringify(['ExploitDB', item.type || 'exploit', item.platform || 'web'].filter(Boolean)),
      affected_products: JSON.stringify([item.platform || 'unknown']),
      weakness_types:   '[]',
      enriched:         0,
      edb_id:           id,
    };
  });
}

// ─── MODULE: Parse RSS Security feeds ────────────────────────────────────────
export async function fetchSecurityRSS(maxPerFeed = 5) {
  const all = [];

  for (const feed of RSS_FEEDS) {
    const result = await timedFetch(feed.url, {
      headers: { 'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/3.0' },
    }, 6000);

    if (!result?.data || typeof result.data !== 'string') continue;

    const xml   = result.data;
    // Parse <item> blocks (RSS 2.0) or <entry> blocks (Atom)
    const items = xml.match(/<item[\s>][\s\S]*?<\/item>/g)
                || xml.match(/<entry>[\s\S]*?<\/entry>/g)
                || [];

    let count = 0;
    for (const block of items) {
      if (count >= maxPerFeed) break;

      const title   = ((block.match(/<title[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/) || [])[1] || '').trim();
      const link    = ((block.match(/<link[^>]*>([^<]+)<\/link>/) || block.match(/<link[^>]*href="([^"]+)"/) || [])[1] || '').trim();
      const pubDate = ((block.match(/<pubDate[^>]*>([^<]+)<\/pubDate>/)
                     || block.match(/<published[^>]*>([^<]+)<\/published>/)
                     || block.match(/<updated[^>]*>([^<]+)<\/updated>/)
                     || [])[1] || '').trim();
      const summary = ((block.match(/<description[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/)
                     || block.match(/<summary[^>]*>([\s\S]*?)<\/summary>/)
                     || [])[1] || '').replace(/<[^>]+>/g, '').trim().slice(0, 300);

      if (!title || !link) continue;

      // Only include if it mentions CVE, vulnerability, or security keywords
      const lc = (title + summary).toLowerCase();
      const isRelevant = lc.includes('cve') || lc.includes('vulnerab') || lc.includes('exploit')
                       || lc.includes('zero-day') || lc.includes('breach') || lc.includes('ransomware')
                       || lc.includes('malware') || lc.includes('patch');
      if (!isRelevant) continue;

      // Try to extract CVE ID
      const cveMatch = (title + summary).match(/CVE-\d{4}-\d{4,}/);
      const entryId  = cveMatch ? cveMatch[0] : `RSS-${feed.name}-${Date.now()}-${count}`;

      // Parse date
      let pubDate_iso = null;
      try { pubDate_iso = pubDate ? new Date(pubDate).toISOString().split('T')[0] : null; } catch {}

      all.push({
        id:               entryId,
        title:            title.slice(0, 200),
        severity:         lc.includes('critical') ? 'CRITICAL' : lc.includes('high') ? 'HIGH' : 'MEDIUM',
        cvss:             null,
        description:      summary,
        source:           'rss_blog',
        source_name:      feed.name,
        source_url:       link,
        published_at:     pubDate_iso,
        exploit_status:   lc.includes('exploit') || lc.includes('exploited') ? 'poc_available' : 'unconfirmed',
        exploit_available: lc.includes('exploit') || lc.includes('poc'),
        actively_exploited: lc.includes('actively exploit') || lc.includes('in the wild'),
        known_ransomware: lc.includes('ransomware') ? 1 : 0,
        tags:             JSON.stringify(['RSS', feed.name, ...(cveMatch ? ['CVE'] : [])]),
        affected_products: '[]',
        weakness_types:   '[]',
        enriched:         0,
      });

      count++;
    }
  }

  return all;
}

// ─── MODULE: VirusTotal threat intel (if API key present) ─────────────────────
export async function fetchVirusTotalIntel(env, limit = 10) {
  const apiKey = env?.VIRUSTOTAL_API_KEY;
  if (!apiKey) return [];

  const url = 'https://www.virustotal.com/api/v3/intelligence/search?query=type:malware&order=last_submission_date-&limit=' + limit;

  const result = await timedFetch(url, {
    headers: {
      'x-apikey':   apiKey,
      'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/3.0',
    },
  }, 10000);

  if (!result?.data?.data) return [];

  return result.data.data.slice(0, limit).map(item => {
    const attrs = item.attributes || {};
    const names = (attrs.meaningful_name || attrs.name || item.id || 'unknown').slice(0, 100);
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const total     = Object.values(stats).reduce((s, v) => s + (typeof v === 'number' ? v : 0), 0);
    const ratio     = total > 0 ? malicious / total : 0;

    return {
      id:               `VT-${item.id?.slice(0, 12) || Date.now()}`,
      title:            `VirusTotal: ${names} (${malicious}/${total} engines)`,
      severity:         ratio >= 0.5 ? 'HIGH' : ratio >= 0.2 ? 'MEDIUM' : 'LOW',
      cvss:             null,
      description:      `VirusTotal intelligence: ${names}. Detection ratio: ${malicious}/${total}. Type: ${attrs.type_description || 'malware'}.`,
      source:           'virustotal',
      source_url:       `https://www.virustotal.com/gui/file/${item.id}`,
      published_at:     attrs.last_submission_date
        ? new Date(attrs.last_submission_date * 1000).toISOString().split('T')[0] : null,
      exploit_status:   'unconfirmed',
      exploit_available: false,
      actively_exploited: ratio >= 0.5,
      known_ransomware: (attrs.popular_threat_classification?.suggested_threat_label || '').toLowerCase().includes('ransom') ? 1 : 0,
      tags:             JSON.stringify(['VirusTotal', 'Malware', attrs.type_description || 'unknown'].filter(Boolean)),
      affected_products: '[]',
      weakness_types:   '[]',
      enriched:         0,
      vt_hash:          item.id,
      vt_detection_ratio: ratio.toFixed(2),
    };
  });
}

// ─── FEDERATION: Global deduplication with conflict resolution ────────────────
export function globalDeduplicate(allEntries) {
  const seen    = new Map();
  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

  for (const entry of allEntries) {
    const key = entry.id;
    if (!seen.has(key)) {
      seen.set(key, { ...entry });
      continue;
    }

    const existing = seen.get(key);

    // Conflict resolution rules:
    // 1. Prefer higher severity
    if ((sevRank[entry.severity] || 0) > (sevRank[existing.severity] || 0)) {
      existing.severity = entry.severity;
    }
    // 2. Prefer higher CVSS
    if (entry.cvss && (!existing.cvss || entry.cvss > existing.cvss)) {
      existing.cvss = entry.cvss;
    }
    // 3. Confirmed exploit wins over unconfirmed
    const exploitRank = { confirmed: 3, poc_available: 2, unconfirmed: 1 };
    if ((exploitRank[entry.exploit_status] || 0) > (exploitRank[existing.exploit_status] || 0)) {
      existing.exploit_status   = entry.exploit_status;
      existing.exploit_available = entry.exploit_available || existing.exploit_available;
    }
    // 4. KEV flag is sticky
    if (entry.known_ransomware) existing.known_ransomware = 1;
    if (entry.actively_exploited) existing.actively_exploited = true;
    // 5. Merge tags
    try {
      const t1 = JSON.parse(existing.tags || '[]');
      const t2 = JSON.parse(entry.tags   || '[]');
      existing.tags = JSON.stringify([...new Set([...t1, ...t2])]);
    } catch {}
    // 6. Track all sources this entry came from
    existing._sources = [...new Set([...(existing._sources || [existing.source]), entry.source])];

    seen.set(key, existing);
  }

  return [...seen.values()];
}

// ─── FEDERATION: Score source reliability dynamically ─────────────────────────
export function scoreSourceReliability(results) {
  const scores = {};

  for (const [source, baseline] of Object.entries(SOURCE_BASELINES)) {
    const entries = results.filter(e => e.source === source || (e._sources || []).includes(source));
    const count   = entries.length;

    // Dynamic scoring factors:
    // +5  if source returned >10 entries (active source)
    // +3  if >50% of entries have CVSS score (high data quality)
    // -10 if source returned 0 entries (possibly down)
    // -5  if <20% have descriptions (low quality)
    let score = baseline.base_score;
    if (count === 0) {
      score -= 10;
    } else {
      if (count >= 10) score += 5;
      const withCVSS = entries.filter(e => e.cvss).length;
      if (count > 0 && withCVSS / count > 0.5) score += 3;
      const withDesc = entries.filter(e => (e.description || '').length > 50).length;
      if (count > 0 && withDesc / count < 0.2) score -= 5;
    }

    scores[source] = {
      ...baseline,
      dynamic_score: Math.max(0, Math.min(100, score)),
      entry_count:   count,
    };
  }

  return scores;
}

// ─── FEDERATION: Compute overall confidence ───────────────────────────────────
function computeConfidence(sourceScores, totalEntries) {
  const scores    = Object.values(sourceScores).map(s => s.dynamic_score);
  const avgScore  = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
  const activeSrc = Object.values(sourceScores).filter(s => s.entry_count > 0).length;

  if (avgScore >= 85 && activeSrc >= 3 && totalEntries >= 10) return 'HIGH';
  if (avgScore >= 65 && activeSrc >= 2 && totalEntries >= 5)  return 'MEDIUM';
  return 'LOW';
}

// ─── MASTER: Run full global federation ──────────────────────────────────────
export async function runFederation(env, existingEntries = []) {
  const startTime    = Date.now();
  const rawResults   = [...existingEntries]; // starts with already-ingested data
  const sourceStats  = { nvd: 0, cisa_kev: 0, github: 0, seed: 0 };
  const errors       = [];

  // Count existing by source
  for (const e of existingEntries) {
    const src = e.source || 'unknown';
    sourceStats[src] = (sourceStats[src] || 0) + 1;
  }

  // ── Fetch ExploitDB ────────────────────────────────────────────────────────
  try {
    const edb = await fetchExploitDB(15);
    if (edb.length > 0) {
      rawResults.push(...edb);
      sourceStats.exploitdb = edb.length;
    }
  } catch (e) {
    errors.push(`ExploitDB: ${e.message}`);
    sourceStats.exploitdb = 0;
  }

  // ── Fetch RSS Security blogs ───────────────────────────────────────────────
  try {
    const rss = await fetchSecurityRSS(4);
    if (rss.length > 0) {
      rawResults.push(...rss);
      sourceStats.rss_blog = rss.length;
    }
  } catch (e) {
    errors.push(`RSS: ${e.message}`);
    sourceStats.rss_blog = 0;
  }

  // ── Fetch VirusTotal (if key configured) ──────────────────────────────────
  try {
    const vt = await fetchVirusTotalIntel(env, 8);
    if (vt.length > 0) {
      rawResults.push(...vt);
      sourceStats.virustotal = vt.length;
    }
  } catch (e) {
    errors.push(`VirusTotal: ${e.message}`);
    sourceStats.virustotal = 0;
  }

  // ── Global deduplication ──────────────────────────────────────────────────
  const globalFeed = globalDeduplicate(rawResults);

  // ── Source reliability scoring ────────────────────────────────────────────
  const sourceScores = scoreSourceReliability(globalFeed);

  // ── Confidence assessment ─────────────────────────────────────────────────
  const confidence = computeConfidence(sourceScores, globalFeed.length);

  // ── Sort: CRITICAL first, then by CVSS desc, then by date desc ───────────
  const sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  globalFeed.sort((a, b) => {
    const sevDiff = (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return (b.cvss || 0) - (a.cvss || 0);
  });

  const result = {
    global_feed:   globalFeed,
    source_scores: sourceScores,
    source_stats:  sourceStats,
    confidence,
    node_identity: NODE_IDENTITY,
    total_entries: globalFeed.length,
    sources_active: Object.values(sourceStats).filter(v => v > 0).length,
    errors,
    federation_ms:  Date.now() - startTime,
    federated_at:   new Date().toISOString(),
  };

  // Cache federation result in KV (5 min TTL)
  if (env?.SECURITY_HUB_KV) {
    env.SECURITY_HUB_KV.put(
      'sentinel:federation:latest',
      JSON.stringify({ ...result, global_feed: globalFeed.slice(0, 50) }), // cap to 50 for KV size
      { expirationTtl: 300 }
    ).catch(() => {});
  }

  return result;
}

// ─── GET node identity ────────────────────────────────────────────────────────
export function getNodeIdentity(env) {
  return {
    ...NODE_IDENTITY,
    queried_at: new Date().toISOString(),
    env_region:  env?.CF?.colo || 'unknown',
    // P2P sync placeholder — future expansion
    peer_nodes:  [],
    sync_status: 'standalone', // will become 'synced' in P2P mode
  };
}
