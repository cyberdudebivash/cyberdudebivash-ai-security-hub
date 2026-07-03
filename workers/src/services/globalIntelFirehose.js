/**
 * CYBERDUDEBIVASH AI Security Hub — Global Threat Intel Firehose v1.0
 * ═══════════════════════════════════════════════════════════════════════════
 * A dedicated, always-on (hourly, 24×7×365) worldwide OSINT threat-intelligence
 * pipeline. Where the CVE pipeline (threatIngestion.js) tracks *vulnerabilities*,
 * this firehose tracks the wider threat landscape — breaking incidents, campaigns,
 * breaches, ransomware, APT activity, malware, phishing and live IOCs — from a
 * broad registry of authoritative sources so we never miss a story.
 *
 * The 8 pipeline stages (one per customer-facing verb):
 *   1. FETCH    — pull every registered source in parallel (bounded, timed).
 *   2. INGEST   — normalize each raw item into one unified GlobalIntel schema.
 *   3. ENRICH   — extract IOCs, CVE ids, threat actors, malware families, tags.
 *   4. ANALYSE  — score threat level (severity × recency × source × signals).
 *   5. DRAFT    — assemble the hourly briefing (breaking-first, deduped).
 *   6. FORMAT   — shape display records + a headline summary line.
 *   7. PUBLISH  — upsert into D1 `global_intel` + write briefing snapshot to KV.
 *   8. DISPLAY  — served by handlers/globalIntel.js (freshest/breaking first).
 *
 * NO fabricated data: every item traces to a real source URL. When a source is
 * unreachable it is skipped (logged), never faked.
 */

import { extractIOCsFromText, summarizeIOCs } from './iocExtractor.js';

// ─── Source registry ─────────────────────────────────────────────────────────
// Real, reputable, no-auth feeds. `kind` selects the parser; `weight` (0–100)
// reflects source authority and feeds the threat score. Add new sources here —
// the pipeline picks them up automatically on the next hourly run.
export const INTEL_SOURCES = [
  // ── Government / national CERT advisories (highest authority) ──────────────
  { id: 'cisa-advisories', name: 'CISA Advisories',      url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', kind: 'rss', category: 'advisory', region: 'US',    weight: 98 },
  { id: 'cisa-current',    name: 'CISA Current Activity', url: 'https://www.cisa.gov/uscert/ncas/current-activity.xml',  kind: 'rss', category: 'advisory', region: 'US',    weight: 97 },
  { id: 'ncsc-uk',         name: 'NCSC UK',               url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', kind: 'rss', category: 'advisory', region: 'UK', weight: 95 },
  { id: 'certnz',          name: 'CERT NZ',               url: 'https://www.cert.govt.nz/rss/individual/', kind: 'rss', category: 'advisory', region: 'NZ', weight: 90 },

  // ── Vendor threat research (deep technical intel) ─────────────────────────
  { id: 'talos',        name: 'Cisco Talos',        url: 'https://blog.talosintelligence.com/rss/',        kind: 'rss', category: 'research', region: 'Global', weight: 94 },
  { id: 'unit42',       name: 'Palo Alto Unit 42',  url: 'https://unit42.paloaltonetworks.com/feed/',      kind: 'rss', category: 'research', region: 'Global', weight: 94 },
  { id: 'mandiant',     name: 'Mandiant',           url: 'https://www.mandiant.com/resources/blog/rss.xml',kind: 'rss', category: 'research', region: 'Global', weight: 95 },
  { id: 'msrc',         name: 'Microsoft MSRC',     url: 'https://msrc.microsoft.com/blog/feed',           kind: 'rss', category: 'research', region: 'Global', weight: 93 },
  { id: 'projectzero',  name: 'Google Project Zero',url: 'https://googleprojectzero.blogspot.com/feeds/posts/default', kind: 'atom', category: 'research', region: 'Global', weight: 95 },
  { id: 'securelist',   name: 'Kaspersky Securelist',url:'https://securelist.com/feed/',                   kind: 'rss', category: 'research', region: 'Global', weight: 90 },
  { id: 'welivesec',    name: 'ESET WeLiveSecurity',url: 'https://www.welivesecurity.com/en/rss/feed/',    kind: 'rss', category: 'research', region: 'Global', weight: 89 },
  { id: 'checkpoint',   name: 'Check Point Research',url:'https://research.checkpoint.com/feed/',           kind: 'rss', category: 'research', region: 'Global', weight: 90 },
  { id: 'sentinelone',  name: 'SentinelOne Labs',   url: 'https://www.sentinelone.com/labs/feed/',         kind: 'rss', category: 'research', region: 'Global', weight: 88 },
  { id: 'sophos',       name: 'Sophos News',        url: 'https://news.sophos.com/en-us/feed/',            kind: 'rss', category: 'research', region: 'Global', weight: 87 },
  { id: 'malwarebytes', name: 'Malwarebytes Labs',  url: 'https://www.malwarebytes.com/blog/feed/index.xml',kind:'rss', category: 'research', region: 'Global', weight: 86 },
  { id: 'rapid7',       name: 'Rapid7',             url: 'https://www.rapid7.com/blog/rss/',               kind: 'rss', category: 'research', region: 'Global', weight: 86 },
  { id: 'crowdstrike',  name: 'CrowdStrike',        url: 'https://www.crowdstrike.com/blog/feed/',         kind: 'rss', category: 'research', region: 'Global', weight: 90 },

  // ── Breaking security news (fast signal) ──────────────────────────────────
  { id: 'thehackernews', name: 'The Hacker News',   url: 'https://feeds.feedburner.com/TheHackersNews',    kind: 'rss', category: 'news', region: 'Global', weight: 80 },
  { id: 'bleeping',      name: 'BleepingComputer',  url: 'https://www.bleepingcomputer.com/feed/',         kind: 'rss', category: 'news', region: 'Global', weight: 82 },
  { id: 'krebs',         name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/',              kind: 'rss', category: 'news', region: 'US',     weight: 85 },
  { id: 'securityweek',  name: 'SecurityWeek',      url: 'https://www.securityweek.com/feed/',             kind: 'rss', category: 'news', region: 'Global', weight: 80 },
  { id: 'darkreading',   name: 'Dark Reading',      url: 'https://www.darkreading.com/rss.xml',            kind: 'rss', category: 'news', region: 'Global', weight: 79 },
  { id: 'theregister',   name: 'The Register',      url: 'https://www.theregister.com/security/headlines.atom', kind: 'atom', category: 'news', region: 'UK', weight: 78 },
  { id: 'infosecmag',    name: 'Infosecurity Mag',  url: 'https://www.infosecurity-magazine.com/rss/news/',kind: 'rss', category: 'news', region: 'UK',     weight: 76 },
  { id: 'schneier',      name: 'Schneier on Security',url:'https://www.schneier.com/feed/atom/',           kind: 'atom', category: 'news', region: 'Global', weight: 82 },
  { id: 'sans-isc',      name: 'SANS ISC Diary',    url: 'https://isc.sans.edu/rssfeed_full.xml',          kind: 'rss', category: 'research', region: 'Global', weight: 88 },
  { id: 'hackread',      name: 'HackRead',          url: 'https://www.hackread.com/feed/',                 kind: 'rss', category: 'news', region: 'Global', weight: 70 },

  // ── Live IOC / malware feeds (abuse.ch — real JSON, no auth) ──────────────
  { id: 'threatfox',   name: 'ThreatFox (abuse.ch)', url: 'https://threatfox.abuse.ch/export/json/recent/',   kind: 'json_threatfox', category: 'ioc', region: 'Global', weight: 92 },
  { id: 'urlhaus',     name: 'URLhaus (abuse.ch)',   url: 'https://urlhaus.abuse.ch/downloads/json_recent/',  kind: 'json_urlhaus',  category: 'ioc', region: 'Global', weight: 90 },
  { id: 'feodo',       name: 'Feodo Tracker (abuse.ch)', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', kind: 'json_feodo', category: 'ioc', region: 'Global', weight: 88 },
];

// ─── Threat actor + malware family lexicon (for tagging) ─────────────────────
const THREAT_ACTORS = [
  'Lazarus','APT28','Fancy Bear','APT29','Cozy Bear','APT41','APT40','APT10','Sandworm',
  'Volt Typhoon','Salt Typhoon','Midnight Blizzard','Scattered Spider','LockBit','ALPHV',
  'BlackCat','Cl0p','Clop','BlackBasta','Black Basta','Akira','Play','Royal','Rhysida',
  'Medusa','Qilin','RansomHub','Kimsuky','Turla','Gamaredon','Mustang Panda','Charming Kitten',
  'Wizard Spider','FIN7','FIN8','TA505','Conti','REvil','DarkSide','Hive','Vice Society',
  'Storm-','UNC','Cobalt Group','Andariel','Bl00dy','8Base','Hunters International',
];
const MALWARE_FAMILIES = [
  'Emotet','TrickBot','QakBot','Qbot','IcedID','BumbleBee','Cobalt Strike','Brute Ratel',
  'AsyncRAT','Remcos','Agent Tesla','Redline','RedLine','Raccoon','Vidar','Lumma','LummaC2',
  'Formbook','NanoCore','njRAT','DarkGate','PikaBot','Gootloader','SocGholish','Latrodectus',
  'Amadey','SmokeLoader','Bumblebee','Ursnif','Gozi','Dridex','Zloader','Mirai','Gh0st',
  'PlugX','ShadowPad','Sliver','Havoc','Meterpreter','XWorm','Rhadamanthys','StealC',
];

// ─── Category / severity keyword signals ─────────────────────────────────────
const CATEGORY_SIGNALS = [
  { cat: 'ransomware', kw: ['ransomware','ransom','encrypt','extortion','data leak site','double extortion'] },
  { cat: 'breach',     kw: ['data breach','breached','leaked','exposed database','data leak','stolen data','records exposed'] },
  { cat: 'apt',        kw: ['apt','nation-state','state-sponsored','espionage','threat actor','advanced persistent'] },
  { cat: 'malware',    kw: ['malware','trojan','backdoor','loader','infostealer','stealer','rat ','botnet','rootkit','worm'] },
  { cat: 'phishing',   kw: ['phishing','smishing','spear-phishing','credential harvest','business email compromise','bec '] },
  { cat: 'exploit',    kw: ['zero-day','zero day','0-day','exploit','actively exploited','in the wild','proof-of-concept','poc'] },
  { cat: 'vulnerability', kw: ['vulnerability','vulnerabilit','cve-','patch','security update','flaw'] },
];
const CRITICAL_KW = ['zero-day','0-day','actively exploited','in the wild','mass exploitation','critical','wormable','unauthenticated rce','emergency patch'];
const HIGH_KW     = ['ransomware','breach','rce','remote code execution','exploit','nation-state','supply chain','backdoor'];

// ─── Small stable hash for dedupe ids ────────────────────────────────────────
function djb2(str = '') {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}
function normalizeUrl(u = '') {
  return u.trim().toLowerCase().replace(/[#?].*$/, '').replace(/\/+$/, '');
}
function intelId(url, title) {
  const key = normalizeUrl(url) || (title || '').trim().toLowerCase();
  return 'gi_' + djb2(key);
}

// ─── Bounded, timed fetch ─────────────────────────────────────────────────────
async function timedFetch(url, { timeoutMs = 9000, json = false } = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'CYBERDUDEBIVASH-SecurityHub/1.0 (+https://cyberdudebivash.in; research)',
        'Accept': json ? 'application/json' : 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
      },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return json ? await res.json() : await res.text();
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// ─── STAGE 1+2: fetch + normalize an RSS/Atom source ─────────────────────────
function tag(block, names) {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</${n}>`, 'i'));
    if (m && m[1] != null && m[1].trim()) return m[1].trim();
  }
  return '';
}
function stripHtml(s = '') { return s.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/\s+/g, ' ').trim(); }

function parseFeed(xml, source, maxItems) {
  const blocks = xml.match(/<item[\s>][\s\S]*?<\/item>/gi)
              || xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi)
              || [];
  const out = [];
  for (const block of blocks.slice(0, maxItems)) {
    const title = stripHtml(tag(block, ['title']));
    let link = tag(block, ['link']);
    if (!link) {
      const href = block.match(/<link[^>]*href="([^"]+)"/i);
      link = href ? href[1] : '';
    }
    const pub = tag(block, ['pubDate', 'published', 'updated', 'dc:date']);
    const summary = stripHtml(tag(block, ['description', 'summary', 'content:encoded', 'content'])).slice(0, 600);
    if (!title || !link) continue;

    let published_at = null;
    try { const d = new Date(pub); if (!isNaN(d)) published_at = d.toISOString(); } catch {}

    out.push({
      title: title.slice(0, 300),
      url: link,
      summary,
      source: source.id,
      source_name: source.name,
      category: source.category,
      region: source.region,
      weight: source.weight,
      published_at,
    });
  }
  return out;
}

// ─── STAGE 1+2: abuse.ch JSON parsers ────────────────────────────────────────
function parseThreatFox(data, source) {
  // ThreatFox recent export: { "id": [ {ioc, ioc_type, malware, threat_type, confidence_level, first_seen, reference} ] }
  const rows = [];
  const bag = data && typeof data === 'object' ? Object.values(data) : [];
  for (const arr of bag) {
    const r = Array.isArray(arr) ? arr[0] : arr;
    if (!r || !r.ioc) continue;
    rows.push(r);
  }
  return rows.slice(0, 60).map(r => ({
    title: `ThreatFox IOC: ${r.malware_printable || r.malware || r.threat_type || 'malicious'} — ${r.ioc_type || 'ioc'}`.slice(0, 300),
    url: r.reference || `https://threatfox.abuse.ch/ioc/${r.id || ''}`,
    summary: `Malware: ${r.malware_printable || r.malware || 'unknown'}. Type: ${r.threat_type || 'ioc'}. IOC: ${r.ioc}. Confidence: ${r.confidence_level ?? '?'}%.`,
    source: source.id, source_name: source.name, category: 'ioc', region: source.region, weight: source.weight,
    published_at: r.first_seen ? safeIso(r.first_seen) : null,
    _ioc: r.ioc, _malware: r.malware_printable || r.malware,
  }));
}
function parseUrlhaus(data, source) {
  // URLhaus recent: { "urls" or object keyed } — the json_recent export is an object of arrays
  const rows = [];
  const bag = data && typeof data === 'object' ? Object.values(data) : [];
  for (const arr of bag) {
    const r = Array.isArray(arr) ? arr[0] : arr;
    if (!r || !r.url) continue;
    rows.push(r);
  }
  return rows.slice(0, 60).map(r => ({
    title: `URLhaus: malicious URL (${r.threat || 'malware_download'})`.slice(0, 300),
    url: r.urlhaus_reference || 'https://urlhaus.abuse.ch/',
    summary: `Malicious URL flagged by URLhaus. Threat: ${r.threat || 'malware_download'}. Status: ${r.url_status || 'unknown'}. Tags: ${(r.tags || []).join(', ')}.`,
    source: source.id, source_name: source.name, category: 'ioc', region: source.region, weight: source.weight,
    published_at: r.dateadded ? safeIso(r.dateadded) : null,
    _ioc: r.url, _malware: (r.tags || [])[0],
  }));
}
function parseFeodo(data, source) {
  const rows = Array.isArray(data) ? data : [];
  return rows.slice(0, 60).map(r => ({
    title: `Feodo Tracker: ${r.malware || 'botnet'} C2 — ${r.ip_address}`.slice(0, 300),
    url: 'https://feodotracker.abuse.ch/browse/',
    summary: `Active botnet C2 server. Malware: ${r.malware || 'unknown'}. IP: ${r.ip_address}:${r.port || ''}. First seen: ${r.first_seen || '?'}.`,
    source: source.id, source_name: source.name, category: 'ioc', region: source.region, weight: source.weight,
    published_at: r.first_seen ? safeIso(r.first_seen) : null,
    _ioc: r.ip_address, _malware: r.malware,
  }));
}
function safeIso(s) { try { const d = new Date(String(s).replace(' ', 'T') + (String(s).includes('T') ? '' : 'Z')); return isNaN(d) ? null : d.toISOString(); } catch { return null; } }

async function fetchSource(source, maxItems) {
  try {
    if (source.kind === 'json_threatfox') { const d = await timedFetch(source.url, { json: true }); return d ? parseThreatFox(d, source) : []; }
    if (source.kind === 'json_urlhaus')   { const d = await timedFetch(source.url, { json: true }); return d ? parseUrlhaus(d, source) : []; }
    if (source.kind === 'json_feodo')     { const d = await timedFetch(source.url, { json: true }); return d ? parseFeodo(d, source) : []; }
    const xml = await timedFetch(source.url);
    return xml && typeof xml === 'string' ? parseFeed(xml, source, maxItems) : [];
  } catch { return []; }
}

// ─── STAGE 3: enrich (IOCs, CVEs, actors, malware, category, tags) ───────────
function enrich(item) {
  const text = `${item.title}\n${item.summary}`;
  const lc = text.toLowerCase();

  const cveIds = Array.from(new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(s => s.toUpperCase())));
  const actors = THREAT_ACTORS.filter(a => lc.includes(a.toLowerCase()));
  const malware = Array.from(new Set([
    ...MALWARE_FAMILIES.filter(m => lc.includes(m.toLowerCase())),
    ...(item._malware ? [item._malware] : []),
  ].filter(Boolean)));

  // IOCs — for OSINT text pull from body; for abuse.ch use the provided indicator.
  let iocs = [];
  if (item._ioc) {
    iocs = [{ type: guessIocType(item._ioc), value: item._ioc }];
  } else {
    try { iocs = (extractIOCsFromText(text, { maxPerType: 8 }) || []).map(i => ({ type: i.type, value: i.value })); } catch { iocs = []; }
  }

  // Category — start from the source's category, refine from content signals.
  let category = item.category;
  if (category !== 'ioc') {
    for (const sig of CATEGORY_SIGNALS) {
      if (sig.kw.some(k => lc.includes(k))) { category = sig.cat; break; }
    }
  }

  const tags = Array.from(new Set([
    category,
    ...(cveIds.length ? ['cve'] : []),
    ...(actors.length ? ['threat-actor'] : []),
    ...(malware.length ? ['malware'] : []),
    ...(iocs.length ? ['ioc'] : []),
    item.region,
  ].filter(Boolean)));

  return { ...item, category, cve_ids: cveIds, actors, malware, iocs, tags };
}
function guessIocType(v = '') {
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ipv4';
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  if (/\./.test(v)) return 'domain';
  return 'indicator';
}

// ─── STAGE 4: analyse (severity + threat score) ──────────────────────────────
function analyse(item) {
  const lc = `${item.title} ${item.summary}`.toLowerCase();

  let severity = 'MEDIUM';
  if (CRITICAL_KW.some(k => lc.includes(k))) severity = 'CRITICAL';
  else if (HIGH_KW.some(k => lc.includes(k)) || item.actors.length || item.category === 'ransomware' || item.category === 'apt') severity = 'HIGH';
  else if (item.category === 'ioc' || item.category === 'news') severity = item.category === 'ioc' ? 'MEDIUM' : 'LOW';

  const sevBase = { CRITICAL: 60, HIGH: 42, MEDIUM: 25, LOW: 12 }[severity];

  // Recency: newest gets a strong boost so breaking intel ranks first.
  const ageHrs = item.published_at ? (Date.now() - new Date(item.published_at).getTime()) / 3.6e6 : 72;
  const recency = ageHrs <= 6 ? 22 : ageHrs <= 24 ? 16 : ageHrs <= 72 ? 9 : ageHrs <= 168 ? 4 : 0;

  const sourceBoost = Math.round((item.weight || 70) / 10); // 7–10
  const signalBoost = (item.cve_ids.length ? 4 : 0) + (item.actors.length ? 4 : 0)
                    + (item.malware.length ? 3 : 0) + (item.iocs.length ? 2 : 0);

  const threat_score = Math.max(1, Math.min(100, sevBase + recency + sourceBoost + signalBoost));
  const is_breaking = ageHrs <= 6 ? 1 : 0;
  return { ...item, severity, threat_score, is_breaking };
}

// ─── STAGE 5+6: draft + format the hourly briefing ───────────────────────────
function buildBriefing(items) {
  const sorted = [...items].sort((a, b) => {
    if (a.is_breaking !== b.is_breaking) return b.is_breaking - a.is_breaking;
    return (b.threat_score - a.threat_score) || (new Date(b.published_at || 0) - new Date(a.published_at || 0));
  });
  const top = sorted.slice(0, 12);
  const bySev = items.reduce((m, i) => (m[i.severity] = (m[i.severity] || 0) + 1, m), {});
  const byCat = items.reduce((m, i) => (m[i.category] = (m[i.category] || 0) + 1, m), {});
  const actors = Array.from(new Set(items.flatMap(i => i.actors))).slice(0, 15);
  const malware = Array.from(new Set(items.flatMap(i => i.malware))).slice(0, 15);
  const cves = Array.from(new Set(items.flatMap(i => i.cve_ids))).slice(0, 20);
  const breaking = sorted.filter(i => i.is_breaking).length;

  const level = bySev.CRITICAL >= 3 ? 'CRITICAL' : (bySev.CRITICAL || (bySev.HIGH || 0) >= 5) ? 'HIGH' : (bySev.HIGH ? 'ELEVATED' : 'GUARDED');
  const headline = `${breaking} breaking item(s) in the last 6h · ${bySev.CRITICAL || 0} critical, ${bySev.HIGH || 0} high across ${Object.keys(byCat).length} categories`;

  return {
    generated_at: new Date().toISOString(),
    threat_level: level,
    headline,
    total_items: items.length,
    breaking_count: breaking,
    by_severity: bySev,
    by_category: byCat,
    active_actors: actors,
    active_malware: malware,
    referenced_cves: cves,
    top_intel: top.map(t => ({
      intel_id: t.intel_id, title: t.title, url: t.url, source_name: t.source_name,
      category: t.category, severity: t.severity, threat_score: t.threat_score,
      is_breaking: !!t.is_breaking, published_at: t.published_at,
    })),
  };
}

// ─── STAGE 7: publish — ensure table, dedupe, upsert into D1 + KV ────────────
export async function ensureGlobalIntelTable(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS global_intel (
    intel_id     TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    summary      TEXT,
    url          TEXT,
    source       TEXT,
    source_name  TEXT,
    category     TEXT,
    region       TEXT,
    severity     TEXT,
    threat_score INTEGER DEFAULT 0,
    is_breaking  INTEGER DEFAULT 0,
    cve_ids      TEXT DEFAULT '[]',
    actors       TEXT DEFAULT '[]',
    malware      TEXT DEFAULT '[]',
    iocs         TEXT DEFAULT '[]',
    tags         TEXT DEFAULT '[]',
    published_at TEXT,
    ingested_at  TEXT
  )`).run();
  // Indexes for the freshest-first display queries.
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_gi_published ON global_intel(published_at DESC)`).run().catch(() => {});
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_gi_score ON global_intel(threat_score DESC)`).run().catch(() => {});
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_gi_category ON global_intel(category)`).run().catch(() => {});
}

async function upsertItems(db, items) {
  let inserted = 0;
  const now = new Date().toISOString();
  for (const it of items) {
    try {
      const res = await db.prepare(
        `INSERT INTO global_intel
          (intel_id,title,summary,url,source,source_name,category,region,severity,threat_score,is_breaking,cve_ids,actors,malware,iocs,tags,published_at,ingested_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(intel_id) DO UPDATE SET
           severity=excluded.severity, threat_score=excluded.threat_score, is_breaking=excluded.is_breaking,
           cve_ids=excluded.cve_ids, actors=excluded.actors, malware=excluded.malware, iocs=excluded.iocs,
           tags=excluded.tags, summary=excluded.summary`
      ).bind(
        it.intel_id, it.title, it.summary || '', it.url || '', it.source, it.source_name,
        it.category, it.region || '', it.severity, it.threat_score, it.is_breaking,
        JSON.stringify(it.cve_ids || []), JSON.stringify(it.actors || []),
        JSON.stringify(it.malware || []), JSON.stringify(it.iocs || []), JSON.stringify(it.tags || []),
        it.published_at || now, now,
      ).run();
      if (res?.meta?.changes) inserted += 1;
    } catch { /* skip a bad row, keep the batch */ }
  }
  return inserted;
}

// ─── ORCHESTRATOR: run the full 8-stage pipeline ─────────────────────────────
export async function runGlobalIntelFirehose(env, { maxPerFeed = 12 } = {}) {
  const started = Date.now();
  const db = env?.SECURITY_HUB_DB;
  const errors = [];

  // 1. FETCH (parallel, bounded, fault-isolated)
  const results = await Promise.allSettled(INTEL_SOURCES.map(s => fetchSource(s, maxPerFeed)));
  let raw = [];
  const sourcesOk = [];
  results.forEach((r, i) => {
    if (r.status === 'fulfilled' && Array.isArray(r.value) && r.value.length) {
      raw = raw.concat(r.value);
      sourcesOk.push(INTEL_SOURCES[i].id);
    } else {
      errors.push(INTEL_SOURCES[i].id);
    }
  });

  // 2+3+4. INGEST → ENRICH → ANALYSE
  const analysed = raw.map(item => analyse(enrich({ ...item, intel_id: intelId(item.url, item.title) })));

  // Dedupe by intel_id, preferring the higher threat score.
  const dedup = new Map();
  for (const it of analysed) {
    const prev = dedup.get(it.intel_id);
    if (!prev || it.threat_score > prev.threat_score) dedup.set(it.intel_id, it);
  }
  const items = Array.from(dedup.values());

  // 5+6. DRAFT + FORMAT the briefing
  const briefing = buildBriefing(items);

  // 7. PUBLISH — D1 + KV
  let inserted = 0;
  if (db) {
    try { await ensureGlobalIntelTable(db); inserted = await upsertItems(db, items); }
    catch (e) { errors.push('d1:' + (e?.message || 'store_failed')); }
    // Prune to a rolling window so the table never grows unbounded (keep 60 days).
    try { await db.prepare(`DELETE FROM global_intel WHERE published_at < datetime('now','-60 days')`).run(); } catch {}
  }
  if (env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put('global_intel:briefing:v1', JSON.stringify(briefing), { expirationTtl: 7200 });
    } catch (e) { errors.push('kv:' + (e?.message || 'put_failed')); }
  }

  return {
    ok: true,
    sources_total: INTEL_SOURCES.length,
    sources_ok: sourcesOk.length,
    sources_failed: errors.filter(e => !e.includes(':')).length,
    fetched: raw.length,
    unique_items: items.length,
    inserted,
    breaking: briefing.breaking_count,
    threat_level: briefing.threat_level,
    duration_ms: Date.now() - started,
    errors: errors.slice(0, 20),
  };
}
