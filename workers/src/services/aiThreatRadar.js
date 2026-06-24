/**
 * CYBERDUDEBIVASH AI Security Hub — AI Threat Radar v1.0
 *
 * Unlike aiThreatIngestion.js (which passively re-filters whatever the generic
 * CTI pipeline already fetched for unrelated reasons), this module makes its
 * OWN dedicated, targeted outbound fetches aimed specifically at the AI/LLM
 * ecosystem, so the AI threat feed gets genuinely fresh signal instead of
 * depending on AI-relevant CVEs happening to fall inside a 7-day generic batch.
 *
 * Sources monitored:
 *   1. OSV.dev   — batched vulnerability lookup for a curated watchlist of
 *                  AI/ML packages (PyPI + npm). No API key, no rate-limit risk.
 *   2. NVD       — keywordSearch against AI/LLM-specific terms, one phrase per
 *                  run rotated hourly across the whole list, over a 120-day
 *                  window (NVD's max range) — AI CVEs are sparse, so a wide
 *                  window is required to ever surface anything.
 *   3. GitHub    — Security Advisories REST API filtered by `affects=<pkg>`
 *                  per ecosystem, so it returns only AI-package advisories
 *                  instead of parsing GitHub's entire public Atom feed.
 *
 * Writes into the same ai_threat_feed table as aiThreatIngestion.js, reusing
 * its OWASP/MITRE mapping + upsert logic so both pipelines converge on one
 * schema and one conflict-resolution rule. Persists a status snapshot to KV
 * for the radar health endpoint (handlers/aiThreatIntel.js GET
 * /api/ai-security/threat-feed/radar-status).
 */

import {
  ensureAIThreatFeedTable,
  upsertAIThreatFeedRows,
  mapToOwaspLLM,
  mapToMitreAtlas,
  mapToMitreAttack,
  classifyFeedType,
} from './aiThreatIngestion.js';

const OSV_BATCH_URL    = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL     = 'https://api.osv.dev/v1/vulns';
const NVD_API_BASE     = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const GH_ADVISORY_API  = 'https://api.github.com/advisories';
const RADAR_TIMEOUT_MS = 12000;
export const RADAR_STATUS_KV_KEY = 'ai_threat_radar:status';
const RADAR_USER_AGENT = 'CYBERDUDEBIVASH-AIThreatRadar/1.0 (security-research@cyberdudebivash.in)';

// Cap how many full vulnerability records we fetch per OSV run, so a watchlist
// hit doesn't blow past the Workers per-invocation subrequest budget.
const OSV_DETAIL_FETCH_CAP = 12;

// ─── Curated AI/ML package watchlist — OSV.dev + GitHub Advisory API both key
// off (name, ecosystem) pairs, so one list drives both sources. ──────────────
export const AI_RADAR_PACKAGES = [
  { name: 'langchain', ecosystem: 'PyPI' },
  { name: 'llama-index', ecosystem: 'PyPI' },
  { name: 'transformers', ecosystem: 'PyPI' },
  { name: 'torch', ecosystem: 'PyPI' },
  { name: 'tensorflow', ecosystem: 'PyPI' },
  { name: 'mlflow', ecosystem: 'PyPI' },
  { name: 'gradio', ecosystem: 'PyPI' },
  { name: 'ray', ecosystem: 'PyPI' },
  { name: 'vllm', ecosystem: 'PyPI' },
  { name: 'onnxruntime', ecosystem: 'PyPI' },
  { name: 'chromadb', ecosystem: 'PyPI' },
  { name: 'weaviate-client', ecosystem: 'PyPI' },
  { name: 'pymilvus', ecosystem: 'PyPI' },
  { name: 'pyautogen', ecosystem: 'PyPI' },
  { name: 'crewai', ecosystem: 'PyPI' },
  { name: 'semantic-kernel', ecosystem: 'PyPI' },
  { name: 'langgraph', ecosystem: 'PyPI' },
  { name: 'openai', ecosystem: 'PyPI' },
  { name: 'anthropic', ecosystem: 'PyPI' },
  { name: 'huggingface-hub', ecosystem: 'PyPI' },
  { name: 'accelerate', ecosystem: 'PyPI' },
  { name: 'sentence-transformers', ecosystem: 'PyPI' },
  { name: 'ollama', ecosystem: 'PyPI' },
  { name: 'langchain', ecosystem: 'npm' },
  { name: 'openai', ecosystem: 'npm' },
];

// NVD only accepts ONE keywordSearch phrase per call. Rotate by hour-of-day so
// coverage spreads across the whole list without hammering NVD's
// unauthenticated rate limit (5 req/30s) — only 1 extra NVD call per radar run.
export const NVD_RADAR_KEYWORDS = [
  'large language model', 'prompt injection', 'LangChain', 'PyTorch',
  'TensorFlow', 'Hugging Face', 'machine learning model', 'vector database',
  'model context protocol', 'Stable Diffusion', 'Ollama', 'jailbreak',
];

// ─── Safe fetch with timeout — local copy (threatIngestion.js's safeFetch
// isn't exported, and this module also needs POST + custom headers). ────────
async function safeFetchJSON(url, options = {}, timeoutMs = RADAR_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
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

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n - 3) + '...' : s;
}

// ─── Source 1: OSV.dev batched watchlist query ──────────────────────────────
export async function fetchOSVRadarSignals() {
  const body = JSON.stringify({
    queries: AI_RADAR_PACKAGES.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem } })),
  });
  const batchResult = await safeFetchJSON(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': RADAR_USER_AGENT },
    body,
  });
  if (!batchResult?.results) return [];

  // Collect unique vuln IDs across the whole watchlist, newest-modified first,
  // capped so the detail-lookup fan-out stays bounded.
  const seen = new Map(); // id -> modified timestamp
  for (const r of batchResult.results) {
    for (const v of r.vulns || []) {
      if (!seen.has(v.id) || (v.modified || '') > (seen.get(v.id) || '')) seen.set(v.id, v.modified || '');
    }
  }
  const ids = [...seen.entries()]
    .sort((a, b) => (b[1] || '').localeCompare(a[1] || ''))
    .slice(0, OSV_DETAIL_FETCH_CAP)
    .map(([id]) => id);

  const entries = [];
  for (const id of ids) {
    const vuln = await safeFetchJSON(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
      headers: { 'User-Agent': RADAR_USER_AGENT },
    });
    if (!vuln) continue;

    const cveAlias = (vuln.aliases || []).find(a => /^CVE-\d{4}-\d{4,}/.test(a));
    const advisoryRef = (vuln.references || []).find(r => r.type === 'ADVISORY')?.url
      || `https://osv.dev/vulnerability/${vuln.id}`;
    const pkgNames = [...new Set((vuln.affected || []).map(a => a.package?.name).filter(Boolean))];
    const severity = (vuln.database_specific?.severity || '').toUpperCase();

    entries.push({
      id: cveAlias || vuln.id,
      title: truncate(vuln.summary || vuln.id, 200),
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity) ? severity : 'MEDIUM',
      description: truncate(vuln.details || vuln.summary || '', 500),
      cve_id: cveAlias || null,
      source: 'osv',
      source_url: advisoryRef,
      published_at: vuln.published || vuln.modified || null,
      matched_on: pkgNames,
    });
  }
  return entries;
}

// ─── Source 2: NVD targeted keyword search (rotated, wide window) ───────────
export async function fetchNVDRadarKeyword() {
  const keyword = NVD_RADAR_KEYWORDS[Math.floor(Date.now() / 3600000) % NVD_RADAR_KEYWORDS.length];
  const now   = new Date();
  const start = new Date(now.getTime() - 120 * 86400 * 1000); // NVD max range = 120 days
  const fmt   = (d) => d.toISOString().replace(/\.\d+Z$/, '.000 UTC+00:00');
  const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keyword)}`
    + `&lastModStartDate=${encodeURIComponent(fmt(start))}`
    + `&lastModEndDate=${encodeURIComponent(fmt(now))}`
    + `&resultsPerPage=15`;

  const data = await safeFetchJSON(url, { headers: { 'User-Agent': RADAR_USER_AGENT } }, 15000);
  if (!data?.vulnerabilities) return [];

  return data.vulnerabilities.map(item => {
    const cve     = item.cve;
    const id      = cve.id;
    const desc    = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
    const metrics = cve.metrics || {};
    const cvssData = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData;
    const severity  = (cvssData?.baseSeverity || 'MEDIUM').toUpperCase();
    return {
      id,
      title: truncate(desc, 200) || id,
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity) ? severity : 'MEDIUM',
      description: truncate(desc, 500),
      cve_id: id,
      source: 'nvd_radar',
      source_url: `https://nvd.nist.gov/vuln/detail/${id}`,
      published_at: cve.published ? cve.published.split('T')[0] : null,
      matched_on: [keyword],
    };
  });
}

// ─── Source 3: GitHub Security Advisories REST API, affects=<watchlist> ─────
export async function fetchGitHubAdvisoryRadar() {
  const byEcosystem = { pip: [], npm: [] };
  for (const p of AI_RADAR_PACKAGES) {
    const eco = p.ecosystem === 'PyPI' ? 'pip' : p.ecosystem === 'npm' ? 'npm' : null;
    if (eco && !byEcosystem[eco].includes(p.name)) byEcosystem[eco].push(p.name);
  }

  const entries = [];
  for (const [eco, names] of Object.entries(byEcosystem)) {
    if (!names.length) continue;
    const url = `${GH_ADVISORY_API}?ecosystem=${eco}&affects=${encodeURIComponent(names.join(','))}`
      + `&per_page=20&sort=published&direction=desc`;
    const data = await safeFetchJSON(url, {
      headers: { 'User-Agent': RADAR_USER_AGENT, 'Accept': 'application/vnd.github+json' },
    });
    if (!Array.isArray(data)) continue;

    for (const a of data) {
      const matchedPkgs = [...new Set((a.vulnerabilities || []).map(v => v.package?.name).filter(Boolean))];
      entries.push({
        id: a.cve_id || a.ghsa_id,
        title: truncate(a.summary || a.ghsa_id, 200),
        severity: (a.severity || 'MEDIUM').toUpperCase(),
        description: truncate(a.description || a.summary || '', 500),
        cve_id: a.cve_id || null,
        source: 'github_advisory_api',
        source_url: a.html_url || `https://github.com/advisories/${a.ghsa_id}`,
        published_at: a.published_at || null,
        matched_on: matchedPkgs,
      });
    }
  }
  return entries;
}

// ─── Orchestrator — fan out to all 3 sources, classify, upsert, persist status
export async function runAIThreatRadar(env) {
  const startedAt = Date.now();
  const db = env?.DB;
  const result = { matched: 0, inserted: 0, sources: {}, errors: [] };
  if (!db) return result;

  await ensureAIThreatFeedTable(db);

  const sourceRunners = [
    ['osv', fetchOSVRadarSignals],
    ['nvd_radar', fetchNVDRadarKeyword],
    ['github_advisory_api', fetchGitHubAdvisoryRadar],
  ];

  const allEntries = [];
  for (const [name, runner] of sourceRunners) {
    try {
      const entries = await runner();
      result.sources[name] = entries.length;
      allEntries.push(...entries);
    } catch (e) {
      result.sources[name] = 0;
      result.errors.push(`${name}: ${e.message}`);
    }
  }

  // Dedupe across sources by final ai_threat_feed id (later source wins on conflict).
  const byId = new Map();
  for (const entry of allEntries) {
    if (!entry.id) continue;
    const haystack = [entry.title, entry.description, (entry.matched_on || []).join(' ')].join(' ').toLowerCase();
    const isCve = /^CVE-\d{4}-\d{4,}$/.test(entry.cve_id || '');
    byId.set(`ai_${entry.id}`, {
      id: `ai_${entry.id}`,
      feed_type: classifyFeedType(haystack, isCve),
      title: entry.title,
      description: entry.description,
      severity: entry.severity,
      cve_id: entry.cve_id || null,
      affected_frameworks: JSON.stringify(entry.matched_on || []),
      iocs: '[]',
      mitigations: '[]',
      owasp_ref: mapToOwaspLLM(haystack),
      attack_ref: mapToMitreAttack(haystack),
      atlas_ref: mapToMitreAtlas(haystack),
      source_url: entry.source_url || null,
      published_at: (() => {
        if (!entry.published_at) return Math.floor(Date.now() / 1000);
        const t = Date.parse(entry.published_at);
        return Number.isNaN(t) ? Math.floor(Date.now() / 1000) : Math.floor(t / 1000);
      })(),
      metadata: JSON.stringify({ ingested_from: 'ai_threat_radar', source: entry.source, matched_on: entry.matched_on || [] }),
    });
  }

  const matches = [...byId.values()];
  result.matched = matches.length;
  if (matches.length) {
    const upsertResult = await upsertAIThreatFeedRows(db, matches);
    result.inserted = upsertResult.inserted;
    result.errors.push(...upsertResult.errors);
  }

  result.duration_ms = Date.now() - startedAt;

  // Persist a status snapshot for the radar health endpoint. TTL'd at 6h (2x
  // the hourly cadence) so a stalled cron self-reports as offline rather than
  // serving an indefinitely-stale "last scan" timestamp to the dashboard.
  if (env?.SECURITY_HUB_KV) {
    try {
      await env.SECURITY_HUB_KV.put(RADAR_STATUS_KV_KEY, JSON.stringify({
        last_scan_at: new Date().toISOString(),
        duration_ms: result.duration_ms,
        sources_monitored: Object.keys(result.sources).length,
        packages_watched: AI_RADAR_PACKAGES.length,
        signals_found: result.matched,
        signals_inserted: result.inserted,
        source_breakdown: result.sources,
        errors: result.errors,
      }), { expirationTtl: 21600 });
    } catch { /* non-fatal — status read falls back to "unknown" */ }
  }

  return result;
}
