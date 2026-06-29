/**
 * CYBERDUDEBIVASH® AI Security Hub — Cyber Signal Radar Service v1.0
 * P3.0-003 — Unified RadarService
 * Responsibilities: collect → normalize → deduplicate → score → cache
 * Reuses: threat_intel (D1), ai_threat_feed (D1), SECURITY_HUB_KV
 */

export const KV_SNAPSHOT_KEY  = 'radar:snapshot:v1';
export const KV_SNAPSHOT_TTL  = 300;   // 5 minutes
export const CACHE_HEADER_TTL = 300;

const MAX_SIGNALS = 200;
const PUBLISHER   = 'CYBERDUDEBIVASH® Cyber Signal Radar';

// ── Severity ranking ──────────────────────────────────────────────────────────
const SEV_RANK = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, INFORMATIONAL:0, UNKNOWN:0 };

function normSeverity(raw) {
  const s = String(raw || '').toUpperCase().trim();
  if (SEV_RANK[s] !== undefined) return s;
  if (s.includes('CRIT')) return 'CRITICAL';
  if (s.includes('HIGH')) return 'HIGH';
  if (s.includes('MED'))  return 'MEDIUM';
  if (s.includes('LOW'))  return 'LOW';
  return 'MEDIUM';
}

function confidenceScore(row) {
  let score = 40;
  const cvss = parseFloat(row.cvss ?? row.cvss_score ?? 0) || 0;
  if (cvss >= 9.0)      score += 25;
  else if (cvss >= 7.0) score += 15;
  else if (cvss >= 4.0) score += 5;
  if (row.actively_exploited || row.exploit_status === 'confirmed') score += 20;
  if (row.known_ransomware)     score += 15;
  const epss = parseFloat(row.epss_score ?? 0) || 0;
  if (epss > 0.5)  score += 10;
  else if (epss > 0.1) score += 5;
  const src = (row.source || '').toUpperCase();
  if (src === 'NVD' || src === 'CISA') score += 5;
  return Math.min(100, score);
}

function safeJson(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch { return []; } }
  return [];
}

// ── Normalize a D1 row from either threat_intel or ai_threat_feed ─────────────
function normalizeRow(row, source_table) {
  const sev = normSeverity(row.severity);
  const id  = row.cve_id || row.advisory_id || row.vuln_id || row.id || null;
  const cvss = parseFloat(row.cvss ?? row.cvss_score ?? 0) || 0;
  return {
    id:                 id || `sig_${Date.now().toString(36)}`,
    title:              row.title || id || 'Security Advisory',
    severity:           sev,
    severity_rank:      SEV_RANK[sev] ?? 0,
    cvss,
    epss:               parseFloat(row.epss_score ?? 0) || 0,
    actively_exploited: !!(row.actively_exploited || row.exploit_status === 'confirmed'),
    known_ransomware:   !!(row.known_ransomware),
    source:             row.source || PUBLISHER,
    source_table,
    published_at:       row.published_at || row.created_at || null,
    confidence:         confidenceScore(row),
    tags:               safeJson(row.tags || row.weakness_types || row.owasp_categories || '[]'),
    threat_actor:       row.threat_actor || row.actor_name || null,
    campaign:           row.campaign_name || row.campaign || null,
    ransomware_group:   row.ransomware_group || null,
  };
}

// ── Collect from both D1 tables ───────────────────────────────────────────────
async function collectFromD1(db) {
  const signals = [];

  // 1. threat_intel (main CTI pipeline)
  try {
    const r = await db.prepare(
      `SELECT cve_id, id, title, severity, cvss, cvss_score, epss_score,
              actively_exploited, known_ransomware, source, published_at, created_at,
              weakness_types, exploit_status
       FROM threat_intel
       ORDER BY created_at DESC LIMIT 100`
    ).all();
    if (r.results?.length) r.results.forEach(row => signals.push(normalizeRow(row, 'threat_intel')));
  } catch {}

  // 2. ai_threat_feed (AI/LLM-specific radar — from aiThreatRadar.js)
  try {
    const r = await db.prepare(
      `SELECT id, advisory_id, title, severity, cvss, epss_score,
              actively_exploited, known_ransomware, source, published_at, created_at,
              owasp_categories, mitre_atlas_techniques, threat_actor
       FROM ai_threat_feed
       ORDER BY created_at DESC LIMIT 100`
    ).all();
    if (r.results?.length) r.results.forEach(row => signals.push(normalizeRow(row, 'ai_threat_feed')));
  } catch {}

  return signals;
}

// ── Deduplicate by id, keep highest confidence ────────────────────────────────
function deduplicateSignals(signals) {
  const seen = new Map();
  for (const sig of signals) {
    const k = sig.id;
    if (!seen.has(k) || sig.confidence > seen.get(k).confidence) seen.set(k, sig);
  }
  return Array.from(seen.values())
    .sort((a, b) => b.severity_rank - a.severity_rank || b.confidence - a.confidence || b.cvss - a.cvss)
    .slice(0, MAX_SIGNALS);
}

// ── Build the unified Radar Snapshot ─────────────────────────────────────────
function buildSnapshot(signals, sourceCount) {
  const dist = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  const campaigns  = {};
  const actors     = {};
  const ransomware = {};
  let aiThreats    = 0;

  for (const s of signals) {
    if (dist[s.severity] !== undefined) dist[s.severity]++;
    if (s.campaign)       campaigns[s.campaign]           = (campaigns[s.campaign]     || 0) + 1;
    if (s.threat_actor)   actors[s.threat_actor]          = (actors[s.threat_actor]    || 0) + 1;
    if (s.ransomware_group) ransomware[s.ransomware_group]= (ransomware[s.ransomware_group] || 0) + 1;
    if (s.source_table === 'ai_threat_feed') aiThreats++;
  }

  const topCampaigns  = Object.entries(campaigns).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([n,c])=>({name:n,count:c}));
  const topActors     = Object.entries(actors).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([n,c])=>({name:n,count:c}));
  const topRansomware = Object.entries(ransomware).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([n,c])=>({name:n,count:c}));
  const trending      = [...signals].sort((a,b)=>b.epss-a.epss||b.cvss-a.cvss).slice(0,15);
  const latestCVEs    = signals.filter(s=>s.id?.startsWith('CVE-')).slice(0,10)
    .map(s=>({id:s.id,severity:s.severity,cvss:s.cvss,title:s.title,published_at:s.published_at}));

  const aiSummary = aiThreats > 0
    ? `${aiThreats} AI/LLM-specific signals detected. ` +
      `${dist.CRITICAL} critical, ${dist.HIGH} high severity. ` +
      `Monitoring LangChain, transformers, MLflow, vLLM and ${sourceCount} active sources.`
    : signals.length > 0
      ? `${signals.length} signals active across ${sourceCount} monitored sources. ` +
        `${dist.CRITICAL}C / ${dist.HIGH}H / ${dist.MEDIUM}M / ${dist.LOW}L.`
      : `Radar operational — monitoring ${sourceCount} sources. No active signals.`;

  return {
    timestamp:             new Date().toISOString(),
    radar_health:          signals.length > 0 ? 'OPERATIONAL' : 'NOMINAL',
    total_signals:         signals.length,
    source_count:          sourceCount,
    severity_distribution: dist,
    top_campaigns:         topCampaigns,
    active_threat_actors:  topActors,
    ransomware_activity:   topRansomware,
    ai_threat_summary:     aiSummary,
    ai_threats_detected:   aiThreats,
    latest_cves:           latestCVEs,
    trending_threats:      trending.map(s=>({id:s.id,severity:s.severity,cvss:s.cvss,epss:s.epss,title:s.title,actively_exploited:s.actively_exploited})),
    critical_count:        dist.CRITICAL,
    high_count:            dist.HIGH,
    publisher:             PUBLISHER,
    // Full signals kept for enterprise (not exposed by public sanitizer)
    _signals:              signals,
  };
}

// ── Strip enterprise-only fields for public responses ────────────────────────
export function sanitizeForPublic(snapshot) {
  return {
    timestamp:             snapshot.timestamp,
    radar_health:          snapshot.radar_health,
    total_signals:         snapshot.total_signals,
    source_count:          snapshot.source_count,
    severity_distribution: snapshot.severity_distribution,
    ai_threat_summary:     snapshot.ai_threat_summary,
    latest_cves:           snapshot.latest_cves,
    trending_threats:      snapshot.trending_threats.slice(0, 5),
    top_campaigns:         snapshot.top_campaigns,
    critical_count:        snapshot.critical_count,
    publisher:             snapshot.publisher,
    cache_ttl:             KV_SNAPSHOT_TTL,
  };
}

// ── RadarService ──────────────────────────────────────────────────────────────
export class RadarService {
  constructor(env) {
    this.env = env;
    this.kv  = env.SECURITY_HUB_KV;
    this.db  = env.SECURITY_HUB_DB;
  }

  async getSnapshot({ forceRefresh = false } = {}) {
    // 1. KV edge cache (5-min TTL)
    if (!forceRefresh && this.kv) {
      try {
        const cached = await this.kv.get(KV_SNAPSHOT_KEY, 'json');
        if (cached) return { snapshot: cached, cached: true };
      } catch {}
    }

    // 2. Collect → normalize → deduplicate → build
    const signals     = this.db ? await collectFromD1(this.db) : [];
    const deduped     = deduplicateSignals(signals);
    const sourceCount = deduped.length > 0 ? 4 : (this.db ? 1 : 0); // threat_intel, ai_threat_feed, NVD cache, OSV cache
    const snapshot    = buildSnapshot(deduped, sourceCount);

    // 3. Cache
    if (this.kv) {
      try {
        // Remove _signals from KV-stored copy (enterprise serves from memory)
        const { _signals, ...kv_snapshot } = snapshot;
        await this.kv.put(KV_SNAPSHOT_KEY, JSON.stringify(kv_snapshot), { expirationTtl: KV_SNAPSHOT_TTL });
      } catch {}
    }

    return { snapshot, cached: false };
  }

  async getPublicSnapshot() {
    const { snapshot, cached } = await this.getSnapshot();
    return { ...sanitizeForPublic(snapshot), _cached: cached };
  }

  async getLatest({ limit = 20 } = {}) {
    const { snapshot } = await this.getSnapshot();
    return snapshot.latest_cves.slice(0, Math.min(limit, 20));
  }

  async getSummary() {
    const { snapshot, cached } = await this.getSnapshot();
    return {
      timestamp:             snapshot.timestamp,
      radar_health:          snapshot.radar_health,
      total_signals:         snapshot.total_signals,
      severity_distribution: snapshot.severity_distribution,
      ai_threat_summary:     snapshot.ai_threat_summary,
      critical_count:        snapshot.critical_count,
      high_count:            snapshot.high_count,
      source_count:          snapshot.source_count,
      publisher:             snapshot.publisher,
      _cached:               cached,
    };
  }

  async getTrending({ limit = 10 } = {}) {
    const { snapshot } = await this.getSnapshot();
    return snapshot.trending_threats.slice(0, Math.min(limit, 10));
  }

  // Enterprise: full snapshot with confidence scores and actor intel
  async getEnterpriseSnapshot({ industry = null } = {}) {
    const { snapshot } = await this.getSnapshot();
    const { _signals, ...safe } = snapshot;
    const signals = (_signals || []).map(s => ({
      id:                 s.id,
      title:              s.title,
      severity:           s.severity,
      cvss:               s.cvss,
      epss:               s.epss,
      confidence:         s.confidence,
      actively_exploited: s.actively_exploited,
      known_ransomware:   s.known_ransomware,
      threat_actor:       s.threat_actor,
      campaign:           s.campaign,
      ransomware_group:   s.ransomware_group,
      tags:               s.tags,
      source:             s.source,
      published_at:       s.published_at,
    }));
    return {
      ...safe,
      signals: industry
        ? signals.filter(s => !industry || s.tags?.some(t => String(t).toLowerCase().includes(industry.toLowerCase())))
        : signals,
      enterprise: true,
    };
  }
}
