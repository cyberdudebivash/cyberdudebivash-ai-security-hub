/**
 * CYBERDUDEBIVASH Threat Intelligence API Economy — v1.0
 * Phase B Revenue Product 3: monetized /api/intel/* endpoints
 *
 * Endpoints:
 *   GET/POST /api/intel/ioc       — IOC enrichment + verdict + context
 *   GET/POST /api/intel/cve       — CVE lookup with CVSS, KEV, MITRE mapping
 *   GET/POST /api/intel/actor     — Threat actor profiles (TTPs, campaigns, targets)
 *   GET/POST /api/intel/ttp       — MITRE ATT&CK technique lookup
 *   GET/POST /api/intel/risk      — Composite risk score for domain/IP/org
 *
 * Tier gates:
 *   Developer  (FREE):       100 req/day  — IOC + CVE basic only
 *   Business   (PRO):      1,000 req/day  — all 5 endpoints + historical + STIX
 *   Enterprise (ENTERPRISE): unlimited   — all endpoints + STIX export + webhook
 *
 * STIX 2.1 bundle export lives at GET /api/v1/intel/stix.json (PRO+, per the
 * public pricing matrix); `stix_available` in responses reflects the caller's
 * real entitlement. Per-minute burst limits (canonical tier table: FREE 2/min,
 * STARTER 5, PRO 20, ENTERPRISE 60, MSSP 120) are enforced here in addition to
 * the daily quota — both were advertised, only daily was previously enforced.
 */

import { callClaude } from '../core/mythosAIProvider.js';
import { lookupCVE   } from '../services/cveEngine.js';
import { checkEntitlement, FEATURES } from '../middleware/entitlementCheck.js';

// ─── Utility ─────────────────────────────────────────────────────────────────
function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Intel-Powered-By': 'CYBERDUDEBIVASH SENTINEL APEX',
    },
  });
}

function tierLimits(tier) {
  // `stix` mirrors the public pricing matrix (FEED_TIERS in intelMonetization.js):
  // STIX 2.1 export is sold as PRO+ — this flag previously said PRO:false while
  // pricing.json advertised PRO stix_export:true.
  if (tier === 'ENTERPRISE' || tier === 'MSSP') return { daily: Infinity, burst: 60,  endpoints: ['ioc','cve','actor','ttp','risk'], stix: true  };
  if (tier === 'TEAM')  return { daily: 10000, burst: 30, endpoints: ['ioc','cve','actor','ttp','risk'], stix: true  };
  if (tier === 'PRO')   return { daily: 1000,  burst: 20, endpoints: ['ioc','cve','actor','ttp','risk'], stix: true  };
  if (tier === 'STARTER') return { daily: 100, burst: 5,  endpoints: ['ioc','cve'],                      stix: false };
  return                       { daily: 100,   burst: 2,  endpoints: ['ioc','cve'],                      stix: false };
}

// Per-minute burst check shared by all /api/intel/* endpoints. Best-effort KV
// counter — fails open on KV outage (availability over enforcement, risk R-14).
async function checkIntelBurst(env, authCtx, limits) {
  const kv = env.KV || env.SECURITY_HUB_KV;
  if (!kv || !(limits.burst > 0)) return { allowed: true };
  const id     = authCtx?.userId || authCtx?.id || authCtx?.user_id || `ip:${authCtx?.ip || 'unknown'}`;
  const minute = new Date().toISOString().slice(0, 16);
  const key    = `intel_burst:${id}:${minute}`;
  try {
    const current = parseInt(await kv.get(key) || '0', 10);
    if (current >= limits.burst) {
      return { allowed: false, reason: `Rate limit exceeded: ${limits.burst} requests/minute on your plan. Retry in 60s.`, retry_after: 60 };
    }
    await kv.put(key, String(current + 1), { expirationTtl: 120 });
    return { allowed: true };
  } catch { return { allowed: true }; }
}

// Feature required per endpoint (for entitlement table check)
const ENDPOINT_FEATURE = {
  ioc:   FEATURES.API_ACCESS,
  cve:   FEATURES.API_ACCESS,
  actor: FEATURES.THREAT_FEED_FULL,
  ttp:   FEATURES.THREAT_FEED_FULL,
  risk:  FEATURES.THREAT_FEED_FULL,
};

async function checkIntelQuota(env, authCtx, endpoint) {
  const tier   = authCtx?.tier || 'FREE';
  const userId = authCtx?.userId || authCtx?.id || null;
  const limits = tierLimits(tier);

  // ── Step 0: Per-minute burst window (advertised alongside the daily quota) ──
  const burst = await checkIntelBurst(env, authCtx, limits);
  if (!burst.allowed) {
    return { allowed: false, reason: burst.reason, retry_after: burst.retry_after, tier, upgrade: 'https://intel.cyberdudebivash.com/pricing.html' };
  }

  // ── Step 1: Check customer_entitlements table (v39 grants) ─────────────────
  const requiredFeature = ENDPOINT_FEATURE[endpoint] || FEATURES.API_ACCESS;
  if (userId && env.DB) {
    try {
      const entResult = await checkEntitlement(env.DB, userId, requiredFeature, tier);
      if (entResult.granted && entResult.source === 'entitlement') {
        // Has explicit entitlement grant — use entitlement-derived daily limit
        if (limits.daily === Infinity) return { allowed: true, tier, remaining: 'unlimited', source: 'entitlement', stix: limits.stix };

        const key = `intel_quota:${userId}:${new Date().toISOString().slice(0,10)}`;
        const kv  = env.KV || env.SECURITY_HUB_KV;
        try {
          const current = parseInt(await kv?.get(key) || '0', 10);
          if (current >= limits.daily) return { allowed: false, reason: `Daily limit of ${limits.daily} requests reached`, upgrade: 'https://intel.cyberdudebivash.com/pricing.html', reset: 'tomorrow 00:00 UTC' };
          await kv?.put(key, String(current + 1), { expirationTtl: 86400 });
          return { allowed: true, tier, used: current + 1, limit: limits.daily, remaining: limits.daily - current - 1, source: 'entitlement', stix: limits.stix };
        } catch { return { allowed: true, tier, remaining: 'unknown', source: 'entitlement', stix: limits.stix }; }
      }
    } catch {}
  }

  // ── Step 2: Legacy tier-based check (backward compatibility) ───────────────
  if (!limits.endpoints.includes(endpoint)) {
    return { allowed: false, reason: `${endpoint.toUpperCase()} endpoint requires PRO or ENTERPRISE plan`, upgrade: 'https://intel.cyberdudebivash.com/pricing.html' };
  }

  if (limits.daily === Infinity) return { allowed: true, tier, remaining: 'unlimited', source: 'tier', stix: limits.stix };

  const key = `intel_quota:${userId || 'anon'}:${new Date().toISOString().slice(0,10)}`;
  const kv  = env.KV || env.SECURITY_HUB_KV;

  try {
    const current = parseInt(await kv?.get(key) || '0', 10);
    if (current >= limits.daily) {
      return { allowed: false, reason: `Daily limit of ${limits.daily} requests reached on ${tier} plan`, upgrade: 'https://intel.cyberdudebivash.com/pricing.html', reset: 'tomorrow 00:00 UTC' };
    }
    await kv?.put(key, String(current + 1), { expirationTtl: 86400 });
    return { allowed: true, tier, used: current + 1, limit: limits.daily, remaining: limits.daily - current - 1, source: 'tier', stix: limits.stix };
  } catch {
    return { allowed: true, tier, remaining: 'unknown', source: 'tier', stix: limits.stix };
  }
}

function extractParam(request, ...keys) {
  const url = new URL(request.url);
  for (const k of keys) {
    const v = url.searchParams.get(k);
    if (v) return v.trim();
  }
  return null;
}

async function extractBody(request) {
  if (request.method === 'POST') {
    try { return await request.clone().json(); } catch {}
  }
  return {};
}

// ─── IOC Classification ───────────────────────────────────────────────────────
function classifyIOC(value) {
  if (!value) return 'unknown';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value))                        return 'ipv4';
  if (/^[0-9a-f:]{7,39}$/i.test(value) && value.includes(':'))       return 'ipv6';
  if (/^[a-f0-9]{32}$/i.test(value))                                 return 'md5';
  if (/^[a-f0-9]{40}$/i.test(value))                                 return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(value))                                 return 'sha256';
  if (/^[a-f0-9]{128}$/i.test(value))                                return 'sha512';
  if (/^https?:\/\//i.test(value))                                   return 'url';
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'email';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(value)) return 'domain';
  return 'unknown';
}

// ─── IOC Scoring heuristic ────────────────────────────────────────────────────
function scoreIOC(value, iocType) {
  let score = 0;
  const low = value.toLowerCase();

  // High-risk TLDs
  if (['.ru','.cn','.tk','.pw','.top','.xyz','.work','.click','.gq','.ml'].some(t => low.includes(t))) score += 25;
  // Suspicious keywords
  if (['update','secure','login','verify','account','password','banking','paypal','microsoft','apple','google'].some(k => low.includes(k))) score += 20;
  // IP in range of known bad blocks (simplified)
  if (iocType === 'ipv4') {
    const parts = value.split('.').map(Number);
    // RFC1918 private — lower risk
    if (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168)) score -= 20;
    // Known DNS servers — safe
    if (value === '8.8.8.8' || value === '1.1.1.1' || value === '9.9.9.9') score = -10;
  }
  // Hash type — moderate risk by default
  if (['md5','sha1','sha256','sha512'].includes(iocType)) score += 30;
  // URL with suspicious patterns
  if (iocType === 'url' && (low.includes('bit.ly') || low.includes('t.co') || /\/[a-z]{2,4}\.exe/.test(low))) score += 35;

  return Math.min(100, Math.max(0, score + 10));
}

function riskVerdict(score) {
  if (score >= 70) return 'MALICIOUS';
  if (score >= 40) return 'SUSPICIOUS';
  if (score >= 15) return 'UNKNOWN';
  return 'SAFE';
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 1: /api/intel/ioc — IOC Enrichment
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleIntelIOC(request, env, authCtx) {
  const quota = await checkIntelQuota(env, authCtx, 'ioc');
  if (!quota.allowed) return json({ success: false, error: quota.reason, upgrade: quota.upgrade, reset: quota.reset, retry_after: quota.retry_after }, 429);

  const body  = await extractBody(request);
  const value = extractParam(request, 'value', 'ioc', 'indicator') || body?.value || body?.ioc || body?.indicator;
  if (!value) return json({ success: false, error: 'Missing indicator. Use ?value= or POST {value}' }, 400);
  if (value.length > 512) return json({ success: false, error: 'Indicator too long (max 512 chars)' }, 400);

  const iocType = classifyIOC(value);
  const riskScore = scoreIOC(value, iocType);
  const verdict   = riskVerdict(riskScore);

  // D1 lookup for known IOCs
  let dbRecord = null;
  try {
    dbRecord = await env.DB?.prepare(
      'SELECT * FROM ioc_requests WHERE ioc_value = ? ORDER BY created_at DESC LIMIT 1'
    ).bind(value).first();
  } catch {}

  // AI context enrichment (PRO+)
  let aiContext = null;
  if (authCtx?.tier !== 'FREE' && (authCtx?.isAdmin || ['PRO','ENTERPRISE'].includes(authCtx?.tier))) {
    try {
      const result = await callClaude(env, {
        prompt: `Analyze this IOC: "${value}" (type: ${iocType}). Provide: threat context, associated campaigns, recommended action. Be concise (3-4 sentences).`,
        tier: 'PRO',
        max_tokens: 200,
        temperature: 0.1,
      });
      aiContext = result?.content?.trim() || null;
    } catch {}
  }

  // Log to D1
  try {
    const kv = env.KV || env.SECURITY_HUB_KV;
    const cacheKey = `intel:ioc:${value.toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 64)}`;
    await kv?.put(cacheKey, JSON.stringify({ verdict, riskScore, iocType, ts: Date.now() }), { expirationTtl: 3600 });
  } catch {}

  return json({
    success:     true,
    api:         'CYBERDUDEBIVASH Threat Intel API',
    endpoint:    'ioc',
    query: {
      value,
      type: iocType,
    },
    analysis: {
      verdict,
      risk_score:    riskScore,
      confidence:    riskScore > 60 ? 'HIGH' : riskScore > 30 ? 'MEDIUM' : 'LOW',
      first_seen:    dbRecord?.created_at || null,
      times_queried: dbRecord ? 1 : 0,
    },
    context: {
      ai_assessment: aiContext,
      recommended_action: verdict === 'MALICIOUS' ? 'Block immediately' :
                          verdict === 'SUSPICIOUS' ? 'Investigate and monitor' :
                          verdict === 'SAFE'       ? 'No action required' : 'Manual review recommended',
      mitre_relevance: iocType === 'domain' ? 'T1566.002 (Spearphishing Link)' :
                       iocType === 'ipv4'   ? 'T1071.001 (Web Protocols C2)' :
                       ['md5','sha1','sha256'].includes(iocType) ? 'T1204.002 (Malicious File)' : null,
    },
    stix_available: quota.stix === true,
    stix_endpoint:  quota.stix === true ? '/api/v1/intel/stix.json' : null,
    quota: { used: quota.used, limit: quota.limit, remaining: quota.remaining, tier: quota.tier },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 2: /api/intel/cve — CVE Intelligence
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleIntelCVE(request, env, authCtx) {
  const quota = await checkIntelQuota(env, authCtx, 'cve');
  if (!quota.allowed) return json({ success: false, error: quota.reason, upgrade: quota.upgrade, retry_after: quota.retry_after }, 429);

  const body   = await extractBody(request);
  const cveId  = (extractParam(request, 'cve_id', 'cve', 'id') || body?.cve_id || body?.cve || '').toUpperCase().trim();
  const search = extractParam(request, 'q', 'search', 'keyword') || body?.q || body?.search || null;

  if (!cveId && !search) return json({ success: false, error: 'Missing cve_id or search query. Use ?cve_id=CVE-YYYY-NNNN or ?q=keyword' }, 400);

  // D1 lookup
  let record = null;
  try {
    if (cveId) {
      record = await env.DB?.prepare(
        'SELECT * FROM threat_intel WHERE cve_id = ? OR title LIKE ? LIMIT 1'
      ).bind(cveId, `%${cveId}%`).first();
    } else if (search) {
      record = await env.DB?.prepare(
        `SELECT * FROM threat_intel WHERE title LIKE ? OR description LIKE ?
         ORDER BY cvss_score DESC LIMIT 5`
      ).bind(`%${search}%`, `%${search}%`).first();
    }
  } catch {}

  // ── Static CVE_DB fallback when D1 has no record ────────────────────────────
  // CRITICAL FIX: prevents hallucination on unknown CVEs
  let staticCVE = null;
  if (!record && cveId) {
    staticCVE = lookupCVE(cveId); // returns null if not in static DB
  }

  // Resolved record: D1 takes priority, static DB is fallback, null = not found
  const resolved = record
    ? {
        cve_id:       record.cve_id || cveId,
        title:        record.title,
        description:  record.description,
        cvss_score:   record.cvss_score,
        kev_listed:   record.actively_exploited === 1 || record.kev === 1 || false,
        source:       record.source || 'NVD',
        found_in_db:  true,
      }
    : staticCVE
    ? {
        cve_id:       staticCVE.id,
        title:        `${staticCVE.id} — ${staticCVE.description.slice(0, 60)}`,
        description:  staticCVE.description,
        cvss_score:   staticCVE.cvss,
        kev_listed:   staticCVE.exploited || false,
        source:       'CYBERDUDEBIVASH Static Intel DB (NVD/CISA KEV)',
        found_in_db:  true,
        cwe:          staticCVE.cwe,
        epss:         staticCVE.epss,
        nvd_url:      staticCVE.nvd_url,
      }
    : null;

  const cvssScore = resolved?.cvss_score || null;
  const severity  = cvssScore ? (cvssScore >= 9 ? 'CRITICAL' : cvssScore >= 7 ? 'HIGH' : cvssScore >= 4 ? 'MEDIUM' : 'LOW') : null;

  // ── AI enrichment — ONLY when CVE is actually found ─────────────────────────
  // SECURITY: Never run AI enrichment on unknown CVEs — prevents hallucination
  let aiEnrichment = null;
  if (resolved && (authCtx?.tier !== 'FREE' || authCtx?.isAdmin)) {
    try {
      const prompt = cveId
        ? `Provide a concise threat intelligence brief for ${resolved.cve_id}:
Description: ${resolved.description}
CVSS: ${resolved.cvss_score} (${severity})
KEV Listed: ${resolved.kev_listed}

Cover: active exploitation evidence, affected products/versions, patch availability, attacker motivation, and top 2 defensive actions. 4-5 sentences. Be precise — do not add information not grounded in the description above.`
        : `Search threat intelligence for: "${search}". Summarize relevant CVEs, risk level, and recommended actions. Be concise.`;
      const result = await callClaude(env, { prompt, tier: 'PRO', max_tokens: 250, temperature: 0.1 });
      aiEnrichment = result?.content?.trim() || null;
    } catch {}
  }

  return json({
    success:  true,
    api:      'CYBERDUDEBIVASH Threat Intel API',
    endpoint: 'cve',
    query:    { cve_id: cveId || null, search: search || null },
    result:   resolved || {
      cve_id:      cveId || null,
      found_in_db: false,
      note:        `CVE not in local database. Reference: https://nvd.nist.gov/vuln/detail/${cveId || ''}`,
      cvss_score:  null,
      severity:    null,
      kev_listed:  false,
    },
    ai_enrichment:    aiEnrichment,
    mitre_mapping:    cveId ? 'T1190 (Exploit Public-Facing Application)' : null,
    recommended_actions: severity === 'CRITICAL' ? ['Patch immediately','Enable WAF rules','Enable IDS alerts'] :
                         severity === 'HIGH'     ? ['Patch within 7 days','Monitor for exploitation'] :
                                                   ['Patch in next maintenance window','Monitor advisories'],
    quota:     { used: quota.used, limit: quota.limit, remaining: quota.remaining, tier: quota.tier },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 3: /api/intel/actor — Threat Actor Intelligence
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleIntelActor(request, env, authCtx) {
  const quota = await checkIntelQuota(env, authCtx, 'actor');
  if (!quota.allowed) return json({ success: false, error: quota.reason, upgrade: quota.upgrade, retry_after: quota.retry_after }, 429);

  const body    = await extractBody(request);
  const actorId = extractParam(request, 'actor_id', 'actor', 'name') || body?.actor_id || body?.actor || body?.name || null;
  const sector  = extractParam(request, 'sector', 'industry') || body?.sector || null;

  // D1 lookup — threat_actors table
  let actor = null;
  let actors = [];
  try {
    if (actorId) {
      actor = await env.DB?.prepare(
        `SELECT * FROM threat_actors WHERE
         LOWER(name) = LOWER(?) OR LOWER(aliases) LIKE LOWER(?)
         LIMIT 1`
      ).bind(actorId, `%${actorId}%`).first();
    }
    if (sector && !actor) {
      const rows = await env.DB?.prepare(
        'SELECT name, aliases, nation_state, motivation, target_sectors FROM threat_actors WHERE target_sectors LIKE ? LIMIT 10'
      ).bind(`%${sector}%`).all();
      actors = rows?.results || [];
    }
    if (!actorId && !sector) {
      const rows = await env.DB?.prepare(
        'SELECT name, nation_state, motivation, target_sectors, last_seen FROM threat_actors ORDER BY last_seen DESC LIMIT 20'
      ).all();
      actors = rows?.results || [];
    }
  } catch {}

  // AI enrichment
  let aiProfile = null;
  if (authCtx?.isAdmin || ['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    try {
      const subject = actorId || (sector ? `threat actors targeting ${sector} sector` : 'current top APT groups');
      const result = await callClaude(env, {
        prompt: `Provide threat intelligence on ${subject}: nation-state attribution, primary TTPs, recent campaigns, targeted industries, and defensive recommendations. Be concise (5-6 sentences).`,
        tier: 'PRO',
        max_tokens: 300,
        temperature: 0.1,
      });
      aiProfile = result?.content?.trim() || null;
    } catch {}
  }

  return json({
    success:  true,
    api:      'CYBERDUDEBIVASH Threat Intel API',
    endpoint: 'actor',
    query:    { actor_id: actorId, sector },
    result: actor ? {
      name:            actor.name,
      aliases:         actor.aliases ? JSON.parse(actor.aliases) : [],
      nation_state:    actor.nation_state,
      motivation:      actor.motivation,
      target_sectors:  actor.target_sectors ? JSON.parse(actor.target_sectors) : [],
      primary_ttps:    actor.primary_ttps   ? JSON.parse(actor.primary_ttps)   : [],
      known_tools:     actor.known_tools     ? JSON.parse(actor.known_tools)     : [],
      last_seen:       actor.last_seen,
      active:          actor.active === 1,
      risk_rating:     actor.nation_state ? 'CRITICAL' : 'HIGH',
    } : null,
    actors_list:   actors.length > 0 ? actors : null,
    total_found:   actor ? 1 : actors.length,
    ai_profile:    aiProfile,
    data_sources:  ['D1 Threat Actor DB', 'MITRE ATT&CK', 'SENTINEL APEX AI'],
    quota:     { used: quota.used, limit: quota.limit, remaining: quota.remaining, tier: quota.tier },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 4: /api/intel/ttp — MITRE ATT&CK TTP Intelligence
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleIntelTTP(request, env, authCtx) {
  const quota = await checkIntelQuota(env, authCtx, 'ttp');
  if (!quota.allowed) return json({ success: false, error: quota.reason, upgrade: quota.upgrade, retry_after: quota.retry_after }, 429);

  const body    = await extractBody(request);
  const ttpId   = (extractParam(request, 'ttp_id', 'technique_id', 'id') || body?.ttp_id || body?.technique_id || '').toUpperCase();
  const keyword = extractParam(request, 'q', 'search') || body?.q || null;
  const tactic  = (extractParam(request, 'tactic') || body?.tactic || '').toLowerCase();

  if (!ttpId && !keyword && !tactic) {
    return json({ success: false, error: 'Missing parameter. Use ?ttp_id=T1566, ?q=keyword, or ?tactic=initial-access' }, 400);
  }

  // Embedded MITRE ATT&CK catalog (top 30 TTPs by frequency)
  const MITRE_CATALOG = {
    'T1566':   { name: 'Phishing', tactic: 'initial-access', sub: ['T1566.001 Spearphishing Attachment','T1566.002 Spearphishing Link','T1566.003 Spearphishing via Service'], mitigations: ['M1049 Antivirus/Antimalware','M1031 Network Intrusion Prevention','M1021 Restrict Web-Based Content'] },
    'T1190':   { name: 'Exploit Public-Facing Application', tactic: 'initial-access', mitigations: ['M1048 Application Isolation','M1030 Network Segmentation','M1016 Vulnerability Scanning'] },
    'T1059':   { name: 'Command and Scripting Interpreter', tactic: 'execution', sub: ['T1059.001 PowerShell','T1059.003 Windows Command Shell','T1059.004 Unix Shell'], mitigations: ['M1040 Behavior Prevention on Endpoint','M1049 Antivirus/Antimalware'] },
    'T1078':   { name: 'Valid Accounts', tactic: 'defense-evasion', mitigations: ['M1036 Account Use Policies','M1032 Multi-factor Authentication','M1026 Privileged Account Management'] },
    'T1110':   { name: 'Brute Force', tactic: 'credential-access', sub: ['T1110.001 Password Guessing','T1110.003 Password Spraying','T1110.004 Credential Stuffing'], mitigations: ['M1036 Account Use Policies','M1032 Multi-factor Authentication'] },
    'T1071':   { name: 'Application Layer Protocol (C2)', tactic: 'command-and-control', sub: ['T1071.001 Web Protocols','T1071.004 DNS'], mitigations: ['M1037 Filter Network Traffic','M1031 Network Intrusion Prevention'] },
    'T1486':   { name: 'Data Encrypted for Impact (Ransomware)', tactic: 'impact', mitigations: ['M1053 Data Backup','M1049 Antivirus/Antimalware','M1040 Behavior Prevention'] },
    'T1505':   { name: 'Server Software Component (Webshell)', tactic: 'persistence', sub: ['T1505.003 Web Shell'], mitigations: ['M1042 Disable or Remove Feature','M1018 User Account Management'] },
    'T1053':   { name: 'Scheduled Task/Job', tactic: 'execution', mitigations: ['M1028 Operating System Configuration','M1026 Privileged Account Management'] },
    'T1027':   { name: 'Obfuscated Files or Information', tactic: 'defense-evasion', mitigations: ['M1049 Antivirus/Antimalware','M1040 Behavior Prevention'] },
    'T1055':   { name: 'Process Injection', tactic: 'privilege-escalation', mitigations: ['M1040 Behavior Prevention','M1026 Privileged Account Management'] },
    'T1021':   { name: 'Remote Services', tactic: 'lateral-movement', sub: ['T1021.001 Remote Desktop Protocol','T1021.004 SSH'], mitigations: ['M1047 Audit','M1026 Privileged Account Management','M1032 MFA'] },
    'T1082':   { name: 'System Information Discovery', tactic: 'discovery', mitigations: ['M1028 OS Configuration'] },
    'T1018':   { name: 'Remote System Discovery', tactic: 'discovery', mitigations: ['M1030 Network Segmentation','M1037 Filter Network Traffic'] },
    'T1041':   { name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', mitigations: ['M1057 Data Loss Prevention','M1031 Network Intrusion Prevention'] },
    'T1562':   { name: 'Impair Defenses', tactic: 'defense-evasion', sub: ['T1562.001 Disable or Modify Tools'], mitigations: ['M1022 Restrict File and Directory Permissions','M1024 Restrict Registry Permissions'] },
    'T1203':   { name: 'Exploitation for Client Execution', tactic: 'execution', mitigations: ['M1050 Exploit Protection','M1048 Application Isolation'] },
    'T1112':   { name: 'Modify Registry', tactic: 'defense-evasion', mitigations: ['M1024 Restrict Registry Permissions'] },
    'T1140':   { name: 'Deobfuscate/Decode Files or Information', tactic: 'defense-evasion', mitigations: ['M1049 Antivirus/Antimalware'] },
    'T1105':   { name: 'Ingress Tool Transfer', tactic: 'command-and-control', mitigations: ['M1031 Network Intrusion Prevention','M1037 Filter Network Traffic'] },
    'T1204':   { name: 'User Execution', tactic: 'execution', sub: ['T1204.001 Malicious Link','T1204.002 Malicious File'], mitigations: ['M1038 Execution Prevention','M1017 User Training'] },
    'T1574':   { name: 'Hijack Execution Flow', tactic: 'privilege-escalation', mitigations: ['M1044 Restrict Library Loading','M1038 Execution Prevention'] },
    'T1003':   { name: 'OS Credential Dumping', tactic: 'credential-access', sub: ['T1003.001 LSASS Memory'], mitigations: ['M1028 OS Configuration','M1026 Privileged Account Management','M1017 User Training'] },
    'T1098':   { name: 'Account Manipulation', tactic: 'persistence', mitigations: ['M1032 MFA','M1026 Privileged Account Management'] },
    'T1047':   { name: 'Windows Management Instrumentation', tactic: 'execution', mitigations: ['M1026 Privileged Account Management','M1040 Behavior Prevention'] },
    'T1136':   { name: 'Create Account', tactic: 'persistence', mitigations: ['M1032 MFA','M1030 Network Segmentation','M1028 OS Configuration'] },
    'T1570':   { name: 'Lateral Tool Transfer', tactic: 'lateral-movement', mitigations: ['M1031 Network Intrusion Prevention','M1022 Restrict File/Dir Permissions'] },
    'T1219':   { name: 'Remote Access Software', tactic: 'command-and-control', mitigations: ['M1031 Network Intrusion Prevention','M1037 Filter Network Traffic'] },
    'T1048':   { name: 'Exfiltration Over Alternative Protocol', tactic: 'exfiltration', mitigations: ['M1057 Data Loss Prevention','M1037 Filter Network Traffic'] },
    'T1560':   { name: 'Archive Collected Data', tactic: 'collection', mitigations: ['M1057 Data Loss Prevention'] },
  };

  // Lookup
  let found = null;
  if (ttpId) {
    const baseId = ttpId.split('.')[0];
    found = MITRE_CATALOG[ttpId] || MITRE_CATALOG[baseId];
    if (found) found = { ...found, technique_id: ttpId };
  }

  const tacticFiltered = tactic
    ? Object.entries(MITRE_CATALOG)
        .filter(([,t]) => t.tactic === tactic || t.tactic.includes(tactic.replace('-',' ')))
        .map(([id, t]) => ({ technique_id: id, ...t }))
    : [];

  const keywordResults = keyword
    ? Object.entries(MITRE_CATALOG)
        .filter(([,t]) => t.name.toLowerCase().includes(keyword.toLowerCase()))
        .map(([id, t]) => ({ technique_id: id, ...t }))
    : [];

  // AI context
  let aiContext = null;
  if (authCtx?.isAdmin || ['PRO','ENTERPRISE'].includes(authCtx?.tier)) {
    try {
      const subject = found?.name || keyword || tactic;
      const result = await callClaude(env, {
        prompt: `Threat intelligence briefing for MITRE ATT&CK technique: ${subject}. Include: real-world usage by APT groups, detection strategies, priority mitigations, and affected industries. Be concise (4-5 sentences).`,
        tier: 'PRO',
        max_tokens: 250,
        temperature: 0.1,
      });
      aiContext = result?.content?.trim() || null;
    } catch {}
  }

  return json({
    success:  true,
    api:      'CYBERDUDEBIVASH Threat Intel API',
    endpoint: 'ttp',
    query:    { ttp_id: ttpId || null, tactic: tactic || null, search: keyword || null },
    result:   found || null,
    tactic_results: tacticFiltered.length > 0 ? tacticFiltered : null,
    search_results: keywordResults.length > 0 ? keywordResults : null,
    total_found:    found ? 1 : (tacticFiltered.length || keywordResults.length),
    ai_context:     aiContext,
    framework:      'MITRE ATT&CK Enterprise v15',
    available_tactics: ['initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'],
    quota:     { used: quota.used, limit: quota.limit, remaining: quota.remaining, tier: quota.tier },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT 5: /api/intel/risk — Composite Risk Score
// ═══════════════════════════════════════════════════════════════════════════════
export async function handleIntelRisk(request, env, authCtx) {
  const quota = await checkIntelQuota(env, authCtx, 'risk');
  if (!quota.allowed) return json({ success: false, error: quota.reason, upgrade: quota.upgrade, retry_after: quota.retry_after }, 429);

  const body    = await extractBody(request);
  const target  = extractParam(request, 'target', 'domain', 'org') || body?.target || body?.domain || body?.org;
  const sector  = extractParam(request, 'sector', 'industry') || body?.sector || body?.industry || 'General';
  const context = extractParam(request, 'context') || body?.context || null;

  if (!target) return json({ success: false, error: 'Missing target. Use ?target=domain.com or POST {target}' }, 400);

  // Pull data from multiple D1 sources
  let sslData      = null;
  let iocHistory   = null;
  let cveCount     = 0;
  let actorTargets = 0;

  try {
    // Recent SSL risk
    const kv = env.KV || env.SECURITY_HUB_KV;
    const sslCached = await kv?.get(`ssl_result:${target}`);
    if (sslCached) sslData = JSON.parse(sslCached);

    // IOC history
    iocHistory = await env.DB?.prepare(
      'SELECT COUNT(*) as cnt, MAX(verdict) as worst FROM ioc_requests WHERE ioc_value LIKE ? OR ioc_value LIKE ?'
    ).bind(`%${target}%`, `%.${target}`).first();

    // CVE count for context
    const cveRow = await env.DB?.prepare('SELECT COUNT(*) as cnt FROM threat_intel WHERE cvss_score >= 7').first();
    cveCount = cveRow?.cnt || 0;

    // Actors targeting this sector
    const actorRow = await env.DB?.prepare(
      'SELECT COUNT(*) as cnt FROM threat_actors WHERE target_sectors LIKE ? AND active = 1'
    ).bind(`%${sector}%`).first();
    actorTargets = actorRow?.cnt || 0;
  } catch {}

  // Composite risk calculation
  const components = {
    domain_risk:       classifyIOC(target) === 'domain' ? scoreIOC(target, 'domain') : 20,
    ioc_history:       iocHistory?.cnt > 0 ? Math.min(100, iocHistory.cnt * 15) : 0,
    ssl_risk:          sslData?.risk_score || 35,
    sector_exposure:   actorTargets > 3 ? 70 : actorTargets > 0 ? 45 : 20,
    cve_landscape:     cveCount > 100 ? 60 : cveCount > 50 ? 45 : 30,
  };

  const weights = { domain_risk: 0.25, ioc_history: 0.20, ssl_risk: 0.20, sector_exposure: 0.20, cve_landscape: 0.15 };
  const compositeScore = Math.round(
    Object.entries(components).reduce((sum, [k, v]) => sum + v * (weights[k] || 0), 0)
  );
  const riskLevel = compositeScore >= 70 ? 'CRITICAL' : compositeScore >= 55 ? 'HIGH' : compositeScore >= 35 ? 'MEDIUM' : 'LOW';

  // AI risk narrative
  let narrative = null;
  try {
    const result = await callClaude(env, {
      prompt: `Generate an executive-level risk assessment for: "${target}" in the ${sector} sector.
Risk scores — Domain: ${components.domain_risk}, SSL: ${components.ssl_risk}, Sector Exposure: ${components.sector_exposure}.
Overall: ${compositeScore}/100 (${riskLevel}).
Provide: key risk drivers, top 3 immediate actions, business impact if breached. Be concise (4-5 sentences).`,
      tier: authCtx?.tier || 'PRO',
      max_tokens: 300,
      temperature: 0.2,
    });
    narrative = result?.content?.trim() || null;
  } catch {}

  return json({
    success:   true,
    api:       'CYBERDUDEBIVASH Threat Intel API',
    endpoint:  'risk',
    query:     { target, sector, context },
    risk_assessment: {
      composite_score:  compositeScore,
      risk_level:       riskLevel,
      confidence:       'HIGH',
      components,
      trend:            'STABLE',
    },
    threat_context: {
      active_actors_targeting_sector: actorTargets,
      high_cvss_cves_in_db:           cveCount,
      ioc_hits_for_target:            iocHistory?.cnt || 0,
      worst_ioc_verdict:              iocHistory?.worst || 'UNKNOWN',
    },
    executive_narrative: narrative,
    recommendations: {
      immediate:   riskLevel === 'CRITICAL' ? ['Initiate incident response', 'Enable emergency WAF rules', 'Alert security team'] :
                   riskLevel === 'HIGH'     ? ['Schedule security review within 48h', 'Enable enhanced monitoring'] :
                                             ['Continue standard monitoring', 'Review posture quarterly'],
      strategic:   ['Deploy CYBERDUDEBIVASH continuous monitoring', 'Enroll in Sentinel APEX threat feeds', 'Schedule executive risk briefing'],
    },
    report_url:   `https://tools.cyberdudebivash.com/risk-report?target=${encodeURIComponent(target)}`,
    quota:     { used: quota.used, limit: quota.limit, remaining: quota.remaining, tier: quota.tier },
    powered_by: 'CYBERDUDEBIVASH SENTINEL APEX',
    timestamp:  new Date().toISOString(),
  });
}
