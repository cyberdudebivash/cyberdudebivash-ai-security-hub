/**
 * CYBERDUDEBIVASH® Sentinel APEX — Threat-Intel API Monetization
 *
 * Turns the public threat-intel feeds (now backed by ~1,600+ real CVEs) into a
 * tiered API product. FREE access stays generous-but-limited (recent items,
 * basic fields, attribution, daily cap); paid tiers unlock the full catalog,
 * EPSS exploit-probability scores, full detail, the complete CISA KEV feed, and
 * STIX 2.1 bundle export for SIEM/TIP ingestion.
 *
 * Tier resolution reuses the platform API-key system (x-api-key → KV apikey:*).
 * FREE responses remain edge-cacheable (identical for everyone); keyed responses
 * bypass the cache and are rate-limited per key.
 */

import { resolveAuth } from '../middleware/auth.js';

const UPGRADE_URL  = 'https://cyberdudebivash.in/#pricing';
const DOCS_URL     = 'https://cyberdudebivash.in/api-docs';
const CONTACT      = 'contact@cyberdudebivash.in';

// ─── Feed entitlements per tier ───────────────────────────────────────────────
// Keyed off the API-key tier (FREE | STARTER | PRO | ENTERPRISE | MSSP). Unknown
// tiers degrade to FREE; ENTERPRISE_SOC / MSSP map to ENTERPRISE-grade access.
export const FEED_TIERS = {
  FREE:       { max_results: 25,   full_detail: false, epss: false, stix: false, kev_full: false, daily_limit: 100,    rpm: 10,  price_inr: 0,      label: 'Free'       },
  STARTER:    { max_results: 100,  full_detail: true,  epss: true,  stix: false, kev_full: true,  daily_limit: 2000,   rpm: 30,  price_inr: 999,    label: 'Starter'    },
  PRO:        { max_results: 500,  full_detail: true,  epss: true,  stix: true,  kev_full: true,  daily_limit: 20000,  rpm: 60,  price_inr: 1499,   label: 'Pro'        },
  ENTERPRISE: { max_results: 2000, full_detail: true,  epss: true,  stix: true,  kev_full: true,  daily_limit: -1,     rpm: 120, price_inr: 4999,   label: 'Enterprise' },
  MSSP:       { max_results: 5000, full_detail: true,  epss: true,  stix: true,  kev_full: true,  daily_limit: -1,     rpm: 240, price_inr: 9999,   label: 'MSSP'       },
};

export function entitlementsFor(tier) {
  const t = String(tier || 'FREE').toUpperCase();
  if (FEED_TIERS[t]) return { tier: t, ...FEED_TIERS[t] };
  if (t === 'ENTERPRISE_SOC') return { tier: 'ENTERPRISE', ...FEED_TIERS.ENTERPRISE };
  return { tier: 'FREE', ...FEED_TIERS.FREE };
}

// ─── Resolve the caller's feed tier (API key → tier, else FREE via IP) ────────
export async function resolveFeedTier(request, env) {
  let auth = { tier: 'FREE', authenticated: true, ip: 'unknown', key: null };
  try { auth = await resolveAuth(request, env) || auth; } catch {}
  // A key was supplied but is invalid → explicit signal so the caller can 401.
  const invalidKey = auth.method === 'api_key' && auth.authenticated === false;
  const ent = entitlementsFor(auth.tier);
  return {
    ...ent,
    keyed: !!auth.key && !invalidKey,
    invalidKey,
    identity: auth.key ? `key:${String(auth.key).slice(0, 10)}` : `ip:${auth.ip}`,
  };
}

// ─── Rate limits (KV counters; only enforced for keyed/dynamic requests) ──────
// Enforces BOTH limits the pricing matrix advertises (`rate_per_min` + daily
// quota). The per-minute window applies to every tier — including the
// unlimited-daily ENTERPRISE/MSSP plans, whose advertised 120/240 rpm was
// previously not enforced anywhere. KV counters are best-effort (fail open on
// KV outage — availability over enforcement, consistent with risk R-14).
export async function enforceDailyLimit(env, ent, identity) {
  if (!env?.SECURITY_HUB_KV) {
    return { allowed: true, remaining: -1, limit: ent.daily_limit };
  }

  // Per-minute window first (advertised as rate_per_min in pricing.json).
  const rpm = ent.rpm > 0 ? ent.rpm : 0;
  if (rpm > 0) {
    const minute = new Date().toISOString().slice(0, 16); // 2026-07-04T09:41
    const mKey = `intel:rl:min:${identity}:${minute}`;
    let burst = 0;
    try { burst = parseInt((await env.SECURITY_HUB_KV.get(mKey)) || '0', 10) || 0; } catch {}
    if (burst >= rpm) {
      return { allowed: false, reason: 'rate_per_min', remaining: 0, limit: rpm, retry_after: 60 };
    }
    env.SECURITY_HUB_KV.put(mKey, String(burst + 1), { expirationTtl: 120 }).catch(() => {});
  }

  if (ent.daily_limit < 0) {
    return { allowed: true, remaining: -1, limit: ent.daily_limit };
  }
  const day = new Date().toISOString().slice(0, 10);
  const key = `intel:rl:${identity}:${day}`;
  let used = 0;
  try { used = parseInt((await env.SECURITY_HUB_KV.get(key)) || '0', 10) || 0; } catch {}
  if (used >= ent.daily_limit) {
    return { allowed: false, reason: 'daily_quota', remaining: 0, limit: ent.daily_limit };
  }
  // Best-effort increment (TTL to end of day-ish: 26h covers timezone slack).
  env.SECURITY_HUB_KV.put(key, String(used + 1), { expirationTtl: 93600 }).catch(() => {});
  return { allowed: true, remaining: ent.daily_limit - used - 1, limit: ent.daily_limit };
}

// ─── Gate items: cap count + strip premium fields for lower tiers ─────────────
export function gateItems(items, ent, requestedLimit) {
  const cap = Math.min(ent.max_results, requestedLimit || ent.max_results);
  const sliced = items.slice(0, cap);
  if (ent.full_detail && ent.epss) return sliced; // paid: full payload
  // FREE: basic fields only — no EPSS, vectors, affected products, or long desc.
  return sliced.map(it => ({
    id:           it.id,
    cve:          it.cve,
    title:        it.title,
    severity:     it.severity,
    cvss:         it.cvss ?? null,
    source:       it.source,
    published_at: it.published_at,
    summary:      it.summary ? String(it.summary).slice(0, 140) : null,
    _premium:     'EPSS score, full description, CWE/CPE & STIX export require a paid plan',
  }));
}

// ─── Upgrade / pricing metadata attached to FREE responses ────────────────────
export function upgradeMeta(ent) {
  if (ent.tier !== 'FREE') return undefined;
  return {
    message: 'You are on the FREE tier (recent items, basic fields). Unlock the full ~1,600+ CVE catalog, EPSS scores, full KEV feed and STIX 2.1 export.',
    upgrade_url: UPGRADE_URL,
    docs: DOCS_URL,
    plans: Object.entries(FEED_TIERS)
      .filter(([k]) => k !== 'FREE')
      .map(([k, v]) => ({ tier: k, price_inr: v.price_inr, max_results: v.max_results, epss: v.epss, stix: v.stix, daily_limit: v.daily_limit })),
  };
}

// ─── Public pricing matrix (GET /api/v1/intel/pricing.json) ───────────────────
export function pricingMatrix() {
  return {
    product:   'CYBERDUDEBIVASH® Sentinel APEX — Threat Intelligence API',
    publisher: 'CYBERDUDEBIVASH®',
    currency:  'INR',
    billing:   'per month',
    auth:      'x-api-key header — obtain a key at /api/keys or ' + UPGRADE_URL,
    tiers: Object.entries(FEED_TIERS).map(([k, v]) => ({
      tier:        k,
      label:       v.label,
      price_inr:   v.price_inr,
      max_results: v.max_results,
      epss_scores: v.epss,
      kev_full:    v.kev_full,
      stix_export: v.stix,
      daily_quota: v.daily_limit < 0 ? 'unlimited' : v.daily_limit,
      rate_per_min: v.rpm,
    })),
    contact:    CONTACT,
    upgrade_url: UPGRADE_URL,
  };
}

// ─── STIX 2.1 bundle builder (premium export) ─────────────────────────────────
// Emits one `vulnerability` SDO per CVE with CVSS + EPSS in external references.
export function toStixBundle(items, { tlp = 'clear' } = {}) {
  const uuid = () => (globalThis.crypto?.randomUUID ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      }));
  const now = new Date().toISOString();
  const marking = {
    type: 'marking-definition', spec_version: '2.1',
    id: `marking-definition--${uuid()}`, created: now,
    definition_type: 'tlp', name: `TLP:${tlp.toUpperCase()}`,
  };
  const objects = [marking];
  for (const it of items) {
    const refs = [{ source_name: 'cve', external_id: it.cve || it.id }];
    if (it.source_url) refs.push({ source_name: it.source || 'nvd', url: it.source_url });
    objects.push({
      type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid()}`,
      created: now, modified: now,
      name: it.cve || it.id,
      description: it.summary || it.title || '',
      external_references: refs,
      object_marking_refs: [marking.id],
      x_cdb_severity: it.severity || null,
      x_cdb_cvss: it.cvss ?? null,
      x_cdb_epss: it.epss_score ?? null,
      x_cdb_actively_exploited: it.actively_exploited ? true : undefined,
    });
  }
  return {
    type: 'bundle', id: `bundle--${uuid()}`,
    spec_version: '2.1',
    x_cdb_publisher: 'CYBERDUDEBIVASH® Sentinel APEX',
    x_cdb_generated: now,
    objects,
  };
}

export const PREMIUM_FEED_PATHS = [
  '/api/v1/intel/kev.json',
  '/api/v1/intel/stix.json',
  '/api/v1/intel/pricing.json',
];
