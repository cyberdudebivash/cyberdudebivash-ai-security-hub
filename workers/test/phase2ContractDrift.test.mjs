// Phase 2 — Enterprise API Contract & Data Integrity Program.
//
// Every case here locks in the REAL field name/shape a Phase-0/Phase-1
// frontend fix depends on. These are not business-logic tests (those already
// exist elsewhere) — they exist purely to fail loudly the moment a handler's
// response shape drifts again, since that drift is exactly what caused every
// defect this engagement found: a real endpoint, called correctly, returning
// real data under a field name the frontend was never updated to read.
//
// A generic empty-but-well-formed D1 mock is used throughout — these tests
// assert field NAMES and NESTING survive, not that the mocked business
// values are realistic (that's covered by each handler's own test file).
import { describe, it, expect } from 'vitest';
import { handleGetAlerts, handleGetDecisions } from '../src/handlers/soc.js';
import { handlePlatformKPI } from '../src/handlers/enterpriseTransformHandler.js';
import {
  handleListMsspPartners, handleMsspWlStatus, handleMsspUsage,
  handleMsspRevenueTrend, handleMsspExpansionOpps,
} from '../src/handlers/msspOps.js';
import { handleGetThreatIntel, handleThreatIntelStats } from '../src/handlers/threatIntel.js';
import { enrichIOC } from '../src/services/iocEnrichmentEngine.js';
import { sanitizeForPublic } from '../src/services/radarService.js';
import { pricingMatrix } from '../src/handlers/intelMonetization.js';

// A D1 stub that answers any prepare/bind/first/all/run chain with an empty
// but well-formed result, so handlers exercise their real (non-fallback)
// code path and produce their real field set instead of a `!db` shortcut.
function makeEmptyDB() {
  const stmt = {
    bind() { return stmt; },
    async first() { return {}; },
    async all() { return { results: [] }; },
    async run() { return { success: true, meta: {} }; },
  };
  return { prepare() { return stmt; } };
}

function makeEnv() {
  const db = makeEmptyDB();
  return { DB: db, SECURITY_HUB_DB: db, KV: null, SECURITY_HUB_KV: null };
}

function req(url, opts) { return new Request(url, opts); }

describe('Contract: GET /api/v1/alerts (soc.js handleGetAlerts)', () => {
  it('wraps the payload in {success,data:{alerts,total,plan,generated_at}}', async () => {
    const res = await handleGetAlerts(req('https://x/api/v1/alerts?limit=5'), makeEnv(), { tier: 'PRO' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data.alerts)).toBe(true);
    expect(typeof body.data.total).toBe('number');
    expect(typeof body.data.generated_at).toBe('string');
    // Regression guard: a top-level `.alerts` (no `.data`) previously caused
    // frontend/soc-dashboard.html to always render an empty feed.
    expect(body.alerts).toBeUndefined();
  });
});

describe('Contract: GET /api/v1/decisions (soc.js handleGetDecisions)', () => {
  it('wraps the payload in {success,data:{decisions,total}}', async () => {
    const res = await handleGetDecisions(req('https://x/api/v1/decisions?limit=5'), makeEnv(), { tier: 'ENTERPRISE' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data.decisions)).toBe(true);
    expect(typeof body.data.total).toBe('number');
    expect(body.decisions).toBeUndefined();
  });
});

describe('Contract: GET /api/platform/kpi (enterpriseTransformHandler.js handlePlatformKPI)', () => {
  it('exposes the real field names the Executive KPI Dashboard reads', async () => {
    // isAdmin:true (ADMIN_KEY-bypass-equivalent) is the real way to reach this
    // route as an admin — tier:'OWNER' (used here previously) is not a value
    // any auth path ever produces; see enterpriseTransformAdminGuard.test.mjs.
    const res = await handlePlatformKPI(req('https://x/api/platform/kpi'), makeEnv(), { authenticated: true, user_id: 'u_owner', isAdmin: true });
    const body = await res.json();
    expect(body.success).toBe(true);
    const kpi = body.kpi;
    // Real field names — frontend/enterprise-kpi-dashboard.html remaps to
    // these exact keys in loadKPI(). If any of these disappear or get
    // renamed, half the KPI grid silently reverts to a fabricated 0/N-A.
    for (const key of [
      'mrr', 'arr', 'arpu', 'ltv_estimate', 'nrr_estimate', 'cac_estimate',
      'active_paid_subs', 'trial_count', 'new_users_mtd',
      'api_requests_mtd', 'api_active_users', 'churn_rate_est',
      'nrr', 'churn_rate', 'plan_distribution', 'total_customers',
    ]) {
      expect(kpi, `kpi.${key} must exist`).toHaveProperty(key);
    }
    // Regression guard: these field names were what the frontend used to
    // read incorrectly — must NOT be what the backend actually calls them.
    expect(kpi).not.toHaveProperty('total_api_calls_month');
    expect(kpi).not.toHaveProperty('active_api_keys');
    expect(kpi).not.toHaveProperty('new_customers_month');
  });
});

describe('Contract: GET /api/mssp/partners (msspOps.js handleListMsspPartners)', () => {
  it('returns {partners:[...],total} — not a bare array', async () => {
    const res = await handleListMsspPartners(req('https://x/api/mssp/partners'), makeEnv());
    const body = await res.json();
    expect(Array.isArray(body.partners)).toBe(true);
    expect(typeof body.total).toBe('number');
  });
});

describe('Contract: GET /api/mssp/wl-status (msspOps.js handleMsspWlStatus)', () => {
  it('returns real aggregate fields, not per-category status strings', async () => {
    const res = await handleMsspWlStatus(req('https://x/api/mssp/wl-status'), makeEnv());
    const body = await res.json();
    expect(typeof body.total).toBe('number');
    expect(typeof body.configured).toBe('number');
    expect(typeof body.pending).toBe('number');
    expect(Array.isArray(body.partners)).toBe(true);
    // Regression guard: these fields never existed — a frontend reading them
    // always silently fell back to a hardcoded "Available" status.
    expect(body).not.toHaveProperty('api_status');
    expect(body).not.toHaveProperty('portal_status');
    expect(body).not.toHaveProperty('domain_status');
  });
});

describe('Contract: GET /api/mssp/usage (msspOps.js handleMsspUsage)', () => {
  it('returns one platform-wide aggregate object, never a per-partner array', async () => {
    const res = await handleMsspUsage(req('https://x/api/mssp/usage'), makeEnv());
    const body = await res.json();
    expect(Array.isArray(body)).toBe(false);
    for (const key of ['month', 'total_scans', 'total_api_calls', 'total_reports', 'active_clients', 'total_alerts']) {
      expect(body, `usage.${key} must exist`).toHaveProperty(key);
    }
  });
});

describe('Contract: GET /api/mssp/revenue-trend (msspOps.js handleMsspRevenueTrend)', () => {
  it('nests the series under .months with a real mrr_inr field per entry', async () => {
    const db = makeEmptyDB();
    db.prepare = () => ({
      bind() { return this; },
      async all() { return { results: [{ month: '2026-06', label: 'Jun', mrr_inr: 100000 }] }; },
      async first() { return {}; },
      async run() { return { success: true }; },
    });
    const res = await handleMsspRevenueTrend(req('https://x/api/mssp/revenue-trend'), { DB: db });
    const body = await res.json();
    expect(Array.isArray(body.months)).toBe(true);
    if (body.months.length) {
      expect(body.months[0]).toHaveProperty('mrr_inr');
      // Regression guard: a flat top-level array with a `.revenue` field
      // never existed — this is what the frontend used to expect.
      expect(body.months[0]).not.toHaveProperty('revenue');
    }
  });
});

describe('Contract: GET /api/mssp/expansion-opps (msspOps.js handleMsspExpansionOpps)', () => {
  it('returns {opportunities:[...],total} — no tier_upgrade/api_limit/inactive counters', async () => {
    const res = await handleMsspExpansionOpps(req('https://x/api/mssp/expansion-opps'), makeEnv());
    const body = await res.json();
    expect(Array.isArray(body.opportunities)).toBe(true);
    expect(typeof body.total).toBe('number');
    // Regression guard: these three counters were never computed by this
    // handler — a frontend expecting them always silently read 0.
    expect(body).not.toHaveProperty('tier_upgrade');
    expect(body).not.toHaveProperty('api_limit');
    expect(body).not.toHaveProperty('inactive');
  });
});

describe('Contract: GET /api/threat-intel (threatIntel.js handleGetThreatIntel)', () => {
  it('wraps the payload in {success,data:{entries,total}}', async () => {
    const res = await handleGetThreatIntel(req('https://x/api/threat-intel?limit=5'), makeEnv(), { tier: 'PRO' });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(Array.isArray(body.data.entries)).toBe(true);
    expect(typeof body.data.total).toBe('number');
    expect(body.entries).toBeUndefined();
    expect(body.threats).toBeUndefined();
  });
});

describe('Contract: GET /api/threat-intel/stats (threatIntel.js handleThreatIntelStats)', () => {
  it('nests real counters two levels under data.stats', async () => {
    const res = await handleThreatIntelStats(req('https://x/api/threat-intel/stats'), makeEnv());
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data).toHaveProperty('stats');
    for (const key of ['total_advisories', 'critical', 'confirmed_exploited']) {
      expect(body.data.stats, `data.stats.${key} must exist`).toHaveProperty(key);
    }
  });
});

describe('Contract: enrichIOC() (iocEnrichmentEngine.js)', () => {
  it('exposes verdict/risk_score, not confidence_score, and a consistent raw_data field', async () => {
    const result = await enrichIOC({}, '203.0.113.5', 'ip');
    expect(result).toHaveProperty('verdict');
    expect(result).toHaveProperty('risk_score');
    expect(result).toHaveProperty('sources_hit');
    // Regression guard: the fresh-lookup path used to call this field
    // `sources` while the D1-cache-hit path called it `raw_data` — any
    // consumer reading `.raw_data` (e.g. threat-intelligence.html's
    // VirusTotal/Shodan panel) only worked by accident on a cache hit.
    expect(result).toHaveProperty('raw_data');
    expect(result).not.toHaveProperty('confidence_score');
    expect(result).not.toHaveProperty('confidence');
  });
});

describe('Contract: sanitizeForPublic() (radarService.js) — intentional tier gate', () => {
  it('never exposes active_threat_actors/ransomware_activity to non-Enterprise callers', () => {
    const snapshot = {
      timestamp: new Date().toISOString(), radar_health: 'OPERATIONAL', total_signals: 1,
      source_count: 1, severity_distribution: {}, ai_threat_summary: '', latest_cves: [],
      trending_threats: [], top_campaigns: [], critical_count: 0, publisher: 'x',
      active_threat_actors: [{ name: 'APT99', count: 5 }],
      ransomware_activity: [{ name: 'LockBit', count: 3 }],
    };
    const pub = sanitizeForPublic(snapshot);
    expect(pub).not.toHaveProperty('active_threat_actors');
    expect(pub).not.toHaveProperty('ransomware_activity');
    // This is a documented product decision, not a bug — the frontend
    // (cyber-signal-radar.html) must show an honest upgrade prompt here,
    // never a fabricated "No active threat actors."
  });
});

describe('Contract: GET /api/v1/intel/pricing.json (intelMonetization.js pricingMatrix)', () => {
  it('exposes tiers[], not a top-level plans[] or a .data wrapper', () => {
    const result = pricingMatrix();
    expect(Array.isArray(result.tiers)).toBe(true);
    expect(result).not.toHaveProperty('plans');
    expect(result).not.toHaveProperty('data');
    if (result.tiers.length) {
      expect(result.tiers[0]).toHaveProperty('tier');
      expect(result.tiers[0]).toHaveProperty('price_inr');
    }
  });
});
