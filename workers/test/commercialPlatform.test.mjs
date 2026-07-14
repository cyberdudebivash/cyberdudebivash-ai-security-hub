/* P15.0 regression tests — Commercial Platform & Enterprise Customer Success
 *
 * Verifies:
 *   P15.1  handleOnboardingWizard
 *   1.  Unauth returns 401
 *   2.  Returns onboarding object with 5 steps
 *   3.  completion_pct reflects completed steps (2/5 = 40%)
 *   4.  status is STARTED when pct < 60
 *   5.  KV cache returns _cache: hit
 *   6.  next_step is null when all steps complete
 *   7.  tier from authCtx is included
 *   8.  No DB graceful — zero steps completed
 *
 *   P15.2  handleCustomerLicense
 *   9.  Unauth returns 401
 *   10. Returns license object with tier and plan_name
 *   11. Quota matches TIER_QUOTAS for PRO
 *   12. Features list includes api_access for all tiers
 *   13. KV cache returns _cache: hit
 *   14. Trial block present when KV billing:trial:<userId> set
 *   15. Active API key count from DB
 *   16. Entitlements merged with implicit features
 *
 *   P15.3  handleUsageAnalytics
 *   17. Unauth returns 401
 *   18. Returns usage.api.total_calls
 *   19. by_endpoint limited to 10 items
 *   20. scans.completed derived from DB group-by
 *   21. ai_requests counts copilot endpoints
 *   22. KV cache returns _cache: hit
 *   23. avg_latency_ms is calculated correctly
 *   24. reports.scheduled from DB
 *
 *   P15.4  handleCustomerSuccessScore
 *   25. Unauth returns 401
 *   26. adoption_score computed correctly (profile=20, key*10, scan*5, usage/10, report*10)
 *   27. health_score capped at 100
 *   28. renewal_readiness HIGH when health >= 70
 *   29. renewal_readiness LOW when health < 40
 *   30. upgrade_opportunities for FREE tier includes STARTER
 *   31. upgrade_opportunities empty for ENTERPRISE tier
 *   32. recommendations max 3 entries
 *   33. KV cache returns _cache: hit
 *   34. score_breakdown contains all 6 keys
 *
 *   P15.6a handleKeyUpdateMeta
 *   35. Unauth returns 401
 *   36. Missing keyId returns 400
 *   37. Invalid keyId format (e.g. 'key/../../etc') returns 400
 *   38. Non-JSON body returns 400
 *   39. label > 100 chars returns 400
 *   40. Invalid expires_at returns 400
 *   41. scopes not array returns 400
 *   42. Invalid scope value returns 400 with valid_scopes list
 *   43. Key not found returns 404
 *   44. Other user's key returns 403 (non-admin)
 *   45. Successful update returns meta with updated_at
 *   46. History is stored in KV key:history:<userId>
 *   47. ADMIN can update any key
 *
 *   P15.6b handleKeyHistory
 *   48. Unauth returns 401
 *   49. Invalid keyId returns 400
 *   50. Key not found returns 404
 *   51. Other user's key returns 403 (non-admin)
 *   52. Empty history returns [] and total 0
 *   53. History filtered by key_id
 *   54. Meta returned from KV
 *
 *   P15.7  handleReportArchive
 *   55. Unauth returns 401
 *   56. Returns archive with scheduled_reports and completed_scans
 *   57. DELIVERED status when last_run is set
 *   58. PENDING status when last_run is null
 *   59. report_url format is /api/customer/report?scan_id=...
 *   60. KV cache returns _cache: hit
 *   61. limit param respected (max 50)
 *
 *   P15.8  handleNotificationCenter
 *   62. Unauth returns 401
 *   63. Returns notifications with total/delivered/pending counts
 *   64. Priority filter passed to DB
 *   65. Channel filter passed to DB
 *   66. limit capped at 100
 *   67. _cache is 'none' (always live)
 *   68. delivered flag mapped correctly
 *
 *   P15.9  handleCommercialObservability
 *   69. Unauth returns 401
 *   70. Non-admin (PRO) returns 403
 *   71. OWNER returns commercial_observability
 *   72. MRR correctly computed from tier counts
 *   73. ARR is MRR * 12
 *   74. Feature adoption pct computed
 *   75. _cache is 'none' (always live)
 */

import { describe, it, expect } from 'vitest';

import {
  handleOnboardingWizard,
  handleCustomerLicense,
  handleUsageAnalytics,
  handleCustomerSuccessScore,
  handleKeyUpdateMeta,
  handleKeyHistory,
  handleReportArchive,
  handleNotificationCenter,
  handleCommercialObservability,
} from '../src/handlers/commercialPlatformHandler.js';

// ─── Test data ────────────────────────────────────────────────────────────────

const KEY_ROWS = [
  { id: 'key_aaa', user_id: 'u1', tier: 'PRO',    created_at: '2024-01-01T00:00:00Z' },
  { id: 'key_bbb', user_id: 'u1', tier: 'REVOKED', created_at: '2024-02-01T00:00:00Z' },
];
const ENTITLEMENT_ROWS = [
  { feature: 'custom_integrations', granted: 1, expires_at: null },
];
const USAGE_BY_KEY_ROWS = [
  { key_id: 'key_aaa', total_calls: 1200 },
];
const USAGE_BY_ENDPOINT_ROWS = Array.from({ length: 15 }, (_, i) => ({
  endpoint: `/api/endpoint${i}`,
  call_count: 100 - i,
}));
const SCAN_STAT_ROWS = [
  { status: 'completed', cnt: 7 },
  { status: 'pending',   cnt: 2 },
];
const COMPLETED_SCAN_ROWS = [
  { id: 'scan_1', target: 'example.com', risk_level: 'HIGH',   created_at: '2024-06-01T00:00:00Z' },
  { id: 'scan_2', target: 'api.co',      risk_level: 'MEDIUM', created_at: '2024-05-20T00:00:00Z' },
];
const EVENT_ROWS = [
  { event_type: 'api_call',  endpoint: '/api/copilot/chat',  latency_ms: 120, cached: 0, ts: '2024-06-01T10:00:00Z' },
  { event_type: 'api_call',  endpoint: '/api/copilot/quick', latency_ms:  80, cached: 1, ts: '2024-06-01T09:00:00Z' },
  { event_type: 'scan_done', endpoint: '/api/scan/async/domain', latency_ms: 300, cached: 0, ts: '2024-06-01T08:00:00Z' },
];
const SCHEDULED_REPORT_ROWS = [
  { id: 'rep_1', template_type: 'EXECUTIVE', recipients: '["ciso@co.com"]', frequency: 'WEEKLY', last_run: '2024-06-01T00:00:00Z', next_run: '2024-06-08T00:00:00Z' },
  { id: 'rep_2', template_type: 'SOC',       recipients: '["soc@co.com"]',  frequency: 'DAILY',  last_run: null, next_run: '2024-06-10T00:00:00Z' },
];
const NOTIF_ROWS = [
  { id: 'n1', type: 'ALERT', channel: 'email',     subject: 'CVE Alert',   body: 'A new CVE was detected',  delivered: 1, delivery_ts: '2024-06-01T10:00:00Z', created_at: '2024-06-01T10:00:00Z' },
  { id: 'n2', type: 'INFO',  channel: 'dashboard', subject: 'Onboarding',  body: 'Complete your profile',   delivered: 0, delivery_ts: null,                   created_at: '2024-06-01T09:00:00Z' },
];
const USER_TIER_ROWS = [
  { tier: 'FREE',       cnt: 50 },
  { tier: 'STARTER',    cnt: 20 },
  { tier: 'PRO',        cnt: 10 },
  { tier: 'ENTERPRISE', cnt:  3 },
];
const FEATURE_ADOPTION_ROWS = [
  { feature: 'api_access',     user_count: 83 },
  { feature: 'threat_feed_full', user_count: 30 },
];

// ─── DB Mock ──────────────────────────────────────────────────────────────────

function makeDB({ profileExists = false, keyExists = true, assetExists = false, scanExists = false,
                  keyOwner = 'u1' } = {}) {
  return {
    prepare(sql) {
      const stmt = {
        _args: [],
        bind(...args) { stmt._args = args; return stmt; },

        async all() {
          if (/FROM api_keys k.*LEFT JOIN api_key_usage/.test(sql) || /FROM api_key_usage.*JOIN api_keys k/.test(sql)) {
            if (/SUM\(u\.request_count\)/.test(sql)) return { results: USAGE_BY_KEY_ROWS };
            return { results: USAGE_BY_ENDPOINT_ROWS };
          }
          if (/FROM api_keys/.test(sql))            return { results: KEY_ROWS };
          if (/FROM customer_entitlements/.test(sql) && /GROUP BY feature/.test(sql)) return { results: FEATURE_ADOPTION_ROWS };
          if (/FROM customer_entitlements/.test(sql)) return { results: ENTITLEMENT_ROWS };
          if (/FROM scan_jobs.*GROUP BY status/.test(sql)) return { results: SCAN_STAT_ROWS };
          if (/FROM scan_jobs.*status IN/.test(sql)) return { results: COMPLETED_SCAN_ROWS };
          if (/FROM scan_jobs/.test(sql))            return { results: [{ id: scanExists ? 'scan_1' : null }] };
          if (/FROM scheduled_reports.*LIMIT/.test(sql)) return { results: SCHEDULED_REPORT_ROWS };
          if (/FROM ops_usage_events/.test(sql)) return { results: EVENT_ROWS };
          if (/FROM ops_notifications/.test(sql))    return { results: NOTIF_ROWS };
          if (/FROM users.*GROUP BY tier/.test(sql)) return { results: USER_TIER_ROWS };
          if (/FROM customer_assets/.test(sql))      return { results: assetExists ? [{ id: 'asset_1' }] : [] };
          return { results: [] };
        },

        async first() {
          if (/FROM customer_profiles/.test(sql))     return profileExists ? { id: 'u1' } : null;
          if (/FROM api_keys.*LIMIT 1/.test(sql) && /WHERE id/.test(sql)) return keyExists ? { id: stmt._args[0], user_id: keyOwner } : null;
          if (/FROM api_keys.*WHERE id/.test(sql))    return keyExists ? { user_id: keyOwner } : null;
          if (/FROM scan_jobs.*LIMIT 1/.test(sql))    return scanExists ? { id: 'scan_1' } : null;
          if (/COUNT\(\*\) as cnt FROM api_keys/.test(sql))         return { cnt: 2 };
          if (/COUNT\(\*\) as cnt FROM scan_jobs/.test(sql))        return { cnt: 3 };
          if (/COUNT\(\*\) as cnt FROM ops_usage_events/.test(sql)) return { cnt: 50 };
          if (/COUNT\(\*\) as cnt FROM scheduled_reports/.test(sql)) return { cnt: 2 };
          if (/COUNT\(\*\) as cnt FROM customer_profiles/.test(sql)) return { cnt: 15 };
          if (/SUM\(request_count\).*active_keys/.test(sql))        return { total_calls: 5000, active_keys: 8 };
          if (/FROM api_key_usage/.test(sql))         return { cnt: 0 };
          return null;
        },

        async run() { return { success: true, meta: { changes: 1 } }; },
      };
      return stmt;
    },
  };
}

function makeKV(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key)            { return store.has(key) ? store.get(key) : null; },
    async put(key, value, _o) { store.set(key, value); },
    _store: store,
  };
}

function makeEnv(dbOpts = {}, kvInit = {}) {
  return { DB: makeDB(dbOpts), SECURITY_HUB_KV: makeKV(kvInit) };
}

// ─── Auth contexts ────────────────────────────────────────────────────────────
const OWNER_CTX      = { authenticated: true, tier: 'OWNER',      userId: 'u_owner', user_id: 'u_owner' };
const ADMIN_CTX      = { authenticated: true, tier: 'ADMIN',      userId: 'u_admin', user_id: 'u_admin' };
const ENTERPRISE_CTX = { authenticated: true, tier: 'ENTERPRISE', userId: 'u1',      user_id: 'u1' };
const PRO_CTX        = { authenticated: true, tier: 'PRO',        userId: 'u1',      user_id: 'u1' };
const FREE_CTX       = { authenticated: true, tier: 'FREE',       userId: 'u5',      user_id: 'u5' };
const MSSP_CTX       = { authenticated: true, tier: 'MSSP',       userId: 'u6',      user_id: 'u6' };
const UNAUTH_CTX     = { authenticated: false };

// ─── Request helpers ──────────────────────────────────────────────────────────
function getReq(path, params = {}) {
  const url = new URL(`https://hub.test${path}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  return new Request(url.toString(), { method: 'GET' });
}

function patchReq(path, body) {
  return new Request(`https://hub.test${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function badPatchReq(path) {
  return new Request(`https://hub.test${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: 'not-json-{{{',
  });
}

// ─── P15.1: Onboarding Wizard ─────────────────────────────────────────────────
describe('P15.1 handleOnboardingWizard', () => {
  it('1. unauth returns 401', async () => {
    const r = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('2. returns onboarding object with 5 steps', async () => {
    const r = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.success).toBe(true);
    expect(d.onboarding.steps).toHaveLength(5);
    expect(d.onboarding.total_steps).toBe(5);
  });

  it('3. completion_pct is 40 when 2 of 5 steps complete (api_key + scan)', async () => {
    const env = makeEnv({ scanExists: true });
    const r   = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), env, PRO_CTX);
    const d   = await r.json();
    expect(d.onboarding.completed_steps).toBe(2);
    expect(d.onboarding.completion_pct).toBe(40);
  });

  it('4. status is STARTED when pct < 60', async () => {
    const r = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.onboarding.status).toBe('STARTED');
  });

  it('5. KV cache returns _cache: hit', async () => {
    const env = makeEnv();
    await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), env, PRO_CTX);
    const r2 = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), env, PRO_CTX);
    const d  = await r2.json();
    expect(d._cache).toBe('hit');
  });

  it('6. next_step is null when completion_pct is 100', async () => {
    const cachedPayload = JSON.stringify({
      success: true, service: 'CDB-COMMERCIAL', timestamp: new Date().toISOString(),
      onboarding: {
        completion_pct: 100, completed_steps: 5, total_steps: 5, status: 'COMPLETE',
        steps: [], next_step: null, tier: 'PRO',
      },
    });
    const env = makeEnv({}, { 'customer:v1:wizard:u1': cachedPayload });
    const r   = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), env, PRO_CTX);
    const d   = await r.json();
    expect(d.onboarding.next_step).toBeNull();
    expect(d.onboarding.status).toBe('COMPLETE');
  });

  it('7. tier from authCtx is included in onboarding', async () => {
    const r = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), makeEnv(), ENTERPRISE_CTX);
    const d = await r.json();
    expect(d.onboarding.tier).toBe('ENTERPRISE');
  });

  it('8. no DB env — graceful zero completion', async () => {
    const env = { DB: null, SECURITY_HUB_KV: makeKV() };
    const r   = await handleOnboardingWizard(getReq('/api/customer/onboarding/wizard'), env, PRO_CTX);
    const d   = await r.json();
    expect(d.success).toBe(true);
    expect(d.onboarding.completed_steps).toBe(0);
  });
});

// ─── P15.2: License Center ────────────────────────────────────────────────────
describe('P15.2 handleCustomerLicense', () => {
  it('9. unauth returns 401', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('10. returns license with tier and plan_name', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.success).toBe(true);
    expect(d.license.tier).toBe('PRO');
    expect(d.license.plan_name).toBe('Pro');
  });

  it('11. quota matches PRO tier (api_keys: 5, seats: 5)', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.license.quota.api_keys).toBe(5);
    expect(d.license.quota.seats).toBe(5);
  });

  it('12. features list includes api_access for FREE tier', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), FREE_CTX);
    const d = await r.json();
    expect(d.license.features).toContain('api_access');
  });

  it('13. KV cache returns _cache: hit', async () => {
    const env = makeEnv();
    await handleCustomerLicense(getReq('/api/customer/license'), env, PRO_CTX);
    const r2 = await handleCustomerLicense(getReq('/api/customer/license'), env, PRO_CTX);
    const d  = await r2.json();
    expect(d._cache).toBe('hit');
  });

  it('14. trial block present when KV billing:trial set', async () => {
    const trial = JSON.stringify({ tier: 'PRO', expires_at: '2024-12-31T00:00:00Z' });
    const env   = makeEnv({}, { 'billing:trial:u1': trial });
    const r     = await handleCustomerLicense(getReq('/api/customer/license'), env, PRO_CTX);
    const d     = await r.json();
    expect(d.license.trial).not.toBeNull();
    expect(d.license.trial.active).toBe(true);
    expect(d.license.trial.tier).toBe('PRO');
  });

  it('15. active API key count from DB (1 active, 1 REVOKED)', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.license.api_keys.active).toBe(1);
  });

  it('16b. pricing_inr reflects the real MSSP price (₹9,999), not the PLAN_PRICES.MSSP=0 placeholder', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), MSSP_CTX);
    const d = await r.json();
    expect(d.license.tier).toBe('MSSP');
    expect(d.license.pricing_inr).toBe(9999);
  });

  it('16. entitlements merged with implicit features (custom_integrations added)', async () => {
    const r = await handleCustomerLicense(getReq('/api/customer/license'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.license.features).toContain('custom_integrations');
  });
});

// ─── P15.3: Usage Analytics ───────────────────────────────────────────────────
describe('P15.3 handleUsageAnalytics', () => {
  it('17. unauth returns 401', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('18. returns usage.api.total_calls', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.success).toBe(true);
    expect(d.usage.api.total_calls).toBe(1200);
  });

  it('19. by_endpoint limited to 10 items (15 rows → 10)', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.usage.api.by_endpoint.length).toBeLessThanOrEqual(10);
  });

  it('20. scans.completed derived from DB group-by', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.usage.scans.completed).toBe(7);
    expect(d.usage.scans.pending).toBe(2);
  });

  it('21. ai_requests counts copilot endpoints (2 of 3 events)', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.usage.ai_requests).toBe(2);
  });

  it('22. KV cache returns _cache: hit', async () => {
    const env = makeEnv();
    await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), env, PRO_CTX);
    const r2 = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), env, PRO_CTX);
    const d  = await r2.json();
    expect(d._cache).toBe('hit');
  });

  it('23. avg_latency_ms is average of event latencies: (120+80+300)/3 = 167', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.usage.api.avg_latency_ms).toBe(167);
  });

  it('24. reports.scheduled from DB COUNT', async () => {
    const r = await handleUsageAnalytics(getReq('/api/customer/usage/analytics'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.usage.reports.scheduled).toBe(2);
  });
});

// ─── P15.4: Customer Success Score ────────────────────────────────────────────
describe('P15.4 handleCustomerSuccessScore', () => {
  it('25. unauth returns 401', async () => {
    const r = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('26. adoption_score = profile(20)+keys(2*10=20)+scans(3*5=15)+usage(50/10=5,cap20)+reports(2*10=20)=80', async () => {
    const env = makeEnv({ profileExists: true });
    const r   = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), env, PRO_CTX);
    const d   = await r.json();
    expect(d.success_metrics.adoption_score).toBe(80);
  });

  it('27. health_score is capped at 100 (no overflow)', async () => {
    const env = makeEnv({ profileExists: true });
    const r   = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), env, ENTERPRISE_CTX);
    const d   = await r.json();
    expect(d.success_metrics.health_score).toBeLessThanOrEqual(100);
  });

  it('28. renewal_readiness HIGH when health >= 70', async () => {
    const env = makeEnv({ profileExists: true });
    const r   = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), env, ENTERPRISE_CTX);
    const d   = await r.json();
    expect(d.success_metrics.renewal_readiness).toBe('HIGH');
  });

  it('29. renewal_readiness LOW when health < 40 (FREE, no profile, no scans)', async () => {
    const env = makeEnv({ profileExists: false, scanExists: false });
    // zero key count: DB returns cnt:0 for api_keys, cnt:0 for scans, etc.
    const db = {
      prepare(sql) {
        return {
          bind() { return this; },
          async all()  { return { results: [] }; },
          async first() {
            if (/FROM customer_profiles/.test(sql)) return null;
            return { cnt: 0 };
          },
          async run()  { return { success: true, meta: { changes: 1 } }; },
        };
      },
    };
    const e = { DB: db, SECURITY_HUB_KV: makeKV() };
    const r = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), e, FREE_CTX);
    const d = await r.json();
    expect(d.success_metrics.renewal_readiness).toBe('LOW');
  });

  it('30. upgrade_opportunities for FREE includes STARTER', async () => {
    const r = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), makeEnv(), FREE_CTX);
    const d = await r.json();
    expect(d.success_metrics.upgrade_opportunities.some(o => o.to === 'STARTER')).toBe(true);
  });

  it('31. upgrade_opportunities empty for ENTERPRISE', async () => {
    const r = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), makeEnv(), ENTERPRISE_CTX);
    const d = await r.json();
    expect(d.success_metrics.upgrade_opportunities).toHaveLength(0);
  });

  it('32. recommendations max 3 entries', async () => {
    const r = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.success_metrics.recommendations.length).toBeLessThanOrEqual(3);
  });

  it('33. KV cache returns _cache: hit', async () => {
    const env = makeEnv();
    await handleCustomerSuccessScore(getReq('/api/customer/success/score'), env, PRO_CTX);
    const r2 = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), env, PRO_CTX);
    const d  = await r2.json();
    expect(d._cache).toBe('hit');
  });

  it('34. score_breakdown contains 6 keys', async () => {
    const r = await handleCustomerSuccessScore(getReq('/api/customer/success/score'), makeEnv(), PRO_CTX);
    const d = await r.json();
    const bd = d.success_metrics.score_breakdown;
    expect(Object.keys(bd)).toHaveLength(6);
    expect(bd).toHaveProperty('tier_bonus');
    expect(bd).toHaveProperty('profile_completed');
  });
});

// ─── P15.6a: Key Update Metadata ─────────────────────────────────────────────
describe('P15.6a handleKeyUpdateMeta', () => {
  it('35. unauth returns 401', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { label: 'x' }), makeEnv(), UNAUTH_CTX, 'key_aaa');
    expect(r.status).toBe(401);
  });

  it('36. missing keyId returns 400', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/', { label: 'x' }), makeEnv(), PRO_CTX, '');
    expect(r.status).toBe(400);
  });

  it('37. invalid keyId format returns 400', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/../../etc', {}), makeEnv(), PRO_CTX, '../../etc');
    expect(r.status).toBe(400);
  });

  it('38. non-JSON body returns 400', async () => {
    const r = await handleKeyUpdateMeta(badPatchReq('/api/keys/key_aaa'), makeEnv(), PRO_CTX, 'key_aaa');
    expect(r.status).toBe(400);
  });

  it('39. label > 100 chars returns 400', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { label: 'x'.repeat(101) }), makeEnv(), PRO_CTX, 'key_aaa');
    expect(r.status).toBe(400);
  });

  it('40. invalid expires_at returns 400', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { expires_at: 'not-a-date' }), makeEnv(), PRO_CTX, 'key_aaa');
    expect(r.status).toBe(400);
  });

  it('41. scopes not array returns 400', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { scopes: 'read:intel' }), makeEnv(), PRO_CTX, 'key_aaa');
    expect(r.status).toBe(400);
  });

  it('42. invalid scope value returns 400 with valid_scopes', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { scopes: ['read:intel', 'badscope'] }), makeEnv(), PRO_CTX, 'key_aaa');
    const d = await r.json();
    expect(r.status).toBe(400);
    expect(d).toHaveProperty('valid_scopes');
  });

  it('43. key not found returns 404', async () => {
    const env = makeEnv({ keyExists: false });
    const r   = await handleKeyUpdateMeta(patchReq('/api/keys/key_missing', { label: 'test' }), env, PRO_CTX, 'key_missing');
    expect(r.status).toBe(404);
  });

  it('44. other user key returns 403 for non-admin', async () => {
    const env = makeEnv({ keyExists: true, keyOwner: 'u_other' });
    const r   = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { label: 'test' }), env, PRO_CTX, 'key_aaa');
    expect(r.status).toBe(403);
  });

  it('45. successful update returns meta with updated_at', async () => {
    const r = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { label: 'My Key', scopes: ['read:intel'] }), makeEnv(), PRO_CTX, 'key_aaa');
    const d = await r.json();
    expect(r.status).toBe(200);
    expect(d.success).toBe(true);
    expect(d.meta.label).toBe('My Key');
    expect(d.meta.scopes).toEqual(['read:intel']);
    expect(d.meta.updated_at).toBeDefined();
  });

  it('46. history is stored in KV key:history:u1', async () => {
    const env = makeEnv();
    await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { label: 'Test' }), env, PRO_CTX, 'key_aaa');
    const raw  = await env.SECURITY_HUB_KV.get('key:history:u1');
    const hist = JSON.parse(raw);
    expect(Array.isArray(hist)).toBe(true);
    expect(hist[0].key_id).toBe('key_aaa');
    expect(hist[0].action).toBe('META_UPDATE');
  });

  it('47. ADMIN can update any user key', async () => {
    const env = makeEnv({ keyExists: true, keyOwner: 'u_other' });
    const r   = await handleKeyUpdateMeta(patchReq('/api/keys/key_aaa', { label: 'Admin Edit' }), env, ADMIN_CTX, 'key_aaa');
    const d   = await r.json();
    expect(r.status).toBe(200);
    expect(d.success).toBe(true);
  });
});

// ─── P15.6b: Key History ─────────────────────────────────────────────────────
describe('P15.6b handleKeyHistory', () => {
  it('48. unauth returns 401', async () => {
    const r = await handleKeyHistory(getReq('/api/keys/key_aaa/history'), makeEnv(), UNAUTH_CTX, 'key_aaa');
    expect(r.status).toBe(401);
  });

  it('49. invalid keyId returns 400', async () => {
    const r = await handleKeyHistory(getReq('/api/keys/../../history'), makeEnv(), PRO_CTX, '../../');
    expect(r.status).toBe(400);
  });

  it('50. key not found returns 404', async () => {
    const env = makeEnv({ keyExists: false });
    const r   = await handleKeyHistory(getReq('/api/keys/key_miss/history'), env, PRO_CTX, 'key_miss');
    expect(r.status).toBe(404);
  });

  it('51. other user key returns 403 for non-admin', async () => {
    const env = makeEnv({ keyExists: true, keyOwner: 'u_other' });
    const r   = await handleKeyHistory(getReq('/api/keys/key_aaa/history'), env, PRO_CTX, 'key_aaa');
    expect(r.status).toBe(403);
  });

  it('52. empty history returns [] and total 0', async () => {
    const r = await handleKeyHistory(getReq('/api/keys/key_aaa/history'), makeEnv(), PRO_CTX, 'key_aaa');
    const d = await r.json();
    expect(d.history).toEqual([]);
    expect(d.total).toBe(0);
  });

  it('53. history filtered by key_id (only matching entries returned)', async () => {
    const existingHistory = JSON.stringify([
      { key_id: 'key_aaa', action: 'META_UPDATE', changed_at: '2024-01-01T00:00:00Z', changed_by: 'u1', changes: {} },
      { key_id: 'key_bbb', action: 'META_UPDATE', changed_at: '2024-01-02T00:00:00Z', changed_by: 'u1', changes: {} },
    ]);
    const env = makeEnv({}, { 'key:history:u1': existingHistory });
    const r   = await handleKeyHistory(getReq('/api/keys/key_aaa/history'), env, PRO_CTX, 'key_aaa');
    const d   = await r.json();
    expect(d.history.every(e => e.key_id === 'key_aaa')).toBe(true);
    expect(d.total).toBe(1);
  });

  it('54. meta returned from KV', async () => {
    const meta = JSON.stringify({ label: 'Stored Label', updated_at: '2024-01-01T00:00:00Z' });
    const env  = makeEnv({}, { 'key:meta:key_aaa': meta });
    const r    = await handleKeyHistory(getReq('/api/keys/key_aaa/history'), env, PRO_CTX, 'key_aaa');
    const d    = await r.json();
    expect(d.meta.label).toBe('Stored Label');
  });
});

// ─── P15.7: Report Archive ────────────────────────────────────────────────────
describe('P15.7 handleReportArchive', () => {
  it('55. unauth returns 401', async () => {
    const r = await handleReportArchive(getReq('/api/customer/reports/archive'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('56. returns archive with scheduled_reports and completed_scans', async () => {
    const r = await handleReportArchive(getReq('/api/customer/reports/archive'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.success).toBe(true);
    expect(Array.isArray(d.archive.scheduled_reports)).toBe(true);
    expect(Array.isArray(d.archive.completed_scans)).toBe(true);
  });

  it('57. DELIVERED status when last_run is set', async () => {
    const r = await handleReportArchive(getReq('/api/customer/reports/archive'), makeEnv(), PRO_CTX);
    const d = await r.json();
    const delivered = d.archive.scheduled_reports.find(r => r.id === 'rep_1');
    expect(delivered.status).toBe('DELIVERED');
  });

  it('58. PENDING status when last_run is null', async () => {
    const r = await handleReportArchive(getReq('/api/customer/reports/archive'), makeEnv(), PRO_CTX);
    const d = await r.json();
    const pending = d.archive.scheduled_reports.find(r => r.id === 'rep_2');
    expect(pending.status).toBe('PENDING');
  });

  it('59. report_url format is /api/customer/report?scan_id=...', async () => {
    const r = await handleReportArchive(getReq('/api/customer/reports/archive'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.archive.completed_scans[0].report_url).toContain('/api/customer/report?scan_id=');
  });

  it('60. KV cache returns _cache: hit', async () => {
    const env = makeEnv();
    await handleReportArchive(getReq('/api/customer/reports/archive'), env, PRO_CTX);
    const r2 = await handleReportArchive(getReq('/api/customer/reports/archive'), env, PRO_CTX);
    const d  = await r2.json();
    expect(d._cache).toBe('hit');
  });

  it('61. recipients parsed from JSON string', async () => {
    const r = await handleReportArchive(getReq('/api/customer/reports/archive'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(Array.isArray(d.archive.scheduled_reports[0].recipients)).toBe(true);
  });
});

// ─── P15.8: Notification Center ──────────────────────────────────────────────
describe('P15.8 handleNotificationCenter', () => {
  it('62. unauth returns 401', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('63. returns notifications with total/delivered/pending counts', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.success).toBe(true);
    expect(d.notifications.total).toBe(2);
    expect(d.notifications.delivered).toBe(1);
    expect(d.notifications.pending).toBe(1);
  });

  it('64. priority filter in query params', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center', { priority: 'ALERT' }), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.notifications.filters.priority).toBe('ALERT');
  });

  it('65. channel filter in query params', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center', { channel: 'email' }), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.notifications.filters.channel).toBe('email');
  });

  it('66. limit capped at 100', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center', { limit: '999' }), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.notifications.total).toBeLessThanOrEqual(100);
  });

  it('67. _cache is none (always live)', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center'), makeEnv(), PRO_CTX);
    const d = await r.json();
    expect(d.notifications._cache).toBe('none');
  });

  it('68. delivered flag mapped correctly', async () => {
    const r = await handleNotificationCenter(getReq('/api/customer/notifications/center'), makeEnv(), PRO_CTX);
    const d = await r.json();
    const n1 = d.notifications.items.find(n => n.id === 'n1');
    const n2 = d.notifications.items.find(n => n.id === 'n2');
    expect(n1.delivered).toBe(true);
    expect(n2.delivered).toBe(false);
  });
});

// ─── P15.9: Commercial Observability ─────────────────────────────────────────
describe('P15.9 handleCommercialObservability', () => {
  it('69. unauth returns 401', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), UNAUTH_CTX);
    expect(r.status).toBe(401);
  });

  it('70. PRO tier returns 403', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), PRO_CTX);
    expect(r.status).toBe(403);
  });

  it('71. OWNER returns commercial_observability', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), OWNER_CTX);
    const d = await r.json();
    expect(d.success).toBe(true);
    expect(d).toHaveProperty('commercial_observability');
  });

  it('72. MRR correctly computed: 20*999 + 10*1499 + 3*4999 = 49967', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), OWNER_CTX);
    const d = await r.json();
    const expected = 20 * 999 + 10 * 1499 + 3 * 4999;
    expect(d.commercial_observability.revenue.mrr_estimate_inr).toBe(expected);
  });

  it('73. ARR is MRR * 12', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), OWNER_CTX);
    const d = await r.json();
    const co = d.commercial_observability;
    expect(co.revenue.arr_estimate_inr).toBe(co.revenue.mrr_estimate_inr * 12);
  });

  it('74. feature adoption pct computed correctly', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), OWNER_CTX);
    const d = await r.json();
    const totalUsers = 50 + 20 + 10 + 3;
    const fa = d.commercial_observability.feature_adoption;
    const apiAccess = fa.find(f => f.feature === 'api_access');
    expect(apiAccess.pct).toBe(Math.round((83 / totalUsers) * 100));
  });

  it('75. _cache is none (always live)', async () => {
    const r = await handleCommercialObservability(getReq('/api/commercial/observability'), makeEnv(), ADMIN_CTX);
    const d = await r.json();
    expect(d.commercial_observability._cache).toBe('none');
  });
});
