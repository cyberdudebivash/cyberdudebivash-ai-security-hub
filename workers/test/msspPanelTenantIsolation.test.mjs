// CAP-MSSP-005 — MSSP Client Portfolio + White-Label Panel
// (workers/src/handlers/msspPanel.js). Registry evidence previously read:
// zero test coverage (confirmed again here: no existing test file imports
// this module) and a *speculated, unconfirmed* tenant-collision risk.
//
// This suite closes both gaps, and documents a real fix made while writing
// it: every mssp_id-scoping call site computed
//   authCtx?.userId || authCtx?.orgId || 'default_mssp'
// but authCtx.orgId (camelCase) is never populated anywhere in the auth
// layer (workers/src/auth/middleware.js's withAuthAliases only ever sets
// the snake_case authCtx.org_id — see its own "Tenant isolation (root fix)"
// comment, which built this exact mechanism after a "confirmed on SOC
// cases" cross-tenant leak in ~15 OTHER handlers scoping on
// `authCtx.org_id || 'default'`). Because MSSP partner sessions
// (handlers/partnerAuth.js's resolvePartnerSession) always carry
// user_id: null, every partner-tier caller's mssp_id fallback chain
// silently bottomed out at the literal shared string 'default_mssp' —
// meaning any two reseller partners (a real, currently-onboardable tier;
// see handlers/msspOps.js's handleAddMsspPartner and
// handlers/msspOnboardingHandler.js, neither of which validates the
// caller-supplied tier against an allow-list, and schema_master.sql's
// mssp_partners.tier column has no CHECK constraint) shared and could
// silently overwrite each other's entire client roster and white-label
// branding. Fixed by reading the real field name, authCtx.org_id.
//
// Response envelope: all handlers return ok()/fail() from lib/response.js
// — success payloads are nested under body.data, and error responses carry
// the machine code at the top-level body.code (body.error is the human
// message string, not an object).
import { describe, it, expect, beforeEach } from 'vitest';
import {
  handleListClients, handleOnboardClient, handleGetClient, handleUpdateClient,
  handleOffboardClient, handleGetSummary, handleGetAlerts,
  handleSetWhitelabel, handleGetWhitelabel,
} from '../src/handlers/msspPanel.js';

function makeKV() {
  const store = new Map();
  return {
    _store: store,
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
  };
}

function req(url, { method = 'GET', body } = {}) {
  return {
    url,
    method,
    json: async () => body ?? {},
  };
}

async function j(resPromise) {
  const res = await resPromise;
  const body = await res.json();
  return { status: res.status, body, data: body.data };
}

// Two independently-onboarded reseller partners — the exact real-world
// shape resolvePartnerSession produces: user_id is always null, org_id is
// `partner:${partnerId}` (set by withAuthAliases), tier is caller-supplied
// at onboarding time and can legitimately be 'MSSP' or 'ENTERPRISE'.
const partnerA = { authenticated: true, tier: 'MSSP', userId: null, org_id: 'partner:alpha-resellers' };
const partnerB = { authenticated: true, tier: 'MSSP', userId: null, org_id: 'partner:beta-mssp-co' };

// A real JWT-authenticated ENTERPRISE customer — always has userId set, so
// it was never affected by the orgId/org_id bug, but must keep working
// identically after the fix (userId stays first-priority).
const jwtCustomer1 = { authenticated: true, tier: 'ENTERPRISE', userId: 'cust_1' };
const jwtCustomer2 = { authenticated: true, tier: 'ENTERPRISE', userId: 'cust_2' };

describe('requireMSSP auth guard — every entry point rejects non-MSSP/ENTERPRISE tiers', () => {
  it('rejects an unauthenticated/FREE caller', async () => {
    const { status, body } = await j(handleListClients(req('https://x/api/mssp/clients'), makeKV(), {}));
    expect(status).toBe(403);
    expect(body.code).toBe('MSSP_REQUIRED');
  });

  it('rejects a PRO-tier caller', async () => {
    const { status } = await j(handleListClients(req('https://x/api/mssp/clients'), makeKV(), { tier: 'PRO', userId: 'u1' }));
    expect(status).toBe(403);
  });

  it('admits an MSSP-tier caller', async () => {
    const { status } = await j(handleListClients(req('https://x/api/mssp/clients'), { SECURITY_HUB_KV: makeKV() }, partnerA));
    expect(status).toBe(200);
  });

  it('admits an ENTERPRISE-tier caller', async () => {
    const { status } = await j(handleListClients(req('https://x/api/mssp/clients'), { SECURITY_HUB_KV: makeKV() }, jwtCustomer1));
    expect(status).toBe(200);
  });
});

describe('Tenant isolation fix — partner sessions no longer collide on a shared bucket', () => {
  let kv, env;
  beforeEach(() => { kv = makeKV(); env = { SECURITY_HUB_KV: kv }; });

  it('two different reseller partners get fully isolated client rosters', async () => {
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Alpha Client', domain: 'alpha-client.com' } }), env, partnerA);
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Beta Client', domain: 'beta-client.com' } }), env, partnerB);

    const { data: listA } = await j(handleListClients(req('https://x/api/mssp/clients'), env, partnerA));
    const { data: listB } = await j(handleListClients(req('https://x/api/mssp/clients'), env, partnerB));

    expect(listA.total).toBe(1);
    expect(listA.clients[0].domain).toBe('alpha-client.com');
    expect(listB.total).toBe(1);
    expect(listB.clients[0].domain).toBe('beta-client.com');

    // Before the fix both would have been stored under the literal key
    // 'mssp:clients_index:default_mssp' and each onboarding call would have
    // silently overwritten the other partner's roster.
    expect(kv._store.has('mssp:clients_index:partner:alpha-resellers')).toBe(true);
    expect(kv._store.has('mssp:clients_index:partner:beta-mssp-co')).toBe(true);
    expect(kv._store.has('mssp:clients_index:default_mssp')).toBe(false);
  });

  it('two different reseller partners get fully isolated white-label branding', async () => {
    await handleSetWhitelabel(req('https://x/api/mssp/whitelabel', { method: 'POST', body: { brand_name: 'Alpha Security' } }), env, partnerA);
    await handleSetWhitelabel(req('https://x/api/mssp/whitelabel', { method: 'POST', body: { brand_name: 'Beta Security' } }), env, partnerB);

    const { data: wlA } = await j(handleGetWhitelabel(req('https://x/api/mssp/whitelabel'), env, partnerA));
    const { data: wlB } = await j(handleGetWhitelabel(req('https://x/api/mssp/whitelabel'), env, partnerB));

    expect(wlA.whitelabel.brand_name).toBe('Alpha Security');
    expect(wlB.whitelabel.brand_name).toBe('Beta Security');
  });

  it('a partner cannot read another partner client by id even if it guesses the id', async () => {
    const { data: onboarded } = await j(handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Alpha Client', domain: 'alpha-only.com' } }), env, partnerA));
    const client_id = onboarded.client_id;

    const asOwner = await handleGetClient(req(`https://x/api/mssp/clients/${client_id}`), env, partnerA);
    const asOther = await handleGetClient(req(`https://x/api/mssp/clients/${client_id}`), env, partnerB);
    expect(asOwner.status).toBe(200);
    expect(asOther.status).toBe(404);
  });

  it('regression guard: real JWT ENTERPRISE customers keep their pre-existing userId-scoped isolation unchanged', async () => {
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Cust1 Client', domain: 'cust1-client.com' } }), env, jwtCustomer1);
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Cust2 Client', domain: 'cust2-client.com' } }), env, jwtCustomer2);

    const { data: list1 } = await j(handleListClients(req('https://x/api/mssp/clients'), env, jwtCustomer1));
    const { data: list2 } = await j(handleListClients(req('https://x/api/mssp/clients'), env, jwtCustomer2));
    expect(list1.total).toBe(1);
    expect(list1.clients[0].domain).toBe('cust1-client.com');
    expect(list2.total).toBe(1);
    expect(list2.clients[0].domain).toBe('cust2-client.com');
    expect(kv._store.has('mssp:clients_index:cust_1')).toBe(true);
    expect(kv._store.has('mssp:clients_index:cust_2')).toBe(true);
  });

  it('documented residual: a caller with neither userId nor org_id still falls back to the shared default bucket', async () => {
    // Cannot occur via any real resolver path today (every authenticated
    // context reaching requireMSSP has either userId or org_id populated —
    // see withAuthAliases), but the fallback itself is intentionally kept
    // rather than removed, so this documents the boundary explicitly.
    const bareAuthCtx = { authenticated: true, tier: 'ENTERPRISE' };
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Bare Client', domain: 'bare-client.com' } }), env, bareAuthCtx);
    expect(kv._store.has('mssp:clients_index:default_mssp')).toBe(true);
  });
});

describe('handleListClients — search and pagination', () => {
  let env;
  beforeEach(async () => {
    env = { SECURITY_HUB_KV: makeKV() };
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Acme Corp', domain: 'acme.com', sector: 'FINANCE' } }), env, partnerA);
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Globex Inc', domain: 'globex.com', sector: 'HEALTHCARE' } }), env, partnerA);
  });

  it('lists all clients with no filter', async () => {
    const { data } = await j(handleListClients(req('https://x/api/mssp/clients'), env, partnerA));
    expect(data.total).toBe(2);
    expect(data.filtered).toBe(2);
  });

  it('filters by name/domain/sector substring, case-insensitively', async () => {
    const { data } = await j(handleListClients(req('https://x/api/mssp/clients?q=FINANCE'), env, partnerA));
    expect(data.filtered).toBe(1);
    expect(data.clients[0].name).toBe('Acme Corp');
  });

  it('caps the page size at the requested limit', async () => {
    const { data } = await j(handleListClients(req('https://x/api/mssp/clients?limit=1'), env, partnerA));
    expect(data.clients).toHaveLength(1);
    expect(data.total).toBe(2);
  });
});

describe('handleOnboardClient — validation and real persistence', () => {
  let env;
  beforeEach(() => { env = { SECURITY_HUB_KV: makeKV() }; });

  it('rejects a request missing name or domain', async () => {
    const { status, body } = await j(handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Only Name' } }), env, partnerA));
    expect(status).toBe(400);
    expect(body.code).toBe('MISSING_FIELDS');
  });

  it('rejects a duplicate domain within the same tenant', async () => {
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'First', domain: 'dup.com' } }), env, partnerA);
    const { status, body } = await j(handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Second', domain: 'dup.com' } }), env, partnerA));
    expect(status).toBe(409);
    expect(body.code).toBe('DUPLICATE_DOMAIN');
  });

  it('allows the same domain to be onboarded independently by two different tenants', async () => {
    const resA = await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Shared Domain Co', domain: 'shared.com' } }), env, partnerA);
    const resB = await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Shared Domain Co', domain: 'shared.com' } }), env, partnerB);
    expect(resA.status).toBe(200);
    expect(resB.status).toBe(200);
  });

  it('persists a real client record with the onboarding identity recorded', async () => {
    const { data } = await j(handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'New Co', domain: 'newco.com', contact_email: 'ciso@newco.com' } }), env, { ...partnerA, email: 'partner@alpha.com' }));
    expect(data.onboarded).toBe(true);
    expect(data.client.status).toBe('ACTIVE');
    expect(data.client.onboarded_by).toBe('partner@alpha.com');
    expect(data.client.contact_email).toBe('ciso@newco.com');
  });
});

describe('handleGetClient / handleUpdateClient / handleOffboardClient', () => {
  let env, client_id;
  beforeEach(async () => {
    env = { SECURITY_HUB_KV: makeKV() };
    const { data } = await j(handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'Target Co', domain: 'target.com' } }), env, partnerA));
    client_id = data.client_id;
  });

  it('handleGetClient returns 404 for a nonexistent client', async () => {
    const res = await handleGetClient(req('https://x/api/mssp/clients/nope'), env, partnerA);
    expect(res.status).toBe(404);
  });

  it('handleGetClient returns full detail plus a synthesized posture object', async () => {
    const { data } = await j(handleGetClient(req(`https://x/api/mssp/clients/${client_id}`), env, partnerA));
    expect(data.name).toBe('Target Co');
    expect(data.posture).toMatchObject({ threats_detected: 0, compliance_score: 50 });
  });

  it('handleUpdateClient only applies allow-listed fields, ignoring the rest', async () => {
    const { data } = await j(handleUpdateClient(req(`https://x/api/mssp/clients/${client_id}`, { method: 'PUT', body: { name: 'Renamed Co', mssp_id: 'hijacked', onboarded_by: 'hijacked' } }), env, partnerA));
    expect(data.client.name).toBe('Renamed Co');
    expect(data.client.mssp_id).not.toBe('hijacked');
    expect(data.client.onboarded_by).not.toBe('hijacked');
  });

  it('handleUpdateClient syncs the name/domain/status/tier change into the list index', async () => {
    await handleUpdateClient(req(`https://x/api/mssp/clients/${client_id}`, { method: 'PUT', body: { status: 'SUSPENDED' } }), env, partnerA);
    const { data } = await j(handleListClients(req('https://x/api/mssp/clients'), env, partnerA));
    expect(data.clients[0].status).toBe('SUSPENDED');
  });

  it('handleUpdateClient returns 404 for a nonexistent client', async () => {
    const res = await handleUpdateClient(req('https://x/api/mssp/clients/nope', { method: 'PUT', body: { name: 'X' } }), env, partnerA);
    expect(res.status).toBe(404);
  });

  it('handleOffboardClient removes the client from both detail storage and the index', async () => {
    const res = await handleOffboardClient(req(`https://x/api/mssp/clients/${client_id}`, { method: 'DELETE' }), env, partnerA);
    expect(res.status).toBe(200);

    const getRes = await handleGetClient(req(`https://x/api/mssp/clients/${client_id}`), env, partnerA);
    expect(getRes.status).toBe(404);
    const { data } = await j(handleListClients(req('https://x/api/mssp/clients'), env, partnerA));
    expect(data.total).toBe(0);
  });
});

describe('handleGetSummary — real aggregation math, not fabricated', () => {
  it('computes active/inactive counts, total alerts, and tier/sector breakdowns from real onboarded clients', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    await handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'A', domain: 'a.com', sector: 'FINANCE', tier: 'PRO' } }), env, partnerA);
    const { data: onboardedB } = await j(handleOnboardClient(req('https://x/api/mssp/clients', { method: 'POST', body: { name: 'B', domain: 'b.com', sector: 'FINANCE', tier: 'ENTERPRISE' } }), env, partnerA));
    await handleUpdateClient(req(`https://x/api/mssp/clients/${onboardedB.client_id}`, { method: 'PUT', body: { status: 'SUSPENDED' } }), env, partnerA);

    const { data } = await j(handleGetSummary(req('https://x/api/mssp/summary'), env, partnerA));
    expect(data.total_clients).toBe(2);
    expect(data.active_clients).toBe(1);
    expect(data.inactive_clients).toBe(1);
    expect(data.tier_breakdown).toMatchObject({ PRO: 1, ENTERPRISE: 1 });
    expect(data.sector_breakdown).toMatchObject({ FINANCE: 2 });
  });

  it('an empty tenant gets real zeros, not fabricated placeholder numbers', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { data } = await j(handleGetSummary(req('https://x/api/mssp/summary'), env, partnerB));
    expect(data.total_clients).toBe(0);
    expect(data.total_open_alerts).toBe(0);
    expect(data.tier_breakdown).toEqual({});
  });
});

describe('handleGetAlerts — global cross-client feed, not tenant-scoped by design', () => {
  it('returns an honest empty feed with no KV binding', async () => {
    const { data } = await j(handleGetAlerts(req('https://x/api/mssp/alerts'), {}, partnerA));
    expect(data.total).toBe(0);
    expect(data.alerts).toEqual([]);
  });

  it('returns real stored alerts, capped at the requested limit, identically for every tenant', async () => {
    const kv = makeKV();
    await kv.put('mssp:alerts_feed', JSON.stringify([{ id: 'al1' }, { id: 'al2' }, { id: 'al3' }]));
    const env = { SECURITY_HUB_KV: kv };
    const { data: dataA } = await j(handleGetAlerts(req('https://x/api/mssp/alerts?limit=2'), env, partnerA));
    const { data: dataB } = await j(handleGetAlerts(req('https://x/api/mssp/alerts?limit=2'), env, partnerB));
    expect(dataA.alerts).toHaveLength(2);
    expect(dataB.alerts).toHaveLength(2);
    expect(dataA).toEqual(dataB);
  });
});

describe('handleSetWhitelabel / handleGetWhitelabel — allow-listed round-trip config', () => {
  it('only persists allow-listed fields', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    await handleSetWhitelabel(req('https://x/api/mssp/whitelabel', { method: 'POST', body: { brand_name: 'Acme MSSP', not_a_real_field: 'should be dropped' } }), env, partnerA);
    const { data } = await j(handleGetWhitelabel(req('https://x/api/mssp/whitelabel'), env, partnerA));
    expect(data.whitelabel.brand_name).toBe('Acme MSSP');
    expect(data.whitelabel.not_a_real_field).toBeUndefined();
  });

  it('returns an empty config for a tenant that never configured white-label', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { data } = await j(handleGetWhitelabel(req('https://x/api/mssp/whitelabel'), env, partnerB));
    expect(data.whitelabel).toEqual({});
  });
});
