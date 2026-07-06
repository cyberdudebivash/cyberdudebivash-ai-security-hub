// serviceOrderEngine.js's createServiceOrder() had no payment/auth gate at
// all: POST /api/services/orders (no tier check, reachable anonymously)
// auto-dispatched the real assessment engine — a real, billable
// (ai_security_enterprise, threat_hunting, etc.) run — immediately, with
// payment_status permanently stuck at 'pending' (nothing anywhere ever set
// it to 'paid'). Anyone could get a full paid assessment for free.
// Separately, handleCreateOrder (serviceHandlers.js) ran a second, redundant
// dispatch on top of createServiceOrder's own dispatch, running every
// automated assessment twice. Locks both fixes (2026-07-06 revenue-mechanisms
// audit, P0-3).
import { describe, it, expect, vi, beforeEach } from 'vitest';

const sslMock = vi.fn(async () => ({ findings: [], meta: { service_name: 'SSL Security Scan' } }));
vi.mock('../src/services/sslSecurityEngine.js', () => ({ runSSLCheck: sslMock }));
vi.mock('../src/services/mythosEnrichmentEngine.js', () => ({
  enrichAssessmentWithMYTHOS: vi.fn(async ({ report }) => report),
}));

const { createServiceOrder } = await import('../src/services/serviceOrderEngine.js');
const { handleCreateOrder } = await import('../src/handlers/serviceHandlers.js');

function makeEnv() {
  const serviceOrders = [];
  const services = new Map([
    ['CDB-SSL-001', {
      ref_id: 'CDB-SSL-001', name: 'SSL Security Check', price_inr: 999, price_usd: 12,
      delivery_type: 'automated', automated_engine: 'ssl', delivery_hours: 0, active: 1,
    }],
    ['CDB-CONSULT-001', {
      ref_id: 'CDB-CONSULT-001', name: 'Security Consultation', price_inr: 999, price_usd: 12,
      delivery_type: 'manual', automated_engine: null, delivery_hours: 24, active: 1,
    }],
  ]);

  const env = {
    DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async first() {
            if (/SELECT \* FROM services WHERE ref_id/.test(sql)) {
              return services.get(bound[0]) || null;
            }
            return null;
          },
          async run() {
            if (/INSERT INTO service_orders/.test(sql)) {
              serviceOrders.push({ id: bound[0], order_status: bound[13] });
            }
            return { success: true };
          },
          async all() { return { results: [] }; },
        };
      },
    },
  };
  return { env, serviceOrders };
}

function body(overrides = {}) {
  return {
    ref_id: 'CDB-SSL-001', customer_name: 'Buyer', customer_email: 'buyer@x.com',
    target_domain: 'example.com', ...overrides,
  };
}

beforeEach(() => { sslMock.mockClear(); });

describe('createServiceOrder — payment/tier gate before auto-dispatch', () => {
  it('does NOT dispatch the real engine for an anonymous caller (was: free paid assessment)', async () => {
    const { env } = makeEnv();
    const result = await createServiceOrder(env, body(), {});
    expect(result.auto_started).toBe(false);
    expect(result.order_status).toBe('new');
    expect(sslMock).not.toHaveBeenCalled();
  });

  it('does NOT dispatch for an authenticated but FREE-tier caller', async () => {
    const { env } = makeEnv();
    const result = await createServiceOrder(env, body(), { tier: 'FREE', user_id: 'u1' });
    expect(result.auto_started).toBe(false);
    expect(sslMock).not.toHaveBeenCalled();
  });

  it('dispatches for a real paying subscriber (STARTER/PRO/ENTERPRISE/MSSP)', async () => {
    const { env } = makeEnv();
    const result = await createServiceOrder(env, body(), { tier: 'PRO', user_id: 'u2' });
    expect(result.auto_started).toBe(true);
    expect(result.order_status).toBe('in_progress');
    expect(sslMock).toHaveBeenCalledTimes(1);
  });

  it('dispatches for an admin caller regardless of tier', async () => {
    const { env } = makeEnv();
    const result = await createServiceOrder(env, body(), { isAdmin: true });
    expect(result.auto_started).toBe(true);
    expect(sslMock).toHaveBeenCalledTimes(1);
  });

  it('manual (non-automated) services are unaffected by the gate either way', async () => {
    const { env } = makeEnv();
    const result = await createServiceOrder(env, body({ ref_id: 'CDB-CONSULT-001' }), { tier: 'PRO' });
    expect(result.auto_started).toBe(false);
    expect(result.message).toContain('Manual service');
  });
});

describe('handleCreateOrder (POST /api/services/orders) — no more double-dispatch', () => {
  it('runs the automated engine exactly once per order, not twice', async () => {
    const { env } = makeEnv();
    const req = new Request('https://x/api/services/orders', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body()),
    });
    const waited = [];
    const ctx = { waitUntil: (p) => waited.push(p) };
    const res = await handleCreateOrder(req, env, { tier: 'ENTERPRISE', user_id: 'u3' }, ctx);
    expect(res.status).toBe(201);
    await Promise.all(waited);
    expect(sslMock).toHaveBeenCalledTimes(1);
  });

  it('anonymous callers get a recorded-but-not-dispatched order, not a 4xx (no public checkout exists yet for this catalog)', async () => {
    const { env } = makeEnv();
    const req = new Request('https://x/api/services/orders', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body()),
    });
    const res = await handleCreateOrder(req, env, {}, { waitUntil: () => {} });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.auto_started).toBe(false);
    expect(sslMock).not.toHaveBeenCalled();
  });
});
