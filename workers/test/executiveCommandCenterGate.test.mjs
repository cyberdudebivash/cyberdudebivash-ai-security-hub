/* Regression test — RBAC-0. /api/executive/* (handlers/executiveCommandCenter.js,
 * FAIR risk modeling / breach-cost calc / board reports) previously had NO
 * auth check at all in index.js — not even resolveAuthV5 was called, so any
 * anonymous caller reached the handler. Now gated to PRO/ENTERPRISE/MSSP
 * tier or a real platform admin, matching the sibling executiveRiskHandlers.js
 * routes on the same prefix. */
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';

function genericEnv() {
  return {
    DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
          async run() { return { success: true }; },
        };
      },
    },
    KV: { get: async () => null, put: async () => {}, delete: async () => {} },
    SECURITY_HUB_DB: {
      prepare() {
        return {
          bind() { return this; },
          async first() { return null; },
          async all() { return { results: [] }; },
          async run() { return { success: true }; },
        };
      },
    },
    SECURITY_HUB_KV: { get: async () => null, put: async () => {}, delete: async () => {} },
  };
}

function ctxStub() {
  return { waitUntil: (p) => { Promise.resolve(p).catch(() => {}); } };
}

describe('GET /api/executive/* catch-all (executiveCommandCenter.js) — now requires real access', () => {
  it('an anonymous caller is rejected, not served the FAIR risk model data', async () => {
    const req = new Request('https://x/api/executive/fair-risk-model');
    const res = await worker.fetch(req, genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('a FREE-tier caller is rejected', async () => {
    const req = new Request('https://x/api/executive/board-view', { headers: { 'x-api-key': 'cdb_not_a_real_key' } });
    const res = await worker.fetch(req, genericEnv(), ctxStub());
    expect(res.status).toBe(403);
  });

  it('the ADMIN_KEY bypass is admitted', async () => {
    const env = { ...genericEnv(), ADMIN_KEY: 'test-admin-key' };
    const req = new Request('https://x/api/executive/roi-comparison', { headers: { 'x-api-key': 'test-admin-key' } });
    const res = await worker.fetch(req, env, ctxStub());
    expect(res.status).not.toBe(403);
  });
});
