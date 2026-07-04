/* Phase IV remediation regression — auth-gated (private) report downloads.
 *
 * Release Decision #4 documented the limitation: report download links were
 * ONLY capability URLs (anyone with the exact link can view — fine for the
 * default sharing model, unacceptable for regulated enterprise tenants).
 * This locks the new opt-in mode: POST /api/report/generate with
 * visibility:"private" binds the report to the generating account, and the
 * download endpoint then requires authentication as that owner. The default
 * shareable behavior is unchanged. */
import { describe, it, expect } from 'vitest';
import { handleReportGenerate, handleReportDownload } from '../src/handlers/report.js';

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, String(value)); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
    _store: store,
  };
}

const SCAN = {
  module: 'domain_scanner',
  target: 'acme-corp.com',
  risk_score: 62,
  risk_level: 'HIGH',
  grade: 'D',
  findings: [
    { id: 'DOM-001', title: 'Missing DNSSEC', severity: 'HIGH', description: 'DNSSEC not configured.', recommendation: 'Enable DNSSEC.' },
  ],
};

const OWNER    = { authenticated: true, user_id: 'u_owner', tier: 'PRO', identity: 'user:u_owner' };
const STRANGER = { authenticated: true, user_id: 'u_other', tier: 'PRO', identity: 'user:u_other' };
const ANON     = { authenticated: true, user_id: null, tier: 'FREE', identity: 'ip:203.0.113.7' }; // IP-fallback pseudo-auth

function genReq(body) {
  return new Request('https://cyberdudebivash.in/api/report/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
const dlReq = (token) => new Request(`https://cyberdudebivash.in/api/report/${token}`);

async function generate(env, authCtx, extra = {}) {
  const res = await handleReportGenerate(genReq({ scan_result: SCAN, ...extra }), env, authCtx);
  return { res, body: await res.json() };
}

describe('private report generation', () => {
  it('binds the report to the owner and reports visibility:"private"', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { res, body } = await generate(env, OWNER, { visibility: 'private' });
    expect(res.status).toBe(201);
    expect(body.visibility).toBe('private');
    expect(body.report.access).toEqual({ private: true, owner_id: 'u_owner' });
  });

  it('rejects private generation from the anonymous IP-fallback tier (401)', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { res } = await generate(env, ANON, { visibility: 'private' });
    expect(res.status).toBe(401);
  });

  it('default generation stays shareable (no access binding)', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { res, body } = await generate(env, OWNER);
    expect(res.status).toBe(201);
    expect(body.visibility).toBe('shareable');
    expect(body.report.access).toBeUndefined();
  });
});

describe('private report download enforcement', () => {
  it('401 for unauthenticated, 403 for another account, 200 for the owner', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { body } = await generate(env, OWNER, { visibility: 'private' });
    const token = body.download_token;
    expect(token).toBeTruthy();

    const anonRes = await handleReportDownload(dlReq(token), env, ANON);
    expect(anonRes.status).toBe(401);

    const strangerRes = await handleReportDownload(dlReq(token), env, STRANGER);
    expect(strangerRes.status).toBe(403);

    const ownerRes = await handleReportDownload(dlReq(token), env, OWNER);
    expect(ownerRes.status).toBe(200);
  });

  it('default (shareable) reports still download without authentication', async () => {
    const env = { SECURITY_HUB_KV: makeKV() };
    const { body } = await generate(env, OWNER);
    const res = await handleReportDownload(dlReq(body.download_token), env, ANON);
    expect(res.status).toBe(200);
  });
});
