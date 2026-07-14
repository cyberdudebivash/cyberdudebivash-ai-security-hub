/* Priority 3 — Proposal Authorization (2026-07-14 commercial-integrity audit
 * continuation). PR #239 gated /api/v24/proposals (list) and
 * /api/v24/proposals/:id/send with isAdmin, but a full read of the same
 * "PHASE 3 — PROPOSAL FACTORY" section in v24Handler.js found two sibling
 * routes it missed:
 *
 *   1. POST /api/v24/proposals/generate — no auth check at all. Since
 *      /api/v24/* doesn't require authentication (index.js falls back to
 *      { authenticated: false } rather than rejecting), any anonymous caller
 *      could generate and persist a real enterprise sales proposal, including
 *      a client-chosen custom_price_inr.
 *   2. GET /api/v24/proposals/:id/html — no auth check at all, and the id
 *      it's keyed on (PROP-YYYY-MM-XXXX, where XXXX is only the last 4
 *      base36 digits of Date.now()) is a tiny, enumerable keyspace — any
 *      caller could brute-force another prospect's full proposal HTML
 *      (company name, contact email, pricing, ROI figures).
 *
 * Verified access model before fixing: proposalGenerator.js's independent
 * /api/proposals/* equivalent (handleGenerateProposal, handleGetProposal,
 * etc.) is isOwner-gated end to end, and docs/capability-registry/domains/
 * sales-crm.json documents this whole proposal subsystem as an internal
 * staff tool by design (proposals go out to prospects via email/DocuSign,
 * never through an in-app unauthenticated view). So the fix applies the same
 * isAdmin gate already used on this file's own sibling routes — not a new
 * capability-token scheme. */
import { describe, it, expect } from 'vitest';
import { handleV24 } from '../src/handlers/v24Handler.js';

function fakeD1(seedRows = {}) {
  const noop = { async all() { return { results: [] }; }, async first() { return null; }, async run() { return { meta: { changes: 0 } }; } };
  return {
    prepare(sql) {
      let bound = [];
      return {
        bind(...a) { bound = a; return this; },
        async first() {
          if (/SELECT html_content, company, type FROM proposals WHERE id=/.test(sql)) {
            return seedRows[bound[0]] || null;
          }
          return null;
        },
        async all() { return { results: [] }; },
        async run() { return { meta: { changes: 0 } }; },
      };
    },
  };
}

const ANON       = { authenticated: false };
const FREE_USER  = { authenticated: true, userId: 'u1', tier: 'FREE' };
const ADMIN      = { authenticated: true, userId: 'admin', isAdmin: true };

function req(body) {
  return new Request('https://x/v24', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) });
}
function getReq() {
  return new Request('https://x/v24', { method: 'GET' });
}

describe('POST /api/v24/proposals/generate — requires isAdmin (was: no auth check at all)', () => {
  it('an anonymous caller is rejected', async () => {
    const res = await handleV24(
      req({ company: 'Acme Corp', contact_email: 'buyer@acme.test', custom_price_inr: 1 }),
      { DB: fakeD1() }, ANON, '/api/v24/proposals/generate', 'POST'
    );
    expect(res.status).toBe(403);
  });

  it('a regular authenticated customer is rejected', async () => {
    const res = await handleV24(
      req({ company: 'Acme Corp', contact_email: 'buyer@acme.test' }),
      { DB: fakeD1() }, FREE_USER, '/api/v24/proposals/generate', 'POST'
    );
    expect(res.status).toBe(403);
  });

  it('admin is admitted and a proposal is generated', async () => {
    const res = await handleV24(
      req({ company: 'Acme Corp', contact_email: 'buyer@acme.test' }),
      { DB: fakeD1() }, ADMIN, '/api/v24/proposals/generate', 'POST'
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.proposal_id).toBeTruthy();
  });
});

describe('GET /api/v24/proposals/:id/html — requires isAdmin (was: no auth check, enumerable id)', () => {
  const rows = { prop1: { html_content: '<html>Acme Corp Proposal</html>', company: 'Acme Corp', type: 'enterprise' } };

  it('an anonymous caller is rejected — cannot read any proposal HTML by guessing the id', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1(rows) }, ANON, '/api/v24/proposals/prop1/html', 'GET');
    expect(res.status).toBe(403);
  });

  it('a regular authenticated customer is rejected', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1(rows) }, FREE_USER, '/api/v24/proposals/prop1/html', 'GET');
    expect(res.status).toBe(403);
  });

  it('admin can fetch the proposal HTML', async () => {
    const res = await handleV24(getReq(), { DB: fakeD1(rows) }, ADMIN, '/api/v24/proposals/prop1/html', 'GET');
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('Acme Corp Proposal');
  });
});
