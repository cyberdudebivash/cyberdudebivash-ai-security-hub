// CAP-NOTIF-003 (2026-07-15) — developerPortal.js's webhook routes were
// retired, not just fixed. This file used to hold 13 tests proving the
// auth/tenant-isolation/SSRF fixes made on 2026-07-12 (see git history for
// the full account) worked correctly. That security work was real and
// valid, but a deeper comparison against the sibling implementation
// (enterpriseAutomation.js, /api/auto/webhooks*) found this system had:
// zero frontend callers ever, no real event-dispatch function (only a
// manual test-ping), no delivery-log table, and its own catalog promised
// HMAC signing that the code never actually sent. The sibling system has
// live customer usage and (after a companion fix) working signing,
// update/logs routes, and populated delivery logs — so it was kept as the
// one authoritative webhook implementation, and this one was removed
// entirely rather than migrated to, per the owner's explicit decision.
// See docs/capability-registry/PROGRAM_BOARD.md for the full comparison.
//
// These tests now prove the retirement itself: the 5 old routes must stay
// gone (404), not silently resurface in a future edit.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { handleDeveloperPortal } from '../src/handlers/developerPortal.js';

function req(url, { method = 'GET' } = {}) {
  return { url, method, json: async () => ({}) };
}

const USER = { authenticated: true, userId: 'u1', user_id: 'u1', org_id: 'org-A' };

describe('developerPortal webhook routes — retired (CAP-NOTIF-003 consolidation)', () => {
  it('GET /api/developer/webhooks/events no longer exists', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/events'), {}, USER);
    expect(res.status).toBe(404);
  });

  it('POST /api/developer/webhooks/register no longer exists', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/register', { method: 'POST' }), {}, USER);
    expect(res.status).toBe(404);
  });

  it('GET /api/developer/webhooks no longer exists', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks'), {}, USER);
    expect(res.status).toBe(404);
  });

  it('DELETE /api/developer/webhooks/:id no longer exists', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/some-id', { method: 'DELETE' }), {}, USER);
    expect(res.status).toBe(404);
  });

  it('POST /api/developer/webhooks/:id/test no longer exists', async () => {
    const res = await handleDeveloperPortal(req('https://x/api/developer/webhooks/some-id/test', { method: 'POST' }), {}, USER);
    expect(res.status).toBe(404);
  });

  it('no dangling references to the removed functions/table remain in the source', () => {
    const src = readFileSync(new URL('../src/handlers/developerPortal.js', import.meta.url), 'utf8');
    expect(src).not.toMatch(/WEBHOOK_EVENTS|registerWebhook|developer_webhooks/);
  });

  it('the API catalog no longer advertises developer-portal webhook endpoints, and points at the real ones', () => {
    const src = readFileSync(new URL('../src/handlers/developerPortal.js', import.meta.url), 'utf8');
    expect(src).not.toContain("path:'/webhooks/register'");
    expect(src).toContain('/api/auto/webhooks');
    expect(src).toContain('/api/webhooks/catalog');
  });

  // Regression guard: GET /api/developer/examples' soc-case-automation entry
  // previously documented its webhook_payload_example with event:
  // 'vuln.critical_found', which has never been a member of
  // enterpriseAutomation.js's real WEBHOOK_EVENTS catalog (the sole
  // surviving webhook system since this file's retirement above) — a
  // developer who built their webhook receiver against this doc's payload
  // shape would silently never match on the real 'threat.critical' events
  // the platform actually sends. Fixed to match; this test reads the real
  // catalog dynamically (not a hardcoded copy) so it stays correct if the
  // catalog ever changes.
  it('the soc-case-automation example\'s webhook_payload_example.event is a real WEBHOOK_EVENTS member', async () => {
    const automationSrc = readFileSync(new URL('../src/handlers/enterpriseAutomation.js', import.meta.url), 'utf8');
    const m = automationSrc.match(/const WEBHOOK_EVENTS = \[([\s\S]*?)\];/);
    expect(m).toBeTruthy();
    const realEvents = [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]);
    expect(realEvents.length).toBeGreaterThan(0);

    const res = await handleDeveloperPortal(req('https://x/api/developer/examples'), {}, USER);
    expect(res.status).toBe(200);
    const body = await res.json();
    const example = body.examples.find(e => e.id === 'soc-case-automation');
    expect(example?.webhook_payload_example?.event).toBeTruthy();
    expect(realEvents).toContain(example.webhook_payload_example.event);
  });
});
