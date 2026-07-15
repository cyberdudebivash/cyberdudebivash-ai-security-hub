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
});
