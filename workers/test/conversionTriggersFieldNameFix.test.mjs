/* P1 (CAP-CRM-007) — Conversion Trigger & Funnel Tracking: all 6 of the
 * frontend's call sites into workers/src/handlers/conversionTriggers.js sent
 * or read the wrong field name, so the capability was NOT READY end-to-end:
 *
 *  - p4RecordBehaviorEvent() sent `event_type`/`user_id`; handleRecordEvent
 *    reads `event`/`session_id` — every call 400'd (MISSING_EVENT), always.
 *  - p4LoadTriggers() queried `?user_id=` and read `d.triggers`/`t.trigger_id`/
 *    `t.cta_text`; the real contract is `?session_id=` and
 *    `d.active_triggers`/`t.id`/`t.cta` — the trigger list always rendered
 *    "No active triggers.", regardless of real behavior.
 *  - p4ShowTriggers() was unreachable dead code (its only caller read a
 *    `triggers` field handleRecordEvent's response never had) and, even if
 *    reached, read `feature_name`/`required_plan`/`roi_message` off a
 *    trigger object — none of which exist on a real TRIGGERS record. Removed.
 *  - p4DismissTrigger() sent `user_id`; handleDismissTrigger reads
 *    `session_id` — dismissals were recorded under the literal string
 *    'anonymous' for every signed-out visitor, never a real per-visitor key.
 *  - p4CheckPaywall() queried `?feature_id=`; handleGetPaywall requires
 *    `?feature=` and 400s without it (MISSING_FEATURE) — and since a 400 has
 *    no `gated` field, the gate read that as falsy and called onAllowed()
 *    unconditionally: **the paywall failed OPEN for every feature, on every
 *    plan, always.** Also read nonexistent `feature_name`/`roi_message`/
 *    `upsell_trigger` fields (real shape: `d.feature`/`d.trigger.description`,
 *    no upsell_trigger at all).
 *  - p4LoadFunnel() read `d.funnel` and a fabricated {total_sessions,
 *    signups,scans,upgrades,enterprise,revenue_inr,cta_impressions,
 *    cta_clicks} shape; handleGetFunnel actually returns `d.funnel_stages`
 *    (6 real stages: Visitors/Ran a scan/Used AI/Viewed pricing/Clicked
 *    upgrade/Converted, each {stage,count,pct_of_prev}) with no signups or
 *    revenue concept at all — the funnel visualization showed "No funnel
 *    data yet." forever.
 *
 * FIX: frontend/index.html's 6 call sites now send/read the real field
 * names throughout; p4LoadFunnel() renders the real 6-stage funnel_stages
 * array; #p4-f-visitors is deliberately left to the already-correct
 * loadVisitorStats() rather than being overwritten with a near-always-zero
 * session_start count (production code never fires that event). This is a
 * frontend-only change — zero backend modifications — so these tests lock
 * both the backend's real contract (guarding against the same class of
 * drift recurring) and the frontend's corrected field names/shapes.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  handleRecordEvent, handleGetTriggers, handleGetPaywall, handleDismissTrigger, handleGetFunnel,
} from '../src/handlers/conversionTriggers.js';

function makeKV() {
  const store = new Map();
  return {
    async get(key, opts) {
      if (!store.has(key)) return null;
      const v = store.get(key);
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, String(value)); },
  };
}
function getReq(url) { return new Request(url); }
function postReq(url, body) { return new Request(url, { method: 'POST', body: JSON.stringify(body) }); }

describe('CAP-CRM-007 backend contract — workers/src/handlers/conversionTriggers.js (guards against re-drifting)', () => {
  describe('handleRecordEvent — POST /api/conversion/event', () => {
    it('requires `event`, not `event_type` — 400 MISSING_EVENT without it', async () => {
      const res = await handleRecordEvent(postReq('https://x', { event_type: 'scan_completed', session_id: 's1' }), { SECURITY_HUB_KV: makeKV() }, {});
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.code).toBe('MISSING_EVENT');
      expect(body.data).toBeNull();
    });

    it('accepts a real `event` + `session_id` body and persists behavior in KV under the session key', async () => {
      const kv = makeKV();
      const res = await handleRecordEvent(postReq('https://x', { event: 'scan_completed', session_id: 'visitor-42' }), { SECURITY_HUB_KV: kv }, {});
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toMatchObject({ recorded: true, event: 'scan_completed', new_value: 1 });
      const stored = JSON.parse(await kv.get('conv:behavior:visitor-42'));
      expect(stored.scan_completed).toBe(1);
    });

    it('response never carries a `triggers` field — record-event is fire-and-forget by design', async () => {
      const res = await handleRecordEvent(postReq('https://x', { event: 'scan_completed', session_id: 's1' }), { SECURITY_HUB_KV: makeKV() }, {});
      const body = await res.json();
      expect(body.data.triggers).toBeUndefined();
    });

    it('an authenticated userId takes priority over a client-supplied session_id', async () => {
      const kv = makeKV();
      await handleRecordEvent(postReq('https://x', { event: 'scan_completed', session_id: 'anon-session' }), { SECURITY_HUB_KV: kv }, { userId: 'real-user-9' });
      expect(await kv.get('conv:behavior:real-user-9')).not.toBeNull();
      expect(await kv.get('conv:behavior:anon-session')).toBeNull();
    });
  });

  describe('handleGetTriggers — GET /api/conversion/triggers', () => {
    it('reads `session_id` from the query string, not `user_id`, and returns `active_triggers`', async () => {
      const kv = makeKV();
      await kv.put('conv:behavior:visitor-7', JSON.stringify({ scans_today: 5 }));
      const res = await handleGetTriggers(getReq('https://x/api/conversion/triggers?session_id=visitor-7'), { SECURITY_HUB_KV: kv }, {});
      const body = await res.json();
      expect(body.data.triggers).toBeUndefined();
      expect(body.data.active_triggers.length).toBeGreaterThan(0);
    });

    it('each active trigger carries real TRIGGERS record fields (id/title/cta/urgency), not trigger_id/cta_text', async () => {
      const kv = makeKV();
      await kv.put('conv:behavior:visitor-8', JSON.stringify({ scans_today: 5 }));
      const res = await handleGetTriggers(getReq('https://x/api/conversion/triggers?session_id=visitor-8'), { SECURITY_HUB_KV: kv }, {});
      const body = await res.json();
      const t = body.data.active_triggers[0];
      expect(t.id).toBe('SCAN_LIMIT');
      expect(t).toHaveProperty('cta');
      expect(t).toHaveProperty('title');
      expect(t.trigger_id).toBeUndefined();
      expect(t.cta_text).toBeUndefined();
    });

    it('a dismissed trigger no longer appears in active_triggers for that same session', async () => {
      const kv = makeKV();
      await kv.put('conv:behavior:visitor-9', JSON.stringify({ scans_today: 5 }));
      const before = await (await handleGetTriggers(getReq('https://x/api/conversion/triggers?session_id=visitor-9'), { SECURITY_HUB_KV: kv }, {})).json();
      const firstId = before.data.active_triggers[0].id;
      await handleDismissTrigger(postReq('https://x', { trigger_id: firstId, session_id: 'visitor-9' }), { SECURITY_HUB_KV: kv }, {});
      const after = await (await handleGetTriggers(getReq('https://x/api/conversion/triggers?session_id=visitor-9'), { SECURITY_HUB_KV: kv }, {})).json();
      expect(after.data.active_triggers.map(t => t.id)).not.toContain(firstId);
    });
  });

  describe('handleGetPaywall — GET /api/conversion/paywall', () => {
    it('requires `feature`, not `feature_id` — 400s MISSING_FEATURE without it (this is the fail-open root cause)', async () => {
      const res = await handleGetPaywall(getReq('https://x/api/conversion/paywall?feature_id=autonomous-soc'), {}, {});
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.code).toBe('MISSING_FEATURE');
      expect(body.data).toBeNull();
      expect(body.data?.gated).toBeUndefined();
    });

    it('a FREE-plan caller is gated on a PRO-required feature, with the real response shape', async () => {
      const res = await handleGetPaywall(getReq('https://x/api/conversion/paywall?feature=autonomous-soc'), {}, { tier: 'FREE' });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.gated).toBe(true);
      expect(body.data.feature).toBe('Autonomous SOC Mode');
      expect(body.data.required_plan).toBe('PRO');
      expect(body.data.trigger).toHaveProperty('description');
      expect(body.data.roi_message).toBeUndefined();
      expect(body.data.upsell_trigger).toBeUndefined();
      expect(body.data.feature_name).toBeUndefined();
    });

    it('an ENTERPRISE-plan caller is not gated on the same feature', async () => {
      const res = await handleGetPaywall(getReq('https://x/api/conversion/paywall?feature=autonomous-soc'), {}, { tier: 'ENTERPRISE' });
      const body = await res.json();
      expect(body.data.gated).toBe(false);
    });
  });

  describe('handleGetFunnel — GET /api/conversion/funnel', () => {
    it('rejects an unauthenticated caller', async () => {
      const res = await handleGetFunnel(getReq('https://x'), { SECURITY_HUB_KV: makeKV() }, {});
      expect(res.status).toBe(401);
    });

    it('returns `funnel_stages` (not `funnel`) — 6 real stages, no signups/revenue/CTA-impression fields', async () => {
      const kv = makeKV();
      await kv.put('conv:funnel_stats', JSON.stringify({
        session_start: 100, scan_initiated: 40, ai_query: 20, pricing_view: 15, upgrade_click: 8, plan_purchased: 3,
      }));
      const res = await handleGetFunnel(getReq('https://x'), { SECURITY_HUB_KV: kv }, { authenticated: true, userId: 'owner-1' });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.funnel).toBeUndefined();
      expect(body.data.funnel_stages).toHaveLength(6);
      expect(body.data.funnel_stages.map(s => s.stage)).toEqual([
        'Visitors', 'Ran a scan', 'Used AI', 'Viewed pricing', 'Clicked upgrade', 'Converted',
      ]);
      const converted = body.data.funnel_stages.find(s => s.stage === 'Converted');
      expect(converted.count).toBe(3);
      expect(body.data.signups).toBeUndefined();
      expect(body.data.revenue_inr).toBeUndefined();
      expect(body.data.cta_impressions).toBeUndefined();
    });
  });
});

const repoRoot = resolve(import.meta.dirname, '..', '..');
const html = readFileSync(resolve(repoRoot, 'frontend/index.html'), 'utf8');

function fnBody(name, windowSize = 1600) {
  let start = html.indexOf(`function ${name}(`);
  if (start === -1) start = html.indexOf(`${name} = function(`);
  if (start === -1) return '';
  return html.slice(start, start + windowSize);
}

describe('CAP-CRM-007 frontend wiring — frontend/index.html now matches the real backend contract', () => {
  it('p4RecordBehaviorEvent() sends event/session_id, not event_type/user_id', () => {
    const body = fnBody('p4RecordBehaviorEvent', 600);
    expect(body).not.toBe('');
    expect(body).toMatch(/session_id:\s*sessionId/);
    expect(body).toMatch(/event:\s*eventType/);
    expect(body).not.toMatch(/event_type:\s*eventType/);
    expect(body).not.toMatch(/user_id:\s*sessionId/);
  });

  it('p4LoadTriggers() queries session_id and reads active_triggers with id/cta fields', () => {
    const body = fnBody('p4LoadTriggers', 1600);
    expect(body).not.toBe('');
    expect(body).toContain('?session_id=');
    expect(body).toContain('d.active_triggers');
    expect(body).toContain('t.id');
    expect(body).toContain('t.cta');
    expect(body).not.toContain('d.triggers');
    expect(body).not.toContain('t.trigger_id');
    expect(body).not.toContain('t.cta_text');
    expect(body).not.toContain('?user_id=');
  });

  it('p4ShowTriggers no longer exists (was unreachable dead code with its own internal field-shape bugs)', () => {
    expect(html).not.toContain('function p4ShowTriggers');
    expect(html).not.toContain('p4ShowTriggers(');
  });

  it('p4DismissTrigger() sends session_id, not user_id', () => {
    const body = fnBody('p4DismissTrigger', 400);
    expect(body).not.toBe('');
    expect(body).toMatch(/session_id:\s*sessionId/);
    expect(body).not.toMatch(/user_id:\s*sessionId/);
  });

  it('p4CheckPaywall() queries `feature`, not `feature_id`, and reads the real gated-response shape', () => {
    const body = fnBody('p4CheckPaywall', 900);
    expect(body).not.toBe('');
    expect(body).toContain('paywall?feature=');
    expect(body).not.toContain('paywall?feature_id=');
    expect(body).toContain('d.feature ||');
    expect(body).toContain('trig.description');
    expect(body).not.toContain('d.roi_message');
    expect(body).not.toContain('d.upsell_trigger');
    expect(body).not.toContain('d.feature_name');
  });

  it('p4LoadFunnel() reads funnel_stages with stage/count/pct_of_prev, not a fabricated funnel object', () => {
    const body = fnBody('p4LoadFunnel', 2600);
    expect(body).not.toBe('');
    expect(body).toContain('d.funnel_stages');
    expect(body).toContain('s.stage');
    expect(body).toContain('s.pct_of_prev');
    expect(body).not.toContain('d.funnel.');
    expect(body).not.toContain('f.total_sessions');
    expect(body).not.toContain('f.signups');
    expect(body).not.toContain('f.revenue_inr');
    expect(body).not.toContain('f.cta_impressions');
  });

  it('p4LoadFunnel() no longer overwrites #p4-f-visitors (left to the already-correct loadVisitorStats())', () => {
    const body = fnBody('p4LoadFunnel', 2600);
    expect(body).not.toContain("'p4-f-visitors'");
  });

  it('#p4-funnel-viz grid now fits 6 real stages instead of 5 fabricated ones', () => {
    expect(html).toContain('id="p4-funnel-viz" style="display:grid;grid-template-columns:repeat(6,1fr)');
  });
});
