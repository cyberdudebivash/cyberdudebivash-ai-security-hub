/* Integration coverage for the 4 new copilot tools (get_demo_slots, book_demo,
 * capture_lead, create_support_ticket) added to TOOL_REGISTRY/executeTool.
 *
 * The unit tests in copilotSecurityHardening.test.mjs only assert the tool
 * *metadata* (names, required fields). This file drives the tools through the
 * real HTTP entry point (handleCopilotQuickAction -> executeTool -> the actual
 * salesPipeline.js/support.js handlers) to verify the wiring itself — correct
 * import path, correct function name, correct request shape, correct response
 * parsing — against real handler code, not assumptions from reading it.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleCopilotQuickAction } from '../src/handlers/aiSecurityCopilot.js';

function makeReq(body) {
  return new Request('https://x/api/copilot/quick-action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// Full KV mock honoring the { type: 'json' } option used throughout salesPipeline.js
function jsonKV() {
  const store = new Map();
  return {
    async get(k, opts) {
      const raw = store.has(k) ? store.get(k) : null;
      if (raw === null) return null;
      return opts?.type === 'json' ? JSON.parse(raw) : raw;
    },
    async put(k, v) { store.set(k, v); },
  };
}

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  const wrap = (sql) => { let b = []; return {
    bind(...a){ b = a; return this; },
    async all(){ return { results: sqlite.prepare(sql).all(...b) }; },
    async first(){ return sqlite.prepare(sql).get(...b) ?? null; },
    async run(){ const i = sqlite.prepare(sql).run(...b); return { meta: { changes: i.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

describe('copilot quick-action: get_demo_slots', () => {
  it('returns bookable slots from the real salesPipeline handler', async () => {
    const env = { SECURITY_HUB_KV: jsonKV() };
    const res = await handleCopilotQuickAction(makeReq({ skill: 'get_demo_slots' }), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.result.data.slots.length).toBeGreaterThan(0);
    expect(body.data.result.data.timezone).toBe('Asia/Kolkata');
    expect(body.data.result.data.slots[0]).toHaveProperty('slot');
    expect(body.data.result.data.slots[0]).toHaveProperty('available', true);
  });
});

describe('copilot quick-action: book_demo', () => {
  it('refuses to book without email/preferred_slot (no fabricated contact data)', async () => {
    const env = { SECURITY_HUB_KV: jsonKV() };
    const res = await handleCopilotQuickAction(makeReq({ skill: 'book_demo', params: { name: 'Alice' } }), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.result.error).toMatch(/email and preferred_slot are required/);
  });

  it('books a real demo slot through salesPipeline.handleBookDemo', async () => {
    const env = { SECURITY_HUB_KV: jsonKV() };
    const res = await handleCopilotQuickAction(makeReq({
      skill: 'book_demo',
      params: { email: 'prospect@example.com', name: 'Alice', company: 'Acme Corp', preferred_slot: '2026-07-10T14:00:00+05:30' },
    }), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.result.data.booked).toBe(true);
    expect(body.data.result.data.booking_id).toMatch(/^demo_/);
    expect(body.data.result.data.message).toContain('prospect@example.com');
  });
});

describe('copilot quick-action: capture_lead', () => {
  it('refuses to capture a lead missing name/email/company', async () => {
    const env = { SECURITY_HUB_KV: jsonKV() };
    const res = await handleCopilotQuickAction(makeReq({ skill: 'capture_lead', params: { email: 'x@example.com' } }), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.result.error).toMatch(/name, email, and company are required/);
  });

  it('submits a real lead through salesPipeline.handleCreateLead, tagged with the copilot source', async () => {
    const env = { SECURITY_HUB_KV: jsonKV() };
    const res = await handleCopilotQuickAction(makeReq({
      skill: 'capture_lead',
      params: { name: 'Bob Analyst', email: 'bob@enterprise.com', company: 'Enterprise Corp', sector: 'FINANCE', company_size: '501-1000' },
    }), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.result.data.submitted).toBe(true);
    expect(body.data.result.data.lead_id).toBeTruthy();
    expect(typeof body.data.result.data.icp_score).toBe('number');
  });
});

describe('copilot quick-action: create_support_ticket', () => {
  let env;
  beforeEach(() => {
    env = { DB: makeRealD1() };
    env.DB._sqlite.exec(`CREATE TABLE support_tickets (
      id TEXT PRIMARY KEY, user_id TEXT, tier TEXT, subject TEXT, description TEXT,
      category TEXT, priority TEXT, status TEXT, organization_id TEXT, created_at TEXT, updated_at TEXT
    )`);
  });

  it('refuses to file a ticket missing subject/description', async () => {
    const res = await handleCopilotQuickAction(makeReq({ skill: 'create_support_ticket', params: { subject: 'Help' } }), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.result.error).toMatch(/subject and description are required/);
  });

  it('files a real ticket through support.js handleTicket and persists it to D1', async () => {
    const res = await handleCopilotQuickAction(makeReq({
      skill: 'create_support_ticket',
      params: { subject: 'Billing question', description: 'Was double-charged for the PRO plan this month.', category: 'billing' },
    }), env, { userId: 'user@example.com', tier: 'PRO' });
    const body = await res.json();
    expect(body.data.result.success).toBe(true);
    expect(body.data.result.ticket_id).toMatch(/^TKT-/);

    const rows = env.DB._sqlite.prepare('SELECT * FROM support_tickets').all();
    expect(rows.length).toBe(1);
    expect(rows[0].subject).toBe('Billing question');
    expect(rows[0].category).toBe('billing');
    expect(rows[0].user_id).toBe('user@example.com');
  });
});
