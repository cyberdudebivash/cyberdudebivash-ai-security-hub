/* Phase 6 (Customer Lifecycle Completion Program) — Email Drip Engine.
 *
 * DRIP_SEQUENCES.enterprise (workers/src/services/emailEngine.js) declares a
 * 5-touch cadence (steps: [0,1,3,5,7]) and growth.js:86 really enrolls every
 * scan-detected enterprise-domain lead into it. But the legacy dispatch
 * switch in runDripAutomation() — shared with 'welcome'/'trial_expiry' —
 * only ever implemented 4 templates (templateDay0-3). Step index 4 fell
 * through to the `default` branch, which silently advanced past it and
 * marked the row 'completed' without ever calling sendEmail(). Confirmed
 * via templateDay3's own subject line ("This is the last email in your
 * free trial sequence") that the legacy path was only ever built for 4
 * touches, while DELAY_MAP.enterprise (already 5 entries long) and
 * DRIP_SEQUENCES.enterprise.steps (also 5 entries) both expected a 5th.
 *
 * This file proves the fix: step index 4 of the 'enterprise' sequence now
 * sends templateEnterpriseLeadDay7 and the row only completes after that
 * real send — verified against a real node:sqlite D1, not a mock that
 * would hide a silently-skipped send.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { runDripAutomation } from '../src/services/emailEngine.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE email_sequences (
    id TEXT PRIMARY KEY, email TEXT NOT NULL, sequence_id TEXT NOT NULL,
    current_step INTEGER DEFAULT 0, status TEXT DEFAULT 'active', meta TEXT DEFAULT '{}',
    enrolled_at TEXT DEFAULT (datetime('now')), next_send_at TEXT, last_sent_at TEXT
  )`);
  sqlite.exec(`CREATE TABLE email_tracking (
    id TEXT PRIMARY KEY, email TEXT NOT NULL, sequence_id TEXT, step INTEGER DEFAULT 0,
    event TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now'))
  )`);
  sqlite.exec(`CREATE TABLE leads (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, domain TEXT,
    source TEXT DEFAULT 'scan', is_enterprise INTEGER DEFAULT 0, plan TEXT DEFAULT 'free',
    lead_score INTEGER DEFAULT 0, funnel_stage TEXT DEFAULT 'visitor'
  )`);
  const wrap = (sql) => { let b = []; return {
    bind(...a) { b = a; return this; },
    async all()   { return { results: sqlite.prepare(sql).all(...b) }; },
    async first() { return sqlite.prepare(sql).get(...b) ?? null; },
    async run()   { const r = sqlite.prepare(sql).run(...b); return { meta: { changes: r.changes } }; },
  }; };
  return { _sqlite: sqlite, prepare: wrap };
}

function pastTimestamp() {
  return new Date(Date.now() - 60000).toISOString().replace('T', ' ').slice(0, 19);
}

describe('runDripAutomation — enterprise sequence step 4 (previously silently dropped)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends the Day-7 enterprise email at step index 4 instead of silently completing', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, name, domain, is_enterprise) VALUES ('lead_1','ent@bigco.test','Enterprise Lead','bigco.test',1)`
    ).run();
    db._sqlite.prepare(
      `INSERT INTO email_sequences (id, email, sequence_id, current_step, status, meta, next_send_at)
       VALUES ('seq_1','ent@bigco.test','enterprise',4,'active','{"scanData":{"domain":"bigco.test","critical":2,"high":3}}',?)`
    ).run(pastTimestamp());

    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: 'resend_1' }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const env = { DB: db, RESEND_API_KEY: 'test-key' };
    const result = await runDripAutomation(env);

    expect(result.sent).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.subject).toContain('bigco.test');
    expect(body.subject.toLowerCase()).toContain('enterprise');

    const row = db._sqlite.prepare(`SELECT * FROM email_sequences WHERE id = 'seq_1'`).get();
    expect(row.current_step).toBe(5);
    expect(row.status).toBe('completed');

    const tracked = db._sqlite.prepare(`SELECT * FROM email_tracking WHERE email = 'ent@bigco.test'`).get();
    expect(tracked).toBeTruthy();
    expect(tracked.event).toBe('sent');
    expect(tracked.step).toBe(4);
  });

  it('welcome sequence never reaches step 4 in practice, so this fix does not change its behavior', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO leads (id, email, name, domain) VALUES ('lead_2','w@acme.test','Welcome Lead','acme.test')`
    ).run();
    db._sqlite.prepare(
      `INSERT INTO email_sequences (id, email, sequence_id, current_step, status, meta, next_send_at)
       VALUES ('seq_2','w@acme.test','welcome',4,'active','{}',?)`
    ).run(pastTimestamp());

    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: 'resend_2' }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const env = { DB: db, RESEND_API_KEY: 'test-key' };
    const result = await runDripAutomation(env);

    // Defensive case only (welcome's real DELAY_MAP/isDone logic already
    // completes it at step 4 before this branch would ever be reached) —
    // confirms 'enterprise'-only gating doesn't accidentally fire for other
    // legacy sequenceIds if a row is ever manually placed at step 4.
    expect(result.sent).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
    const row = db._sqlite.prepare(`SELECT * FROM email_sequences WHERE id = 'seq_2'`).get();
    expect(row.status).toBe('completed');
  });
});
