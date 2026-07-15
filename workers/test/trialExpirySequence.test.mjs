/* Phase 6 (Customer Lifecycle Completion Program) — Trial Expiry Nudge.
 *
 * DRIP_SEQUENCES.trial_expiry (workers/src/services/emailEngine.js) has
 * always existed and was reachable via runDripAutomation's dispatch, but
 * nothing anywhere in the codebase ever called
 * enrollInSequence(env, email, 'trial_expiry', ...) — every trialing
 * customer's trial lapsed silently, with no expiry nudge.
 *
 * A second, more subtle defect was found while fixing the first: the
 * legacy dispatch switch trial_expiry shared with 'welcome'/'enterprise'
 * routes steps 0/1 through templateDay0/templateDay1 — generic "here's
 * your vulnerability scan report" copy referencing scanData
 * (domain/risk_score/critical/high), not trial-expiry content at all.
 * Simply wiring enrollment without fixing this would have sent factually
 * wrong emails. Fixed by writing dedicated templateTrialExpiryDay0/Day1
 * content and moving 'trial_expiry' out of the legacy switch into the
 * Phase-4-style getSequenceTemplate() dispatch (the same pattern already
 * used for upgrade_nudge/enterprise_winback/etc.).
 *
 * This file proves both halves: enrollTrialExpiryNudges() finds the right
 * subscriptions (against a real node:sqlite D1, not a permissive mock),
 * and runDripAutomation now sends the new trial-specific copy at steps
 * 0 and 1, not the old scan-report templates.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { enrollTrialExpiryNudges, runDripAutomation } from '../src/services/emailEngine.js';

function makeRealD1() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    user_id TEXT NOT NULL, email TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'FREE', status TEXT NOT NULL DEFAULT 'active',
    trial_ends_at TEXT,
    current_period_end TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
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

function daysFromNow(n) {
  return new Date(Date.now() + n * 86400000).toISOString().replace('T', ' ').slice(0, 19);
}

function pastTimestamp() {
  return new Date(Date.now() - 60000).toISOString().replace('T', ' ').slice(0, 19);
}

describe('enrollTrialExpiryNudges — finds and enrolls expiring trials (previously never called anywhere)', () => {
  it('enrolls a trialing subscription ending within 3 days', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (user_id, email, plan, status, trial_ends_at) VALUES ('u_1','trial@acme.test','PRO','trialing',?)`
    ).run(daysFromNow(2));

    const result = await enrollTrialExpiryNudges({ DB: db });
    expect(result.success).toBe(true);
    expect(result.evaluated).toBe(1);
    expect(result.enrolled).toBe(1);

    const row = db._sqlite.prepare(`SELECT * FROM email_sequences WHERE email = 'trial@acme.test'`).get();
    expect(row).toBeTruthy();
    expect(row.sequence_id).toBe('trial_expiry');
    expect(row.status).toBe('active');
    expect(JSON.parse(row.meta).plan).toBe('PRO');
  });

  it('does not enroll a trial ending more than 3 days out', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (user_id, email, plan, status, trial_ends_at) VALUES ('u_2','future@acme.test','PRO','trialing',?)`
    ).run(daysFromNow(10));

    const result = await enrollTrialExpiryNudges({ DB: db });
    expect(result.evaluated).toBe(0);
    expect(db._sqlite.prepare(`SELECT COUNT(*) as c FROM email_sequences`).get().c).toBe(0);
  });

  it('does not enroll a non-trialing subscription', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (user_id, email, plan, status, trial_ends_at) VALUES ('u_3','active@acme.test','PRO','active',?)`
    ).run(daysFromNow(2));

    const result = await enrollTrialExpiryNudges({ DB: db });
    expect(result.evaluated).toBe(0);
  });

  it('does not double-enroll across repeated cron ticks', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO subscriptions (user_id, email, plan, status, trial_ends_at) VALUES ('u_4','dup@acme.test','STARTER','trialing',?)`
    ).run(daysFromNow(1));

    const first  = await enrollTrialExpiryNudges({ DB: db });
    const second = await enrollTrialExpiryNudges({ DB: db });
    expect(first.enrolled).toBe(1);
    expect(second.evaluated).toBe(1); // still found, still eligible by date
    expect(second.enrolled).toBe(0);  // but not re-enrolled — already active
    expect(db._sqlite.prepare(`SELECT COUNT(*) as c FROM email_sequences WHERE email='dup@acme.test'`).get().c).toBe(1);
  });
});

describe('runDripAutomation — trial_expiry sends real trial content, not the old scan-report templates', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('step 0 sends trial-expiry copy (not templateDay0\'s vulnerability-scan content)', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO email_sequences (id, email, sequence_id, current_step, status, meta, next_send_at)
       VALUES ('seq_1','trial@acme.test','trial_expiry',0,'active','{"plan":"PRO","days_remaining":3}',?)`
    ).run(pastTimestamp());

    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: 'resend_1' }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await runDripAutomation({ DB: db, RESEND_API_KEY: 'test-key' });
    expect(result.sent).toBe(1);

    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.subject.toLowerCase()).toContain('trial');
    expect(body.subject).not.toMatch(/Vulnerabilities Found/); // old templateDay0 subject shape
    expect(body.html).toContain('PRO');
    expect(body.html).not.toContain('your domain'); // templateDay0's scanData fallback text
  });

  it('step 1 sends the final trial-expiry reminder', async () => {
    const db = makeRealD1();
    db._sqlite.prepare(
      `INSERT INTO email_sequences (id, email, sequence_id, current_step, status, meta, next_send_at)
       VALUES ('seq_2','trial2@acme.test','trial_expiry',1,'active','{"plan":"STARTER","days_remaining":1}',?)`
    ).run(pastTimestamp());

    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: 'resend_2' }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await runDripAutomation({ DB: db, RESEND_API_KEY: 'test-key' });
    expect(result.sent).toBe(1);

    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.subject.toLowerCase()).toContain('trial');
    expect(body.html).toContain('STARTER');

    const row = db._sqlite.prepare(`SELECT * FROM email_sequences WHERE id = 'seq_2'`).get();
    expect(row.current_step).toBe(2);
  });
});
