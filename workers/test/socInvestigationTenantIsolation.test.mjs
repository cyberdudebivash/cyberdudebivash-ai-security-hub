/* SOC investigation cross-tenant WRITE isolation (Journey 5).
 *
 * DEFECT (found by driving two tenants live): handleAddNote / handleAddEvidence
 * computed org_id from the caller and INSERTed against the URL's caseId WITHOUT
 * verifying the case belonged to that org. So user B could POST notes/evidence
 * onto user A's case_id — a cross-tenant write (IDOR/BOLA). The read + escalate +
 * resolve handlers already gated on `WHERE org_id = ? → 404`; the two INSERT
 * writers did not. Fix: same ownership gate before the write.
 *
 * Verified against a real SQL engine (node:sqlite) with the real schema.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { handleAddNote, handleAddEvidence } from '../src/handlers/socInvestigations.js';

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

function reqFor(caseId, path, authCtx, bodyObj) {
  const r = new Request(`https://x/api/soc/inv/${caseId}/${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bodyObj),
  });
  r.user = authCtx;
  return r;
}
const alice = { authenticated: true, user_id: 'alice', userId: 'alice', email: 'a@x.com' };
const bob   = { authenticated: true, user_id: 'bob',   userId: 'bob',   email: 'b@x.com' };

describe('SOC investigation writes are tenant-isolated', () => {
  let env;
  beforeEach(() => {
    env = { SECURITY_HUB_DB: makeRealD1() };
    const db = env.SECURITY_HUB_DB._sqlite;
    db.exec(`CREATE TABLE soc_cases (id TEXT PRIMARY KEY, org_id TEXT)`);
    db.exec(`CREATE TABLE soc_notes (id TEXT, case_id TEXT, org_id TEXT, author TEXT, content TEXT, note_type TEXT, is_pinned INTEGER, created_at TEXT, updated_at TEXT)`);
    db.exec(`CREATE TABLE soc_evidence (id TEXT, case_id TEXT, org_id TEXT, evidence_type TEXT, title TEXT, description TEXT, data_json TEXT, file_hash TEXT, file_size_bytes INTEGER, source_system TEXT, added_by TEXT, created_at TEXT)`);
    db.exec(`CREATE TABLE soc_timeline (id TEXT, case_id TEXT, org_id TEXT, event_type TEXT, description TEXT, actor TEXT, old_value TEXT, new_value TEXT, metadata_json TEXT, occurred_at TEXT)`);
    // A case owned by alice's org.
    db.prepare(`INSERT INTO soc_cases (id, org_id) VALUES (?, ?)`).run('case_A', 'user:alice');
  });

  it('blocks a cross-tenant NOTE write (bob → alice case) with 404', async () => {
    const res = await handleAddNote(reqFor('case_A', 'notes', bob, { content: 'malicious inject' }), env);
    expect(res.status).toBe(404);
    const n = env.SECURITY_HUB_DB._sqlite.prepare(`SELECT COUNT(*) c FROM soc_notes`).get();
    expect(n.c).toBe(0); // nothing written
  });

  it('allows the owner (alice) to add a note', async () => {
    const res = await handleAddNote(reqFor('case_A', 'notes', alice, { content: 'legit' }), env);
    expect(res.status).toBe(200);
    expect(env.SECURITY_HUB_DB._sqlite.prepare(`SELECT COUNT(*) c FROM soc_notes`).get().c).toBe(1);
  });

  it('blocks a cross-tenant EVIDENCE write (bob → alice case) with 404', async () => {
    const res = await handleAddEvidence(reqFor('case_A', 'evidence', bob, { title: 'planted', evidence_type: 'ARTIFACT' }), env);
    expect(res.status).toBe(404);
    expect(env.SECURITY_HUB_DB._sqlite.prepare(`SELECT COUNT(*) c FROM soc_evidence`).get().c).toBe(0);
  });

  it('allows the owner (alice) to add evidence', async () => {
    const res = await handleAddEvidence(reqFor('case_A', 'evidence', alice, { title: 'pcap', evidence_type: 'PCAP' }), env);
    expect(res.status).toBe(200);
    expect(env.SECURITY_HUB_DB._sqlite.prepare(`SELECT COUNT(*) c FROM soc_evidence`).get().c).toBe(1);
  });
});
