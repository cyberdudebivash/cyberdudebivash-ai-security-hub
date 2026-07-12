/* Regression tests — mssp-command-center.html's "Add Partner" form
 * (full-frontend-audit follow-up, Tier 1 item #4; see
 * docs/capability-registry/PROGRAM_BOARD.md session log).
 *
 * submitPartner() posted { company, contact, tier, contract_value, email,
 * notes } to POST /api/mssp/partners. handleAddMsspPartner (msspOps.js)
 * destructures { company, contact_email, ... } and requires both company
 * and contact_email — the frontend's `email` field was never read (wrong
 * name), so contact_email was always empty and every submission 400'd.
 * contact/contract_value/notes were also silently dropped (no matching
 * destructured field at all).
 *
 * Fix: frontend now sends contact_email/contact_name; backend now also
 * accepts contact_name/contract_value/notes and stores them in the
 * pre-existing (previously unused) metadata JSON column rather than
 * dropping them — that column is already SELECTed via `p.*` in
 * handleListMsspPartners, so this is real, retrievable data, not a
 * write-only stub.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { handleAddMsspPartner } from '../src/handlers/msspOps.js';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/mssp-command-center.html'), 'utf8');

function fnBody(name) {
  const start = fe.indexOf(`function ${name}`);
  expect(start, `${name} must exist`).toBeGreaterThan(-1);
  const end = fe.indexOf('\n}', start);
  expect(end, `${name}'s closing "}" must be found`).toBeGreaterThan(-1);
  return fe.slice(start, end);
}

// ── Backend ──────────────────────────────────────────────────────────────
function makeDb() {
  const rows = [];
  return {
    _rows: rows,
    prepare(sql) {
      let b = [];
      return {
        bind(...a) { b = a; return this; },
        async run() {
          if (/INSERT INTO mssp_partners/.test(sql)) {
            const [id, company, contact_email, tier, plan, brand_name, custom_domain,
              primary_color, api_key, margin_pct, metadata] = b;
            rows.push({ id, company, contact_email, tier, plan, brand_name, custom_domain,
              primary_color, api_key, margin_pct, metadata });
            return { success: true };
          }
          return { success: true }; // subscriptions insert — not under test here
        },
        async first() { return null; },
        async all() { return { results: [] }; },
      };
    },
  };
}

describe('handleAddMsspPartner — real required field is contact_email', () => {
  it('still 400s when contact_email is missing (unchanged validation)', async () => {
    const req = new Request('https://x', { method: 'POST', body: JSON.stringify({ company: 'Acme' }) });
    const res = await handleAddMsspPartner(req, { DB: makeDb() });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/contact_email/);
  });

  it('succeeds with company + contact_email, and stores contact_name/contract_value/notes in metadata instead of dropping them', async () => {
    const db = makeDb();
    const req = new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({
        company: 'Acme Corp', contact_email: 'jane@acme.com', contact_name: 'Jane Doe',
        tier: 'reseller', contract_value: 99999, notes: 'Fast-track onboarding',
      }),
    });
    const res = await handleAddMsspPartner(req, { DB: db });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.partner.contact_email).toBe('jane@acme.com');

    expect(db._rows.length).toBe(1);
    const stored = JSON.parse(db._rows[0].metadata);
    expect(stored.contact_name).toBe('Jane Doe');
    expect(stored.contract_value).toBe(99999);
    expect(stored.notes).toBe('Fast-track onboarding');
  });
});

// ── Frontend ─────────────────────────────────────────────────────────────
describe('submitPartner — sends the real required field names', () => {
  it('posts contact_email and contact_name, not the old contact/email names', () => {
    const body = fnBody('submitPartner');
    expect(body).toContain('contact_email: email');
    expect(body).toContain('contact_name: contact');
  });

  it('requires email to be filled before submitting (previously optional client-side despite being backend-required)', () => {
    const body = fnBody('submitPartner');
    expect(body).toMatch(/!company\s*\|\|\s*!contact\s*\|\|\s*!email/);
  });

  it('the Contact Email label is marked required, matching the real backend requirement', () => {
    expect(fe).toContain('Contact Email *');
  });
});
