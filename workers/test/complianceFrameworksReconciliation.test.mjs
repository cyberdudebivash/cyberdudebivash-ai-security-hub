/* Compliance-framework-claims reconciliation, 2026-07-11.
 *
 * workers/src/handlers/trustCenter.js's COMPLIANCE_FRAMEWORKS (9 frameworks,
 * a 2-state aligned/partial vocabulary) and workers/src/handlers/
 * enterprisePortalHandlers.js's own independent, hand-written
 * compliance_status.frameworks (7 frameworks, a 3-state Implemented/Aligned/
 * Planning vocabulary) had drifted to directly disagree on GDPR: the first
 * said "partial — not yet formally assessed"; the second said
 * "Aligned — data minimization, consent, deletion rights implemented" — a
 * real, live, enterprise-visible contradiction the moment either surface is
 * compared against the other (both are reachable today: GET /api/trust/
 * compliance and GET /api/trust-center respectively).
 *
 * Investigated against real evidence before reconciling (see
 * docs/capability-registry/PROGRAM_BOARD.md): a real DELETE /api/auth/
 * delete-account erasure mechanism, a real DPA template committing to
 * 72-hour breach notification, and in-flight-only scan-target processing all
 * exist — enough to justify "aligned" in this list's own defined sense (no
 * formal certification claimed), but not enough to justify the stronger,
 * unqualified "Aligned — implemented" the second list asserted. Reconciled
 * to one canonical list (trustCenter.js's COMPLIANCE_FRAMEWORKS, now
 * exported and covering the union of both lists' frameworks);
 * enterprisePortalHandlers.js now derives its response from that list via a
 * display-layer transform instead of maintaining a second copy, making this
 * class of drift structurally impossible to reintroduce by accident.
 */
import { describe, it, expect } from 'vitest';
import { handleTrustCompliance } from '../src/handlers/trustCenter.js';
import { handleTrustCenter } from '../src/handlers/enterprisePortalHandlers.js';

function kvStub(seed = {}) {
  const store = new Map(Object.entries(seed));
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put(k, v) { store.set(k, v); } };
}
function dbStub() {
  return {
    prepare() {
      return {
        bind() { return this; },
        async first() { return { v: 0, cnt: 0 }; },
        async all() { return { results: [] }; },
      };
    },
  };
}

describe('GDPR status is now consistent across both real, reachable routes', () => {
  it('GET /api/trust/compliance and GET /api/trust-center report the SAME GDPR alignment', async () => {
    const complianceRes = await handleTrustCompliance(new Request('https://x/api/trust/compliance'), {});
    const { frameworks } = await complianceRes.json();
    const gdprCanonical = frameworks.find(f => f.framework === 'gdpr');
    expect(gdprCanonical).toBeDefined();
    expect(gdprCanonical.alignment_level).toBe('aligned');

    const env = { SECURITY_HUB_KV: kvStub(), DB: dbStub() };
    const centerRes = await handleTrustCenter(new Request('https://x/api/trust-center'), env, {});
    const centerBody = await centerRes.json();
    const gdprDisplay = centerBody.compliance_status.frameworks.find(f => f.framework === 'GDPR');
    expect(gdprDisplay).toBeDefined();
    // Both surfaces now trace to the same source: 'aligned' -> 'Aligned' display label.
    expect(gdprDisplay.status).toBe('Aligned');
    expect(gdprDisplay.evidence).toBe(gdprCanonical.scope_note);
  });

  it('every framework on GET /api/trust-center traces back to a real COMPLIANCE_FRAMEWORKS entry (no orphaned/independent data)', async () => {
    const complianceRes = await handleTrustCompliance(new Request('https://x/api/trust/compliance'), {});
    const { frameworks: canonical } = await complianceRes.json();
    const canonicalScopeNotes = new Set(canonical.map(f => f.scope_note));

    const env = { SECURITY_HUB_KV: kvStub(), DB: dbStub() };
    const centerRes = await handleTrustCenter(new Request('https://x/api/trust-center'), env, {});
    const { compliance_status } = await centerRes.json();
    expect(compliance_status.frameworks.length).toBe(canonical.length);
    for (const f of compliance_status.frameworks) {
      expect(canonicalScopeNotes.has(f.evidence)).toBe(true);
    }
  });
});

describe('COMPLIANCE_FRAMEWORKS — the reconciled canonical list', () => {
  it('covers the union of both previously-separate lists (12 frameworks)', async () => {
    const res = await handleTrustCompliance(new Request('https://x/api/trust/compliance'), {});
    const { frameworks } = await res.json();
    const ids = frameworks.map(f => f.framework).sort();
    expect(ids).toEqual([
      'ccpa', 'dpdp', 'gdpr', 'hipaa', 'iso27001', 'mitre',
      'nist_ai', 'nist_csf2', 'owasp_llm', 'owasp_top10', 'pcidss', 'soc2',
    ].sort());
  });

  it('never claims formal certification for any framework (no fabricated audit dates or "certified" language)', async () => {
    const res = await handleTrustCompliance(new Request('https://x/api/trust/compliance'), {});
    const { frameworks } = await res.json();
    for (const f of frameworks) {
      expect(['aligned', 'partial']).toContain(f.alignment_level);
      expect(f.scope_note).not.toMatch(/\bcertified\b/i);
      expect(f.scope_note).not.toMatch(/Q[1-4]\s*20\d\d/);
    }
  });
});
