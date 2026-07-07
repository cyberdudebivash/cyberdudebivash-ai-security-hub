/* Regression test — buildProposalDocument() (the sales proposal generator
 * handed to real prospective customers via handleGenerateProposal) had two
 * separate bugs:
 *
 * 1. It referenced a bare `env` identifier that was never a parameter or in
 *    scope — handleGenerateProposal called it without passing env, so EVERY
 *    call threw `ReferenceError: env is not defined`. The entire proposal-
 *    generation feature was broken. Fixed by adding env as a real parameter.
 *
 * 2. It claimed "SOC 2 Type II (in progress)" and "ISO 27001 (in progress)" —
 *    false: no certification process has actually started, and
 *    trustCenter.js's own certifications list is honestly empty. It also
 *    asserted "India (Cloudflare India PoP)" data residency with no
 *    infrastructure config (wrangler.toml has no D1 jurisdiction/region
 *    binding) to back it, while two other files asserted two different
 *    regions for the same platform. Both are now the same honest, disclosed
 *    answer everywhere. */
import { describe, it, expect } from 'vitest';
import { buildProposalDocument } from '../src/handlers/proposalGenerator.js';

describe('buildProposalDocument — no fabricated certification or residency claims', () => {
  const lead = { id: 'lead_1', company_name: 'Acme Corp', contact_name: 'Jane', contact_email: 'jane@acme.com' };

  it('does not throw ReferenceError: env is not defined', () => {
    expect(() => buildProposalDocument(lead, 'ENTERPRISE_SHIELD', {}, {})).not.toThrow();
  });

  it('does not claim SOC 2 / ISO 27001 "in progress"', () => {
    const doc = buildProposalDocument(lead, 'ENTERPRISE_SHIELD', {}, {});
    const compliance = doc.sla.security_compliance.join(' ');
    expect(compliance).not.toMatch(/SOC ?2.*in progress/i);
    expect(compliance).not.toMatch(/ISO ?27001.*in progress/i);
  });

  it('data_residency matches the platform-wide honest disclosure, not a specific unconfigured region', () => {
    const doc = buildProposalDocument(lead, 'ENTERPRISE_SHIELD', {}, {});
    expect(doc.sla.data_residency).toMatch(/no dedicated regional jurisdiction pinning configured/i);
    expect(doc.sla.data_residency).not.toBe('India (Cloudflare India PoP)');
  });
});
