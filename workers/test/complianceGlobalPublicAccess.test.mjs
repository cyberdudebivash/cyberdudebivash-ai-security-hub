/* CAP-COMP-001 — Global Compliance Packs section was reachable-but-hidden
 * for the exact visitor most likely to buy (docs/capability-registry/domains/
 * compliance-store.json).
 *
 * ROOT CAUSE: the '#compliance-global' section (frontend/index.html) carried
 * data-auth-gate="true" and style="display:none", so cdbApplyGates() only
 * revealed it for authenticated visitors. But the backend it calls
 * (workers/src/services/globalScale.js's handlePurchaseCompliancePack /
 * handleVerifyCompliancePack) enforces no auth at all — purchase only needs
 * an email address. The primary nav link ('🌐 Global Compliance') stays
 * visible to everyone regardless, so a logged-out prospect could see the
 * nav entry but land on a hidden section when they clicked it.
 *
 * FIX: remove data-auth-gate="true" and the display:none default from the
 * section — it now renders for every visitor, matching what the backend and
 * the nav link already treat as public. No backend change; no change to any
 * other gated section (executive-hub, growth-analytics, etc. keep their
 * gates untouched).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fe = readFileSync(resolve(root, '../frontend/index.html'), 'utf8');

function sectionTag(id) {
  const marker = `id="${id}"`;
  const idx = fe.indexOf(marker);
  expect(idx, `expected to find a <section ...${marker}...>`).toBeGreaterThan(-1);
  const tagStart = fe.lastIndexOf('<section', idx);
  const tagEnd = fe.indexOf('>', idx);
  return fe.slice(tagStart, tagEnd + 1);
}

describe('Global Compliance Packs section is public (CAP-COMP-001)', () => {
  it('the compliance-global section carries no auth gate', () => {
    const tag = sectionTag('compliance-global');
    expect(tag).not.toContain('data-auth-gate');
  });

  it('the compliance-global section is not hidden by a default display:none', () => {
    const tag = sectionTag('compliance-global');
    expect(tag).not.toMatch(/display\s*:\s*none/);
  });

  it('the primary nav link to compliance-global still exists and is unauthenticated-visible', () => {
    expect(fe).toContain(`data-section="compliance-global" href="#compliance-global"`);
  });

  it('the purchase flow itself is unchanged (no auth requirement introduced)', () => {
    expect(fe).toContain('window.purchaseCompliancePack = async function');
    expect(fe).toContain('/api/global/compliance-packs/purchase');
  });

  it('other data-auth-gate="true"/"owner" sections on the page are untouched by this fix', () => {
    expect(sectionTag('executive-hub')).toContain('data-auth-gate="true"');
    expect(sectionTag('growth-analytics')).toContain('data-auth-gate="owner"');
  });
});
