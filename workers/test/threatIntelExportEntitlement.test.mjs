/* Threat-intel CSV export entitlement (Journey 4).
 *
 * DEFECT: /api/v1/threat-intel?format=csv gated on `tier === 'ENTERPRISE'`, but
 * getPlanLimits marks PRO (and ENTERPRISE_SOC) with export:true. So a PRO
 * customer — whose plan advertises CSV export — silently received JSON instead
 * of the CSV they paid for, and ENTERPRISE_SOC was denied outright. Fix: gate on
 * the real `limits.export` entitlement.
 */
import { describe, it, expect } from 'vitest';
import { handleV1ThreatIntel } from '../src/handlers/threatIntel.js';

const req = (fmt) => new Request(`https://x/api/v1/threat-intel?format=${fmt}&limit=5`);

describe('threat-intel CSV export honors the export entitlement, not a hardcoded tier', () => {
  it('PRO (export:true) receives a CSV download', async () => {
    const res = await handleV1ThreatIntel(req('csv'), {}, { tier: 'PRO' });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/csv');
    const body = await res.text();
    expect(body.startsWith('id,severity,cvss,title,source')).toBe(true);
  });

  it('ENTERPRISE_SOC (export:true) also receives CSV (was wrongly denied before)', async () => {
    const res = await handleV1ThreatIntel(req('csv'), {}, { tier: 'ENTERPRISE_SOC' });
    expect(res.headers.get('content-type')).toContain('text/csv');
  });

  it('FREE (export:false) is explicitly gated with 403, not silently downgraded to JSON', async () => {
    const res = await handleV1ThreatIntel(req('csv'), {}, { tier: 'FREE' });
    expect(res.status).toBe(403);
  });

  it('JSON remains available to everyone', async () => {
    const res = await handleV1ThreatIntel(req('json'), {}, { tier: 'FREE' });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('json');
  });
});
