/* Regression coverage — GET /api/v1/threat-intel (the public, paying-customer
 * API surface) used to ignore the caller's requested `limit`/pagination
 * entirely and always request/report `limits.max_results` from D1. The
 * dashboard-facing GET /api/threat-intel has always correctly capped to
 * min(requested limit, plan max). For the same nominal request, a customer
 * comparing dashboard output against API output saw a different number of
 * records — exactly the "dashboard and API must return identical, exact
 * data" complaint raised by enterprise prospects evaluating both surfaces
 * side-by-side. There was zero test coverage on this handler. */
import { describe, it, expect } from 'vitest';
import { handleV1ThreatIntel } from '../src/handlers/threatIntel.js';

function makeRows(n) {
  return Array.from({ length: n }, (_, i) => ({
    id: `CVE-2026-${1000 + i}`, title: `Test CVE ${i}`, description: 'd',
    severity: 'HIGH', cvss: 7.5, source: 'nvd', published_at: '2026-06-01',
    exploit_status: 'unknown', known_ransomware: 0, tags: '[]', enriched: 0,
  }));
}

function makeEnv(totalRows) {
  const allRows = makeRows(totalRows);
  return {
    SECURITY_HUB_DB: {
      prepare(sql) {
        let bound = [];
        return {
          bind(...a) { bound = a; return this; },
          async first() {
            if (/SELECT COUNT\(\*\) as total/.test(sql)) return { total: allRows.length };
            return null;
          },
          async all() {
            if (/SELECT \* FROM threat_intel/.test(sql)) {
              const limit  = bound[bound.length - 2];
              const offset = bound[bound.length - 1];
              return { results: allRows.slice(offset, offset + limit) };
            }
            return { results: [] };
          },
        };
      },
    },
  };
}

function req(qs) { return new Request('https://x.test/api/v1/threat-intel' + qs); }

describe('handleV1ThreatIntel — dashboard/API consistency', () => {
  it('honors an explicit limit smaller than the plan max (PRO requesting 5)', async () => {
    const env = makeEnv(50);
    const res = await handleV1ThreatIntel(req('?limit=5'), env, { tier: 'PRO' });
    const body = await res.json();
    expect(body.data.entries.length).toBe(5);
    expect(body.data.limit).toBe(5);
  });

  it('caps at the plan max when the caller asks for more than allowed (FREE requesting 50)', async () => {
    const env = makeEnv(50);
    const res = await handleV1ThreatIntel(req('?limit=50'), env, { tier: 'FREE' });
    const body = await res.json();
    expect(body.data.entries.length).toBe(5);  // FREE plan max_results
    expect(body.data.limit).toBe(5);
  });

  it('returns the same entry count as the default (no limit param) for a given plan', async () => {
    const env = makeEnv(50);
    const res = await handleV1ThreatIntel(req(''), env, { tier: 'PRO' });
    const body = await res.json();
    // default pagination limit is 20, PRO max_results is 50 -> effective 20
    expect(body.data.entries.length).toBe(20);
    expect(body.data.limit).toBe(20);
  });

  it('reports total_pages consistent with the effective limit actually used', async () => {
    const env = makeEnv(50);
    const res = await handleV1ThreatIntel(req('?limit=10'), env, { tier: 'ENTERPRISE' });
    const body = await res.json();
    expect(body.data.limit).toBe(10);
    expect(body.data.total_pages).toBe(5); // 50 total / 10 per page
  });
});
