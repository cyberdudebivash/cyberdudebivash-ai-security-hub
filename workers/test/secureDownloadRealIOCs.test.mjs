/* Regression test — the SENTINEL APEX™ marketplace intelligence report (paid
 * via marketplace_orders, e.g. "Critical CVE Intelligence Report") rendered a
 * hardcoded IOC Feed table of entirely fabricated indicators (fake IPs,
 * domains, and file hashes attributed to real APT group names, stamped with
 * "Last Seen: <today>" implying live discovery) on every single report,
 * regardless of what the live cti_iocs database actually contained.
 *
 * Proves: the report now pulls real indicators from cti_iocs (joined to
 * cti_actors for attribution) when present, and honestly discloses "no
 * active indicators cataloged" instead of fabricating a fake sample when
 * the table is empty. */
import { describe, it, expect } from 'vitest';
import { handleSecureDownload } from '../src/handlers/secureDownload.js';

function makeDB({ iocRows = [] } = {}) {
  return {
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async first() {
          if (/FROM marketplace_orders/.test(sql)) {
            return { id: bound[0], product_id: 'rpt-cve-critical-2026', status: 'paid', user_id: bound[1] };
          }
          if (/COUNT\(\*\) as total, MAX/.test(sql)) return { total: 0, max_cvss: 0 };
          return null;
        },
        async all() {
          if (/FROM cti_iocs/.test(sql)) return { results: iocRows };
          if (/FROM threat_intel/.test(sql)) return { results: [] };
          return { results: [] };
        },
        async run() { return { success: true }; },
      };
      return stmt;
    },
  };
}

function makeKV() {
  const store = new Map();
  return {
    async put(key, value) { store.set(key, value); },
    async get(key) { return store.has(key) ? store.get(key) : null; },
  };
}

async function generateAndDownload(env, authCtx = { userId: 'u_1', authenticated: true }) {
  const genReq = new Request('https://x/api/report/generate/order_abc', { method: 'POST' });
  const genRes = await handleSecureDownload(genReq, env, authCtx, '/api/report/generate/order_abc', 'POST');
  expect(genRes.status).toBe(200);
  const { token } = await genRes.json();

  const dlReq = new Request(`https://x/api/download/${token}`);
  const dlRes = await handleSecureDownload(dlReq, env, authCtx, `/api/download/${token}`, 'GET');
  expect(dlRes.status).toBe(200);
  return dlRes.text();
}

describe('SENTINEL APEX marketplace report — IOC feed honesty', () => {
  it('renders real indicators from cti_iocs instead of the old fabricated sample', async () => {
    const env = {
      DB: makeDB({
        iocRows: [
          { ioc_type: 'IP', value: '203.0.113.55', severity: 'HIGH', confidence: 82, last_seen: '2026-06-30T00:00:00.000Z', actor_name: 'Test Actor Group' },
        ],
      }),
      SECURITY_HUB_KV: makeKV(),
    };
    const html = await generateAndDownload(env);
    expect(html).toContain('203.0.113.55');
    expect(html).toContain('Test Actor Group');
    // The old hardcoded fake indicators must be gone
    expect(html).not.toContain('185.220.101.47');
    expect(html).not.toContain('update-secure-cdn.net');
    expect(html).not.toContain('a3f2e1');
  });

  it('honestly discloses no cataloged indicators instead of fabricating a sample when cti_iocs is empty', async () => {
    const env = { DB: makeDB({ iocRows: [] }), SECURITY_HUB_KV: makeKV() };
    const html = await generateAndDownload(env);
    expect(html).toContain('No active indicators currently cataloged');
    expect(html).not.toContain('185.220.101.47');
    expect(html).not.toContain('update-secure-cdn.net');
  });
});
