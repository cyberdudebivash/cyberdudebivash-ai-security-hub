/* Phase VII regression — enterprise customer journey locks.
 *
 * Findings from executing real customer journeys against a lab runtime of the
 * deployed build (2026-07-04):
 *   1. A domain that did not resolve returned grade "A" / risk "LOW" — the
 *      DNSBL feed score came back non-numeric, NaN-poisoned the risk total,
 *      and every `>= boundary` comparison failed downward to the best grade.
 *      False assurance for typo'd/internal domains.
 *   2. The sync scan handler carried a near-identical inline copy (v4.0.0) of
 *      buildRealResult (v5.0.0) — two builders, one business truth.
 *   3. A signup that failed AFTER the user INSERT stranded a half-created
 *      account; the customer's retry got "Email already registered".
 *   4. /api self-docs said version 10.0.0 (health says 40.0.0), omitted the
 *      account-deletion endpoint, and the v1 401 told FREE users to "obtain a
 *      key" for an API their key can never access (PRO+ only).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildRealResult } from '../src/handlers/domain.js';

const here = dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(join(here, rel), 'utf8');

const resolvableDns = {
  resolves: true, ipv4: ['93.184.216.34'], ipv6: [], nameservers: ['a.iana-servers.net'],
  mx: { records: [] }, dnssec: { enabled: false, status: 'MISSING' },
  spf: { present: false, policy: null }, dmarc: { present: false, policy: null, enforcement_level: null },
  dkim: { found: false }, caa: { present: false },
};

describe('unmeasurable domains never receive a fabricated verdict', () => {
  it('resolves:false → explicit unmeasurable result, no grade, no risk level', () => {
    const r = buildRealResult('typo-domain.exmaple', { ...resolvableDns, resolves: false }, null, null);
    expect(r.scan_status).toBe('unmeasurable');
    expect(r.grade).toBeNull();
    expect(r.risk_score).toBeNull();
    expect(r.risk_level).toBe('UNKNOWN');
    expect(r.tls_grade).toBe('NOT_MEASURED');
    expect(r.summary).toMatch(/did not resolve/);
    // Exactly one honest INFO finding — no fabricated per-control CRITICALs.
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].severity).toBe('INFO');
  });

  it('a NaN threat-feed score cannot poison the risk total', () => {
    const r = buildRealResult('example.com', resolvableDns, null, { combined_threat_score: NaN, feeds_total: 7 });
    expect(Number.isFinite(r.risk_score)).toBe(true);
    expect(['A','B','C','D','F']).toContain(r.grade);
    expect(r.summary).not.toMatch(/NaN/);
    // This fixture has everything missing — it must NOT read as low risk.
    expect(r.risk_score).toBeGreaterThanOrEqual(60);
  });

  it('measured domains still get a real verdict', () => {
    const r = buildRealResult('example.com', resolvableDns, { reachable: true, tls_grade: 'STRONG', hsts_present: true }, { combined_threat_score: 0, feeds_total: 7 });
    expect(r.scan_status).toBe('measured');
    expect(Number.isFinite(r.risk_score)).toBe(true);
  });
});

describe('one scan-result builder (no duplicated business logic)', () => {
  it('the sync handler uses buildRealResult — the v4.0.0 inline copy is gone', () => {
    const src = read('../src/handlers/domain.js');
    expect(src).not.toContain("version: '4.0.0'");
    expect(src).not.toContain("engine_version: '4.0.0'");
    expect(src).toContain('buildRealResult(domain, dns, tls, bl, scanId)');
  });

  it('unmeasurable attempts are never cached as the domain result', () => {
    const src = read('../src/handlers/domain.js');
    expect(src).toMatch(/scan_status !== 'unmeasurable'\)\s*await cacheScan/);
  });

  it('unmeasurable scans enter history as UNKNOWN/N-A, never as LOW/A', () => {
    const src = read('../src/handlers/domain.js');
    expect(src).toMatch(/scan_status === 'unmeasurable' \? 'UNKNOWN'/);
    expect(src).toMatch(/scan_status === 'unmeasurable' \? 'N\/A'/);
  });
});

describe('signup is atomic from the customer\'s point of view', () => {
  it('a post-insert failure rolls the account back and says so', () => {
    const src = read('../src/handlers/auth.js');
    expect(src).toContain('ERR_SIGNUP_INCOMPLETE');
    expect(src).toContain("DELETE FROM users WHERE id = ?");
    expect(src).toMatch(/no account was created/i);
  });
});

describe('API self-documentation tells customers the truth', () => {
  it('/api version agrees with the platform version', () => {
    const src = read('../src/index.js');
    const fnStart = src.indexOf('function apiInfoResponse');
    const fn = src.slice(fnStart, fnStart + 600);
    expect(fn).toContain("version: '40.0.0'");
  });

  it('/api lists the account-deletion endpoint (GDPR/DPDP discoverability)', () => {
    const src = read('../src/index.js');
    expect(src).toContain("'DELETE /api/auth/delete-account'");
  });

  it('the v1 401 names the required plan instead of a dead-end key hunt', () => {
    const src = read('../src/index.js');
    expect(src).toMatch(/API v1 requires a valid API key on a PRO or ENTERPRISE plan/);
  });

  it('upgrade pointers target the platform\'s own pricing page', () => {
    expect(read('../src/auth/middleware.js')).toContain("UPGRADE_URL   = 'https://cyberdudebivash.in/#pricing'");
    expect(read('../src/handlers/revenueFeatures.js')).not.toContain('tools.cyberdudebivash.com/#pricing');
  });
});
