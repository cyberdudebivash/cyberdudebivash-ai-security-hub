/* Phase IV remediation regression — honesty-of-copy.
 *
 * Live Phase II measurement: the free-tier async scan completes in ~90s end to
 * end, while the homepage and the async-scan API response both promised
 * "< 30 seconds". This platform's differentiator is verified honesty — copy
 * must not outrun measured behavior. Locks:
 *   1. index.html no longer claims sub-30-second scans anywhere;
 *   2. the queue's estimated_eta strings advertise minute-scale times;
 *   3. the /api/intel tier table's STIX flag agrees with the public pricing
 *      matrix (PRO+ stix_export) — the flag previously contradicted pricing. */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const read = (rel) => readFileSync(join(here, rel), 'utf8');

describe('scan-time claims match measured behavior', () => {
  it('index.html carries no sub-30-second scan claim', () => {
    const html = read('../../frontend/index.html');
    expect(html).not.toMatch(/complete in under 30 seconds/i);
    expect(html).not.toMatch(/Results in &lt;30 seconds/i);
    expect(html).not.toMatch(/&lt;30s<\/div>\s*<div class="stat-label">(Avg|Typical) Scan Time/i);
    // The honest replacements are present
    expect(html).toMatch(/within about 2 minutes/i);
    expect(html).toMatch(/~2 min/);
  });

  it('queue estimated_eta advertises minute-scale times, never "< 30s"', () => {
    const src = read('../src/lib/queue.js');
    expect(src).not.toMatch(/'<\s*30s'/);
    expect(src).not.toMatch(/'<\s*10s'/);
    expect(src).not.toMatch(/'<\s*5s'/);
    expect(src).toMatch(/estimated_eta/);
    expect(src).toMatch(/1-2 min/);
  });
});

describe('STIX entitlement copy consistency', () => {
  it('intelAPIHandlers tier flags agree with the sold pricing (PRO+ get STIX)', () => {
    const src = read('../src/handlers/intelAPIHandlers.js');
    // PRO row must declare stix: true — pricing.json advertises PRO stix_export:true.
    const proRow = src.split('\n').find((l) => l.includes("tier === 'PRO'") && l.includes('stix:'));
    expect(proRow).toBeTruthy();
    expect(proRow).toMatch(/stix:\s*true/);
  });
});
