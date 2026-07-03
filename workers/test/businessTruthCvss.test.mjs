/* Business-truth: canonical CVSS column + threat_intel field names.
 *
 * threat_intel carries the score in BOTH `cvss` (written by threatIngestion.js)
 * and `cvss_score` (the canonical, indexed column that 60+ readers query). The
 * ingestion path left cvss_score NULL, so every CVSS-based metric read null and
 * returned 0. storeInD1 now self-heals cvss_score = cvss on each cycle.
 *
 * Also guards the field-name canon: readers must query `cvss_score` (not `cvss`)
 * and `published_at` (not `published_date`, which does not exist on threat_intel
 * and silently errored the whole vulnerability list).
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { storeInD1 } from '../src/services/threatIngestion.js';

const SRC = resolve(import.meta.dirname, '../src');

function grep(pattern, extraArgs = []) {
  try {
    const out = execFileSync('grep', ['-rIn', '-E', ...extraArgs, pattern, SRC], { encoding: 'utf8' });
    return out.trim() ? out.trim().split('\n') : [];
  } catch (e) {
    if (e.status === 1) return [];
    throw e;
  }
}

describe('CVSS self-heal on ingestion', () => {
  it('storeInD1 backfills cvss_score = cvss for out-of-sync rows', async () => {
    const run = [];
    const db = {
      batch: async () => [],
      prepare(sql) {
        return {
          bind() { return this; },
          async run() { run.push(sql.replace(/\s+/g, ' ').trim()); return { meta: {} }; },
          async first() { return null; },
          async all() { return { results: [] }; },
        };
      },
    };
    await storeInD1(db, [{ id: 'CVE-2024-0001', title: 'x', severity: 'CRITICAL', cvss: 9.8, source: 'nvd' }]);
    const heal = run.find(s => /UPDATE threat_intel SET cvss_score = cvss/i.test(s));
    expect(heal, 'ingestion must run the cvss_score self-heal').toBeTruthy();
    expect(heal).toMatch(/WHERE cvss_score IS NULL AND cvss IS NOT NULL/i);

    // cve_id self-heal: the CVE identifier is written to `id`; cve_id must be backfilled.
    const cveHeal = run.find(s => /UPDATE threat_intel SET cve_id = id/i.test(s));
    expect(cveHeal, 'ingestion must run the cve_id self-heal').toBeTruthy();
    expect(cveHeal).toMatch(/id LIKE 'CVE-%'/i);
  });

  it('storeInD1 never throws when the heal step fails (non-fatal)', async () => {
    const db = {
      batch: async () => [],
      prepare(sql) {
        const failHeal = /UPDATE threat_intel SET cvss_score/i.test(sql);
        return {
          bind() { return this; },
          async run() { if (failHeal) throw new Error('heal boom'); return { meta: {} }; },
          async first() { return null; },
          async all() { return { results: [] }; },
        };
      },
    };
    await expect(storeInD1(db, [{ id: 'CVE-2024-0002', title: 'y', severity: 'HIGH', cvss: 7.1, source: 'nvd' }]))
      .resolves.toBeTruthy();
  });
});

describe('threat_intel field-name canon (repo guard)', () => {
  it('no reader selects the non-existent `published_date` column on threat_intel', () => {
    // published_at is canonical (ingestion writes it, 37 readers). published_date
    // does not exist on threat_intel — selecting it errors the whole query.
    // Flag only SQL COLUMN usage of published_date against threat_intel — a bare
    // column reference in a SELECT list / WHERE / ORDER BY. `published_at AS
    // published_date` (an alias that keeps the response field stable) and JS
    // `row.published_date` reads of that alias are correct and excluded.
    const hits = grep('published_date', ['--include=*.js'])
      .filter(l => !/businessTruth|\.test\./.test(l))
      .filter(l => /FROM threat_intel|ORDER BY published_date|WHERE published_date|published_date AS/.test(l))
      .filter(l => !/published_at AS published_date/.test(l));
    expect(hits, `published_date SQL column on threat_intel:\n${hits.join('\n')}`).toEqual([]);
  });
});
