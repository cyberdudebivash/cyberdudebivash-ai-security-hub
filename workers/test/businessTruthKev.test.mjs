/* Business-truth: ONE canonical KEV definition across every consumer.
 *
 * "Known Exploited Vulnerability" had three conflicting SQL definitions on the
 * threat_intel catalog:
 *   • exploit_status = 'confirmed'  — the ONLY column ingestion populates (1631 live)
 *   • is_kev = 1                    — real column, but NEVER written → always 0
 *   • in_kev = 1                    — column does not exist → query errors → 0
 * So the executive report showed 0 exploited vulns, and the vuln-management /
 * threat-hunting "actively exploited" filters returned nothing, while the
 * platform dashboards showed 1631. This locks the canonical definition and
 * guards every consumer against regressing to the broken columns.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import {
  KEV_PREDICATE, CRITICAL_PREDICATE, RANSOMWARE_PREDICATE, KEV_ORDER,
  kevCount, criticalCount,
} from '../src/lib/businessMetrics.js';

const SRC = resolve(import.meta.dirname, '../src');

function grepCount(pattern) {
  let lines;
  try {
    const out = execFileSync('grep', ['-rIn', '-E', pattern, SRC], { encoding: 'utf8' });
    lines = out.trim() ? out.trim().split('\n') : [];
  } catch (e) {
    if (e.status === 1) return []; // grep: no matches
    throw e;
  }
  // Exclude: the canonical layer's own doc table (intentionally names the rejected
  // patterns), comment lines, and the separately-populated tables that legitimately
  // carry an is_kev column (threat_intel_cache = enrichment cache; threat_predictions
  // = God-mode predictions feature, tracked as a separate residual in the register).
  return lines.filter((l) => {
    const body = l.replace(/^[^:]+:\d+:/, '');            // strip file:line: prefix
    if (/businessMetrics\.js/.test(l)) return false;
    if (/^\s*(\/\/|\*|\/\*)/.test(body)) return false;    // comment line
    if (/threat_intel_cache|threat_predictions/.test(body)) return false;
    return true;
  });
}

describe('canonical KEV predicate', () => {
  it('is exploit_status=\'confirmed\' — the only populated column', () => {
    expect(KEV_PREDICATE).toBe("exploit_status = 'confirmed'");
    expect(CRITICAL_PREDICATE).toBe("severity = 'CRITICAL'");
    expect(RANSOMWARE_PREDICATE).toBe("known_ransomware = 1");
    expect(KEV_ORDER).toContain("exploit_status = 'confirmed'");
  });

  it('kevCount() queries exploit_status and returns a number', async () => {
    let captured = '';
    const db = { prepare(sql) { captured = sql; return { first: async () => 42 }; } };
    const n = await kevCount(db);
    expect(captured).toContain("exploit_status = 'confirmed'");
    expect(captured).not.toMatch(/\bis_kev\b|\bin_kev\b/);
    expect(n).toBe(42);
  });

  it('criticalCount() queries severity=\'CRITICAL\'', async () => {
    let captured = '';
    const db = { prepare(sql) { captured = sql; return { first: async () => 14 }; } };
    expect(await criticalCount(db)).toBe(14);
    expect(captured).toContain("severity = 'CRITICAL'");
  });

  it('count helpers never throw (return 0 on DB failure / null db)', async () => {
    expect(await kevCount(null)).toBe(0);
    expect(await kevCount({ prepare() { throw new Error('D1 down'); } })).toBe(0);
  });
});

describe('repo guard — no consumer uses a broken KEV column on threat_intel', () => {
  it('`in_kev = 1` (non-existent column) appears in NO SQL', () => {
    // JS property access never matches `in_kev = 1`; only a SQL predicate does.
    const hits = grepCount('in_kev\\s*=\\s*1');
    expect(hits, `broken in_kev SQL predicate:\n${hits.join('\n')}`).toEqual([]);
  });

  it('`WHERE in_kev` appears in NO SQL', () => {
    const hits = grepCount('WHERE\\s+in_kev');
    expect(hits, `broken in_kev filter:\n${hits.join('\n')}`).toEqual([]);
  });

  it('raw `is_kev = 1` predicate only survives on threat_intel_cache (a separately-populated table)', () => {
    // is_kev IS populated on threat_intel_cache from external enrichment, so that
    // one is legitimate. It must NOT appear anywhere else (threat_intel proper).
    const hits = grepCount('is_kev\\s*=\\s*1').filter(l => !/threat_intel_cache/.test(l));
    expect(hits, `raw is_kev=1 on non-cache table:\n${hits.join('\n')}`).toEqual([]);
  });

  it('SELECT/SUM of raw is_kev on threat_intel is replaced by a derived CASE alias', () => {
    // No `SUM(CASE WHEN is_kev` (the old v13/status pattern) should remain.
    const hits = grepCount('SUM\\(CASE WHEN is_kev');
    expect(hits, `raw is_kev aggregate:\n${hits.join('\n')}`).toEqual([]);
  });
});
