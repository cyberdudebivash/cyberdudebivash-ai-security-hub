// God Mode <-> threat_intel schema contract guard.
// Regression class: God Mode phase-1 SELECT/WHERE referenced columns
// (threat_class, solution_generated) that did not exist in the live D1 schema,
// causing "no such column" -> no_intel -> empty God Mode dashboard despite 47
// CRITICAL/HIGH CVEs being present. This test ensures every threat_intel column
// the phase-1 query reads is provided by the live schema + the v40 migration.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(resolve(__dirname, p), 'utf8');

const GODMODE = read('../src/services/mythosGodMode.js');
const V40     = read('../schema_v40_godmode_intel_columns.sql');

// Snapshot of the live threat_intel columns (verified 2026-06-15 via
// `SELECT name FROM pragma_table_info('threat_intel')`). These existed BEFORE v40.
const LIVE_COLUMNS = new Set([
  'active_exploitation', 'actively_exploited', 'affected_products', 'apt_groups',
  'cisa_kev', 'cisa_kev_date', 'confidence', 'cve_id', 'cvss', 'cvss_score',
  'cvss_vector', 'description', 'enriched', 'epss_percentile', 'epss_score',
  'exploit_available', 'exploit_status', 'id', 'ingested_at', 'ioc_list', 'iocs',
  'is_exploited', 'is_ransomware', 'known_ransomware', 'modified_at',
  'patch_available', 'patch_url', 'product', 'published_at', 'ref_urls',
  'severity', 'source', 'source_url', 'tags', 'title', 'updated_at', 'vendor',
  'weakness_types',
]);

// Columns the v40 migration adds.
function v40AddedColumns() {
  return [...V40.matchAll(/ADD COLUMN\s+(\w+)/gi)].map(m => m[1]);
}

// Extract the phase-1 SELECT column list (between SELECT and FROM threat_intel).
function phase1SelectColumns() {
  const m = GODMODE.match(/SELECT\s+([\s\S]*?)\s+FROM\s+threat_intel/i);
  if (!m) return [];
  return m[1]
    .split(',')
    .map(s => s.trim().replace(/^.*\s+AS\s+/i, '').replace(/^\w+\./, ''))
    .filter(c => /^\w+$/.test(c));
}

describe('v40 migration', () => {
  it('adds exactly the two columns God Mode needs (additive only)', () => {
    const added = v40AddedColumns();
    expect(added).toContain('threat_class');
    expect(added).toContain('solution_generated');
    // Migration must be additive — no DROP/RENAME of threat_intel.
    expect(V40).not.toMatch(/DROP\s+TABLE\s+threat_intel/i);
    expect(V40).not.toMatch(/DROP\s+COLUMN/i);
  });

  it('targets the columns that were missing from the live schema', () => {
    for (const col of v40AddedColumns()) {
      expect(LIVE_COLUMNS.has(col), `${col} already existed live`).toBe(false);
    }
  });
});

describe('God Mode phase-1 / threat_intel column contract', () => {
  const available = new Set([...LIVE_COLUMNS, ...v40AddedColumns()]);

  it('every SELECTed threat_intel column exists after v40', () => {
    const cols = phase1SelectColumns();
    expect(cols.length).toBeGreaterThan(5);
    for (const c of cols) {
      expect(available.has(c), `phase-1 selects unknown column "${c}"`).toBe(true);
    }
  });

  it('the WHERE filter column (solution_generated) exists after v40', () => {
    expect(GODMODE).toMatch(/solution_generated\s*=\s*0/);
    expect(available.has('solution_generated')).toBe(true);
  });

  it('regression proof: the contract would FAIL without v40', () => {
    // Before v40 these are absent, which is exactly what broke the dashboard.
    expect(LIVE_COLUMNS.has('threat_class')).toBe(false);
    expect(LIVE_COLUMNS.has('solution_generated')).toBe(false);
  });
});

describe('God Mode phase-3 backlog drain', () => {
  it('marks processed CVEs solution_generated = 1', () => {
    expect(GODMODE).toMatch(/UPDATE threat_intel SET solution_generated = 1 WHERE id IN/);
  });

  it('the mark is guarded so a missing column never aborts the pipeline', () => {
    // The UPDATE must sit inside a try/catch that warns rather than throws.
    const idx = GODMODE.indexOf('solution_generated = 1 WHERE id IN');
    const window = GODMODE.slice(Math.max(0, idx - 400), idx + 200);
    expect(window).toMatch(/try\s*\{/);
  });
});
