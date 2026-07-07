/* Locks CI-2's schema-drift check (scripts/d1-schema-diff.mjs) against the
 * exact bug class it exists to catch: RC-B1, a column renamed in production
 * (or in the reference) without the other side following — a green test
 * suite saw nothing because the lab schema silently disagreed with
 * production (Production Truth Law, docs/ENGINEERING_STANDARDS.md §11).
 * Fixtures mirror the real syntax in workers/schema_bootstrap.sql (nested
 * parens in DEFAULT/CHECK, table-level FOREIGN KEY/UNIQUE, IF NOT EXISTS)
 * so the parser is proven against what it will actually see, not a
 * simplified stand-in.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseSchema, diffSchemas, extractLiveSql, loadAcceptedDrift } from '../../scripts/d1-schema-diff.mjs';

const SCRIPT = resolve(import.meta.dirname, '../../scripts/d1-schema-diff.mjs');
const REAL_BOOTSTRAP = resolve(import.meta.dirname, '../schema_bootstrap.sql');
const REAL_ACCEPTED_DRIFT = resolve(import.meta.dirname, '../schema_drift_accepted.json');

const FIXTURE_SCHEMA = `
-- a header comment, like schema_bootstrap.sql's own
CREATE TABLE IF NOT EXISTS adsense_events (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type  TEXT NOT NULL
                CHECK (event_type IN ('impression','click','revenue')),
  revenue_usd REAL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_history (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL,
  scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS affiliate_members (
  id       TEXT PRIMARY KEY,
  email    TEXT NOT NULL UNIQUE,
  ref_code TEXT NOT NULL,
  UNIQUE(ref_code)
);
`;

describe('parseSchema', () => {
  it('extracts table names and column names, ignoring types/defaults', () => {
    const tables = parseSchema(FIXTURE_SCHEMA);
    expect([...tables.keys()].sort()).toEqual(['adsense_events', 'affiliate_members', 'scan_history']);
    expect(tables.get('adsense_events')).toEqual(new Set(['id', 'event_type', 'revenue_usd', 'created_at']));
  });

  it('does not mistake a table-level FOREIGN KEY clause for a column', () => {
    const cols = parseSchema(FIXTURE_SCHEMA).get('scan_history');
    expect(cols).toEqual(new Set(['id', 'org_id', 'scanned_at']));
    expect(cols.has('foreign')).toBe(false);
  });

  it('does not mistake a table-level UNIQUE(...) clause for a column', () => {
    const cols = parseSchema(FIXTURE_SCHEMA).get('affiliate_members');
    expect(cols).toEqual(new Set(['id', 'email', 'ref_code']));
  });

  it('is unfazed by nested parens in DEFAULT/CHECK and multi-line column defs', () => {
    const cols = parseSchema(FIXTURE_SCHEMA).get('adsense_events');
    expect(cols.has('event_type')).toBe(true);
    expect(cols.size).toBe(4);
  });

  it('strips -- comments before parsing', () => {
    const tables = parseSchema('-- CREATE TABLE decoy (x TEXT);\nCREATE TABLE IF NOT EXISTS real_one (id TEXT);');
    expect([...tables.keys()]).toEqual(['real_one']);
  });

  it('excludes sqlite_%/_cf_% system tables, matching lab-bootstrap-d1.mjs\'s own --dump-bootstrap filter', () => {
    // A live export always contains SQLite's own sqlite_sequence (auto-created
    // by any AUTOINCREMENT column) and D1-internal _cf_kv — neither is ever
    // written by application schema, and schema_bootstrap.sql's generator
    // already drops both (name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%').
    // Without the same filter here, those two tables would permanently
    // false-positive as "undocumented in live" on every run, forever.
    const tables = parseSchema(
      "CREATE TABLE real_one (id TEXT);\nCREATE TABLE sqlite_sequence(name,seq);\nCREATE TABLE _cf_kv (key TEXT, value TEXT);"
    );
    expect([...tables.keys()]).toEqual(['real_one']);
  });

  it('parses cleanly (>0 tables, no thrown error) against the real schema_bootstrap.sql', () => {
    const real = readFileSync(REAL_BOOTSTRAP, 'utf8');
    const tables = parseSchema(real);
    expect(tables.size).toBeGreaterThan(200); // 227 at time of writing; guards against a parser regression silently returning 0/1
    for (const [name, cols] of tables) {
      expect(cols.size, `table ${name} parsed with zero columns`).toBeGreaterThan(0);
    }
  });
});

describe('diffSchemas', () => {
  it('reports no drift when live matches reference exactly', () => {
    const ref = parseSchema(FIXTURE_SCHEMA);
    const live = parseSchema(FIXTURE_SCHEMA);
    const result = diffSchemas(live, ref);
    expect(result.hasDrift).toBe(false);
    expect(result.missingInLive).toEqual([]);
    expect(result.undocumentedInLive).toEqual([]);
    expect(result.columnDrift).toEqual([]);
  });

  it('catches the RC-B1 class: a column renamed in live vs. the committed reference', () => {
    const ref = parseSchema('CREATE TABLE scan_history (id TEXT, created_at TEXT);');
    const live = parseSchema('CREATE TABLE scan_history (id TEXT, scanned_at TEXT);'); // production actually has this
    const result = diffSchemas(live, ref);
    expect(result.hasDrift).toBe(true);
    expect(result.columnDrift).toEqual([{ table: 'scan_history', onlyInReference: ['created_at'], onlyInLive: ['scanned_at'] }]);
  });

  it('flags a table present in the reference but missing in live production', () => {
    const ref = parseSchema('CREATE TABLE a (id TEXT); CREATE TABLE b (id TEXT);');
    const live = parseSchema('CREATE TABLE a (id TEXT);');
    const result = diffSchemas(live, ref);
    expect(result.missingInLive).toEqual(['b']);
    expect(result.hasDrift).toBe(true);
  });

  it('flags a table present in live production but not in the reference (undocumented drift)', () => {
    const ref = parseSchema('CREATE TABLE a (id TEXT);');
    const live = parseSchema('CREATE TABLE a (id TEXT); CREATE TABLE shadow_table (id TEXT);');
    const result = diffSchemas(live, ref);
    expect(result.undocumentedInLive).toEqual(['shadow_table']);
    expect(result.hasDrift).toBe(true);
  });

  it('does NOT flag drift for a column present on both sides regardless of type/default text', () => {
    const ref = parseSchema('CREATE TABLE a (id TEXT PRIMARY KEY, n INTEGER DEFAULT 0);');
    const live = parseSchema('CREATE TABLE a (id TEXT, n INTEGER DEFAULT 5 NOT NULL);'); // same columns, different type/default detail
    const result = diffSchemas(live, ref);
    expect(result.hasDrift).toBe(false);
  });
});

describe('loadAcceptedDrift', () => {
  it('parses an {accepted: [...]} shape into Map<table, Set<column>>', () => {
    const map = loadAcceptedDrift(JSON.stringify({
      accepted: [{ table: 'Alert_Log', column: 'Alert_Type', reason: 'belongs to a different table' }],
    }));
    expect(map.get('alert_log')).toEqual(new Set(['alert_type'])); // lowercased, matching parseSchema's own convention
  });

  it('also accepts a bare array shape', () => {
    const map = loadAcceptedDrift(JSON.stringify([{ table: 'a', column: 'b', reason: 'r' }]));
    expect(map.get('a')).toEqual(new Set(['b']));
  });

  it('merges multiple columns for the same table into one Set', () => {
    const map = loadAcceptedDrift(JSON.stringify({
      accepted: [
        { table: 'crm_leads', column: 'urgency', reason: 'r1' },
        { table: 'crm_leads', column: 'metadata', reason: 'r2' },
      ],
    }));
    expect(map.get('crm_leads')).toEqual(new Set(['urgency', 'metadata']));
  });

  it('rejects an entry missing a reason — an allowlist entry must be justified, not just asserted', () => {
    expect(() => loadAcceptedDrift(JSON.stringify({ accepted: [{ table: 'a', column: 'b' }] }))).toThrow(/missing table\/column\/reason/);
  });

  it('rejects an entry missing table or column', () => {
    expect(() => loadAcceptedDrift(JSON.stringify({ accepted: [{ column: 'b', reason: 'r' }] }))).toThrow(/missing table\/column\/reason/);
    expect(() => loadAcceptedDrift(JSON.stringify({ accepted: [{ table: 'a', reason: 'r' }] }))).toThrow(/missing table\/column\/reason/);
  });

  it('rejects a shape that is neither an array nor {accepted: [...]}', () => {
    expect(() => loadAcceptedDrift(JSON.stringify({ foo: 'bar' }))).toThrow(/must be a JSON array/);
  });

  it('parses cleanly against the real workers/schema_drift_accepted.json, and every entry is well-formed', () => {
    const real = readFileSync(REAL_ACCEPTED_DRIFT, 'utf8');
    const map = loadAcceptedDrift(real); // throws on any malformed entry — the assertion IS that this doesn't throw
    expect(map.size).toBeGreaterThan(0);
  });
});

describe('diffSchemas — accepted-drift allowlist', () => {
  it('excludes an allowlisted onlyInReference column from columnDrift/hasDrift, but still reports it under acceptedDrift', () => {
    const ref = parseSchema('CREATE TABLE alert_log (id TEXT, alert_type TEXT);');
    const live = parseSchema('CREATE TABLE alert_log (id TEXT);');
    const accepted = loadAcceptedDrift(JSON.stringify({ accepted: [{ table: 'alert_log', column: 'alert_type', reason: 'dead' }] }));
    const result = diffSchemas(live, ref, accepted);
    expect(result.hasDrift).toBe(false);
    expect(result.columnDrift).toEqual([]);
    expect(result.acceptedDrift).toEqual([{ table: 'alert_log', columns: ['alert_type'] }]);
  });

  it('still flags a NON-allowlisted onlyInReference column on the same table as real drift', () => {
    const ref = parseSchema('CREATE TABLE alert_log (id TEXT, alert_type TEXT, brand_new_col TEXT);');
    const live = parseSchema('CREATE TABLE alert_log (id TEXT);');
    const accepted = loadAcceptedDrift(JSON.stringify({ accepted: [{ table: 'alert_log', column: 'alert_type', reason: 'dead' }] }));
    const result = diffSchemas(live, ref, accepted);
    expect(result.hasDrift).toBe(true);
    expect(result.columnDrift).toEqual([{ table: 'alert_log', onlyInReference: ['brand_new_col'], onlyInLive: [] }]);
  });

  it('never lets the allowlist suppress onlyInLive (production-has-undocumented-column) drift, even on a name collision', () => {
    // Same table+column name is allowlisted on the onlyInReference side, but
    // here it shows up as onlyInLive instead — must NOT be suppressed, since
    // that direction always means the reference is stale, never "known dead".
    const ref = parseSchema('CREATE TABLE t (id TEXT);');
    const live = parseSchema('CREATE TABLE t (id TEXT, alert_type TEXT);');
    const accepted = loadAcceptedDrift(JSON.stringify({ accepted: [{ table: 't', column: 'alert_type', reason: 'irrelevant here' }] }));
    const result = diffSchemas(live, ref, accepted);
    expect(result.hasDrift).toBe(true);
    expect(result.columnDrift).toEqual([{ table: 't', onlyInReference: [], onlyInLive: ['alert_type'] }]);
  });

  it('defaults to an empty allowlist (no third argument) — unchanged, strict behavior', () => {
    const ref = parseSchema('CREATE TABLE a (id TEXT, gone TEXT);');
    const live = parseSchema('CREATE TABLE a (id TEXT);');
    const result = diffSchemas(live, ref);
    expect(result.hasDrift).toBe(true);
    expect(result.acceptedDrift).toEqual([]);
  });

  it('a table with only allowlisted drift does not appear in columnDrift at all', () => {
    const ref = parseSchema('CREATE TABLE cti_actors (id TEXT, active_since TEXT);');
    const live = parseSchema('CREATE TABLE cti_actors (id TEXT);');
    const accepted = loadAcceptedDrift(JSON.stringify({ accepted: [{ table: 'cti_actors', column: 'active_since', reason: 'dead' }] }));
    const result = diffSchemas(live, ref, accepted);
    expect(result.columnDrift.find((d) => d.table === 'cti_actors')).toBeUndefined();
  });

  it('the real accepted-drift file resolves the real schema_bootstrap.sql\'s known-dead columns to zero drift, standalone', () => {
    // Directly exercises the exact scenario that caused the CI failure this
    // allowlist was built to fix: a live export missing ONLY the 29 audited
    // dead columns (and nothing else) must now report zero drift.
    const referenceTables = parseSchema(readFileSync(REAL_BOOTSTRAP, 'utf8'));
    const accepted = loadAcceptedDrift(readFileSync(REAL_ACCEPTED_DRIFT, 'utf8'));
    // Build a "live" schema equal to the reference minus every allowlisted column.
    const liveTables = new Map();
    for (const [table, cols] of referenceTables) {
      const deadCols = accepted.get(table) || new Set();
      liveTables.set(table, new Set([...cols].filter((c) => !deadCols.has(c))));
    }
    const result = diffSchemas(liveTables, referenceTables, accepted);
    expect(result.hasDrift).toBe(false);
    expect(result.acceptedDrift.reduce((n, a) => n + a.columns.length, 0)).toBe(
      [...accepted.values()].reduce((n, s) => n + s.size, 0)
    );
  });
});

describe('extractLiveSql (wrangler --json shape)', () => {
  it('unwraps [{ results: [{sql, ...}] }] into concatenated CREATE TABLE text', () => {
    const wranglerJson = [{ results: [{ name: 'a', sql: 'CREATE TABLE a (id TEXT);' }, { name: 'b', sql: 'CREATE TABLE b (id TEXT);' }], success: true }];
    const sql = extractLiveSql(wranglerJson);
    expect(sql).toContain('CREATE TABLE a');
    expect(sql).toContain('CREATE TABLE b');
  });

  it('throws on an unexpected shape instead of silently returning nothing', () => {
    expect(() => extractLiveSql({ not: 'an array' })).toThrow(/unexpected wrangler output shape/);
    expect(() => extractLiveSql([])).toThrow(/unexpected wrangler output shape/);
    expect(() => extractLiveSql([{ no_results_key: true }])).toThrow(/unexpected wrangler output shape/);
  });
});

describe('CLI entry point (file I/O only — no network)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'schema-diff-test-'));

  function run(args) {
    try {
      const stdout = execFileSync('node', [SCRIPT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return { code: 0, stdout };
    } catch (e) {
      return { code: e.status ?? 1, stdout: (e.stdout || '') + (e.stderr || '') };
    }
  }

  it('exits 0 (OK) when the live export matches the reference file', () => {
    const refFile = join(dir, 'reference-match.sql');
    const liveFile = join(dir, 'live-match.json');
    writeFileSync(refFile, 'CREATE TABLE a (id TEXT);');
    writeFileSync(liveFile, JSON.stringify([{ results: [{ sql: 'CREATE TABLE a (id TEXT);' }] }]));
    const { code, stdout } = run([liveFile, refFile]);
    expect(code).toBe(0);
    expect(stdout).toContain('"status":"OK"');
  });

  it('exits 1 (DRIFT) and names the exact column drift on a renamed column', () => {
    const refFile = join(dir, 'reference-drift.sql');
    const liveFile = join(dir, 'live-drift.json');
    writeFileSync(refFile, 'CREATE TABLE scan_history (id TEXT, created_at TEXT);');
    writeFileSync(liveFile, JSON.stringify([{ results: [{ sql: 'CREATE TABLE scan_history (id TEXT, scanned_at TEXT);' }] }]));
    const { code, stdout } = run([liveFile, refFile]);
    expect(code).toBe(1);
    expect(stdout).toContain('"status":"DRIFT"');
    expect(stdout).toContain('scan_history');
    expect(stdout).toContain('scanned_at');
  });

  it('exits 2 (CONFIG_ERROR) on a missing live-schema file, never reporting false drift-free', () => {
    const { code, stdout } = run([join(dir, 'does-not-exist.json')]);
    expect(code).toBe(2);
    expect(stdout).toContain('CONFIG_ERROR');
  });

  it('exits 2 (CONFIG_ERROR) when the live export parses to zero tables', () => {
    const liveFile = join(dir, 'empty-live.json');
    writeFileSync(liveFile, JSON.stringify([{ results: [] }]));
    const { code, stdout } = run([liveFile, REAL_BOOTSTRAP]);
    expect(code).toBe(2);
    expect(stdout).toContain('CONFIG_ERROR');
  });

  it('exits 2 (CONFIG_ERROR) with no args (usage)', () => {
    const { code, stdout } = run([]);
    expect(code).toBe(2);
    expect(stdout).toContain('CONFIG_ERROR');
  });

  it('defaults the reference file to workers/schema_bootstrap.sql and exits 0 against a live export that matches it exactly', () => {
    const real = readFileSync(REAL_BOOTSTRAP, 'utf8');
    const tables = parseSchema(real);
    const liveSqlRows = [...tables.entries()].map(([name, cols]) => ({
      sql: `CREATE TABLE ${name} (${[...cols].join(' TEXT, ')} TEXT)`,
    }));
    const liveFile = join(dir, 'live-full-match.json');
    writeFileSync(liveFile, JSON.stringify([{ results: liveSqlRows }]));
    const { code, stdout } = run([liveFile]); // no reference arg — exercises the default path
    expect(code).toBe(0);
    expect(stdout).toContain('"status":"OK"');
  });

  it('defaults the accepted-drift file to workers/schema_drift_accepted.json and exits 0 when live is missing only allowlisted columns', () => {
    const referenceTables = parseSchema(readFileSync(REAL_BOOTSTRAP, 'utf8'));
    const accepted = loadAcceptedDrift(readFileSync(REAL_ACCEPTED_DRIFT, 'utf8'));
    const liveSqlRows = [...referenceTables.entries()].map(([name, cols]) => {
      const deadCols = accepted.get(name) || new Set();
      const liveCols = [...cols].filter((c) => !deadCols.has(c));
      return { sql: `CREATE TABLE ${name} (${liveCols.map((c) => `${c} TEXT`).join(', ')})` };
    });
    const liveFile = join(dir, 'live-minus-accepted-drift.json');
    writeFileSync(liveFile, JSON.stringify([{ results: liveSqlRows }]));
    const { code, stdout } = run([liveFile]); // no reference/accepted-drift args — exercises both default paths
    expect(code).toBe(0);
    expect(stdout).toContain('"status":"OK"');
    expect(stdout).toContain('ACCEPTED DRIFT');
  });

  it('still exits 1 when live is missing an allowlisted column\'s TABLE plus one genuinely new column elsewhere', () => {
    const referenceTables = parseSchema(readFileSync(REAL_BOOTSTRAP, 'utf8'));
    const accepted = loadAcceptedDrift(readFileSync(REAL_ACCEPTED_DRIFT, 'utf8'));
    const liveSqlRows = [...referenceTables.entries()].map(([name, cols]) => {
      const deadCols = accepted.get(name) || new Set();
      let liveCols = [...cols].filter((c) => !deadCols.has(c));
      if (name === 'users') liveCols = liveCols.filter((c) => c !== 'email'); // simulate one real, unexpected regression
      return { sql: `CREATE TABLE ${name} (${liveCols.map((c) => `${c} TEXT`).join(', ')})` };
    });
    const liveFile = join(dir, 'live-minus-accepted-plus-real-drift.json');
    writeFileSync(liveFile, JSON.stringify([{ results: liveSqlRows }]));
    const { code, stdout } = run([liveFile]);
    expect(code).toBe(1);
    expect(stdout).toContain('"status":"DRIFT"');
    expect(stdout).toContain('users');
    expect(stdout).toContain('email');
  });
});
