#!/usr/bin/env node
/**
 * D1 Restore Drill — proves a Nightly D1 Backup artifact is actually restorable.
 *
 * The Enterprise Acceptance board holds "restore never proven" as an open
 * blocker: a backup you cannot restore is not a backup. This script closes it
 * deterministically — it takes a `wrangler d1 export` dump (the exact artifact
 * .github/workflows/d1-backup.yml produces) and:
 *
 *   1. Decompresses it (accepts .sql or .sql.gz).
 *   2. Restores it into a throwaway SQLite database (better-sqlite3 if present,
 *      else the `sqlite3` CLI, else Node's node:sqlite on Node 22+).
 *   3. Runs `PRAGMA integrity_check` — the restored DB must report "ok".
 *   4. Asserts the restored schema is non-trivial (>= --min-tables, default 10)
 *      and reports table + row counts so the operator can eyeball completeness.
 *   5. Verifies the dump's SHA-256 against --expect-sha256 when provided
 *      (matches the value the backup workflow records in its job summary).
 *
 * Exit 0 = restore proven. Non-zero = drill FAILED (do not trust the backup).
 *
 * Usage:
 *   node scripts/d1-restore-drill.mjs <dump.sql|dump.sql.gz> [--expect-sha256 <hex>] [--min-tables 10]
 *
 * Fetch the latest nightly artifact first (needs repo access + gh CLI):
 *   gh run download --repo cyberdudebivash/cyberdudebivash-ai-security-hub \
 *     --name "$(gh run list --workflow d1-backup.yml -L1 --json databaseId ...)" ...
 *   # or: Actions ▸ Nightly D1 Backup ▸ latest run ▸ Artifacts ▸ download
 *
 * See DISASTER_RECOVERY_RUNBOOK.md for the full restore-to-production path.
 */
import { readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function parseArgs(argv) {
  const args = { file: null, expectSha: null, minTables: 10 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--expect-sha256') args.expectSha = (argv[++i] || '').toLowerCase();
    else if (a === '--min-tables') args.minTables = parseInt(argv[++i] || '10', 10);
    else if (!a.startsWith('--')) args.file = a;
  }
  return args;
}

function fail(msg) { console.error(`\n❌ RESTORE DRILL FAILED: ${msg}\n`); process.exit(1); }
function ok(msg)   { console.log(`✅ ${msg}`); }

const { file, expectSha, minTables } = parseArgs(process.argv.slice(2));
if (!file) fail('no dump file given.\n   Usage: node scripts/d1-restore-drill.mjs <dump.sql|dump.sql.gz> [--expect-sha256 <hex>] [--min-tables N]');
if (!existsSync(file)) fail(`file not found: ${file}`);

console.log(`\n━━━ D1 Restore Drill ━━━\nDump: ${file}\n`);

// 1) Load + decompress + hash the raw artifact bytes (hash is of the file as stored).
const rawBytes = readFileSync(file);
const sha256 = createHash('sha256').update(rawBytes).digest('hex');
ok(`SHA-256: ${sha256}`);
if (expectSha) {
  if (sha256 !== expectSha) fail(`SHA-256 mismatch — expected ${expectSha}, got ${sha256}. Artifact is corrupt or tampered.`);
  ok('SHA-256 matches the recorded backup checksum');
}

const sql = file.endsWith('.gz') ? gunzipSync(rawBytes).toString('utf8') : rawBytes.toString('utf8');
if (!/CREATE TABLE/i.test(sql)) fail('dump contains no CREATE TABLE statements — not a valid D1 export.');
ok(`Decompressed SQL: ${sql.length.toLocaleString()} chars`);

// 2) Restore into a throwaway database using whatever SQLite engine is available.
const dbPath = join(tmpdir(), `d1-restore-drill-${Date.now()}.db`);
let result;
try {
  result = restore(sql, dbPath);
} finally {
  try { rmSync(dbPath, { force: true }); } catch {}
}

// 3-4) Assertions on the restored database.
if (result.integrity !== 'ok') fail(`PRAGMA integrity_check returned "${result.integrity}" (expected "ok").`);
ok(`PRAGMA integrity_check: ok`);
ok(`Restored tables: ${result.tableCount}`);
ok(`Restored rows (all tables): ${result.rowCount.toLocaleString()}`);
if (result.tableCount < minTables) fail(`only ${result.tableCount} tables restored (min ${minTables}) — dump likely truncated.`);
ok(`Table count >= ${minTables}`);

console.log(`\n━━━ RESTORE DRILL PASSED ━━━`);
console.log(`The backup is restorable: ${result.tableCount} tables, ${result.rowCount.toLocaleString()} rows, integrity ok.`);
console.log(`Engine: ${result.engine}\n`);

// Machine-readable evidence line (grep-able in CI / runbook logs).
console.log(`RESTORE_DRILL_RESULT ${JSON.stringify({
  ok: true, sha256, tables: result.tableCount, rows: result.rowCount,
  integrity: result.integrity, engine: result.engine, ts: new Date().toISOString(),
})}`);

// ── SQLite engine adapters ────────────────────────────────────────────────────
function restore(sqlText, dbPath) {
  // Engine selection is resolved FIRST and separately from the restore itself,
  // so a genuine SQL/restore error is never misreported as "no engine".
  const engine = pickEngine();
  if (!engine) fail('no SQLite engine available. Install Node 22.5+ (built-in node:sqlite), or the sqlite3 CLI, then re-run.');

  if (engine === 'node:sqlite') {
    const { DatabaseSync } = require('node:sqlite');
    const db = new DatabaseSync(dbPath);
    try {
      db.exec('PRAGMA foreign_keys=OFF;');
      db.exec(sqlText);
    } catch (e) {
      db.close();
      fail(`restore error (node:sqlite): ${e.message}`);
    }
    const integrity = db.prepare('PRAGMA integrity_check').get().integrity_check;
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
    let rowCount = 0;
    for (const t of tables) rowCount += db.prepare(`SELECT COUNT(*) c FROM "${t.name}"`).get().c;
    db.close();
    return { engine, integrity, tableCount: tables.length, rowCount };
  }

  // sqlite3 CLI.
  try {
    execFileSync('sqlite3', [dbPath], { input: sqlText });
  } catch (e) {
    fail(`restore error (sqlite3 CLI): ${e.message}`);
  }
  const integrity = execFileSync('sqlite3', [dbPath, 'PRAGMA integrity_check'], { encoding: 'utf8' }).trim();
  const tableList = execFileSync('sqlite3', [dbPath, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"], { encoding: 'utf8' }).trim().split('\n').filter(Boolean);
  let rowCount = 0;
  for (const t of tableList) rowCount += parseInt(execFileSync('sqlite3', [dbPath, `SELECT COUNT(*) FROM "${t}"`], { encoding: 'utf8' }).trim() || '0', 10);
  return { engine: 'sqlite3 CLI', integrity, tableCount: tableList.length, rowCount };
}

function pickEngine() {
  try { require('node:sqlite'); return 'node:sqlite'; } catch { /* not on this Node */ }
  try { execFileSync('sqlite3', ['--version'], { stdio: 'ignore' }); return 'sqlite3'; } catch { /* no CLI */ }
  return null;
}
