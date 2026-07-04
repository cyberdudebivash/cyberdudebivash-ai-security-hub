#!/usr/bin/env node
// lab-bootstrap-d1.mjs — build a working D1 schema on an EMPTY local database
// by replaying the repo's historical schema files in production order, with
// continue-on-error semantics (how production itself accreted its schema).
//
// Why this exists (Phase VII finding, DEPLOY.md "Fresh-environment database
// bootstrap"): the schema*.sql files are historical migrations, not a
// reproducible bootstrap — run as single transactions they abort on first
// conflict. This script replays them statement-by-statement, skips the one
// known-destructive pair (v45/v45b users rebuild — already consolidated into
// schema_master.sql's users definition; on an empty DB the rename/rebuild can
// strand the users table if any step fails), and reports exactly what landed.
//
//   node scripts/lab-bootstrap-d1.mjs --db <sqlite file> [--workers workers]
//                                     [--dump-bootstrap <out.sql>]
//
// --dump-bootstrap writes the resulting schema as a single canonical
// CREATE-statement file (the schema_bootstrap.sql tracked in the Production
// Health Scorecard action queue).

import { DatabaseSync } from 'node:sqlite';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const args = process.argv.slice(2);
function arg(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
}
const dbPath = arg('--db');
const workersDir = arg('--workers', 'workers');
const dumpPath = arg('--dump-bootstrap');
if (!dbPath) {
  console.error('usage: lab-bootstrap-d1.mjs --db <sqlite> [--workers dir] [--dump-bootstrap out.sql]');
  process.exit(2);
}

// Production replay order. schema_master.sql is the v38 consolidation of all
// earlier files (v8–v38); pre-master files are intentionally NOT re-applied —
// their DROP+CREATE rebuilds would regress table shapes master already
// modernized. v45/v45b are skipped (see header).
const REPLAY = [
  'schema_master.sql',
  'schema_v39_marketplace.sql',
  'schema_v40_godmode_intel_columns.sql',
  'schema_v41_mssp_partner_isolation.sql',
  'schema_v42_referral_attribution.sql',
  'schema_v43_agent_threat_advisories.sql',
  'schema_v44_attack_library.sql',
  'schema_v44b_attack_library_categories.sql',
  'schema_v46_missing_tables.sql',
  'schema_v47_mssp_revenue_share.sql',
  'schema_v48_generated_rules.sql',
  'schema_migration_missing_cols.sql',
  'schema_migration_mfa.sql',
  'schema_migration_sso.sql',
  'schema_migration_rc1.sql',
  'schema_migration_eboc1.sql',
  'schema_migration_eboc1b.sql',
  'schema_migration_eboc1c.sql',
  'schema_migration_eop.sql',
  'schema_migration_eop_a.sql',
  'schema_migration_eop_b.sql',
  'schema_migration_eop_c.sql',
  'schema_migration_cvss_score_backfill.sql',
  'schema_migrations_v2.sql',
  'schema_threat_intel.sql',
  'schema_gtm_only.sql',
  'schema_mcp_learning.sql',
  'schema_revenue_autopilot.sql',
  join('migrations', 'phase2_soc_mssp_safe.sql'),
];

// Split SQL into statements: semicolons end statements except inside
// 'single-quoted strings'. No schema file in this repo defines triggers
// (verified), so BEGIN…END blocks need no special casing.
function splitStatements(sql) {
  const out = [];
  let cur = '';
  let inStr = false;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (inStr) {
      cur += c;
      if (c === "'") {
        if (sql[i + 1] === "'") { cur += "'"; i++; } else inStr = false;
      }
      continue;
    }
    if (c === "'") { inStr = true; cur += c; continue; }
    if (c === '-' && sql[i + 1] === '-') {         // line comment
      while (i < sql.length && sql[i] !== '\n') i++;
      cur += '\n';
      continue;
    }
    if (c === ';') { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter((s) => s.length > 0);
}

const heal = args.includes('--heal');
const db = new DatabaseSync(dbPath);
db.exec('PRAGMA foreign_keys = OFF');

let applied = 0;
let failed = 0;
const failures = [];
const healed = [];
for (const rel of REPLAY) {
  const p = join(workersDir, rel);
  if (!existsSync(p)) { console.error(`  [missing] ${rel}`); continue; }
  const stmts = splitStatements(readFileSync(p, 'utf8'));
  let ok = 0;
  let bad = 0;
  for (const s of stmts) {
    if (/^PRAGMA/i.test(s)) continue;
    try { db.exec(s); ok++; } catch (e) {
      // Heal pass: production carries columns that later hotfix files index
      // but whose ALTERs were never consolidated into schema_master's CREATEs.
      // For "no such column" failures on CREATE INDEX, add the column (as
      // production has it) and retry — keeps the lab faithful to prod.
      if (heal && /^CREATE\s+(UNIQUE\s+)?INDEX/i.test(s)) {
        let err = e;
        let done = false;
        for (let tries = 0; tries < 6 && !done; tries++) {
          const m = /no such column: (\w+)/.exec(String(err.message));
          const t = /ON\s+(\w+)\s*\(/i.exec(s);
          if (!m || !t) break;
          try {
            db.exec(`ALTER TABLE ${t[1]} ADD COLUMN ${m[1]}`);
            healed.push(`${t[1]}.${m[1]}`);
            db.exec(s);
            done = true;
          } catch (e2) {
            if (!/no such column/.test(String(e2.message))) break;
            err = e2;
          }
        }
        if (done) { ok++; continue; }
      }
      bad++;
      failures.push({ file: rel, error: String(e.message).slice(0, 120), stmt: s.slice(0, 90).replace(/\s+/g, ' ') });
    }
  }
  applied += ok; failed += bad;
  console.log(`  ${rel}: ${ok} applied${bad ? `, ${bad} failed` : ''}`);
}

const tables = db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table'").get().n;
console.log(`\nBootstrap complete: ${applied} statements applied, ${failed} failed, ${tables} tables.`);
if (healed.length) console.log(`Healed columns (${healed.length}): ${healed.join(', ')}`);
if (failures.length) {
  console.log('Failures (expected for historical hotfix statements):');
  for (const f of failures.slice(0, 30)) console.log(`  - [${f.file}] ${f.error} :: ${f.stmt}`);
  if (failures.length > 30) console.log(`  … and ${failures.length - 30} more`);
}

if (dumpPath) {
  const rows = db.prepare(
    "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name"
  ).all();
  const header = `-- schema_bootstrap.sql — canonical single-file schema\n-- Generated by scripts/lab-bootstrap-d1.mjs from the historical migration\n-- replay on an empty database. Apply to an EMPTY D1 only.\n-- Tables: ${tables}. PRAGMA foreign_keys=OFF during load.\nPRAGMA foreign_keys = OFF;\n\n`;
  writeFileSync(dumpPath, header + rows.map((r) => r.sql.replace(/^CREATE TABLE /i, 'CREATE TABLE IF NOT EXISTS ').replace(/^CREATE INDEX /i, 'CREATE INDEX IF NOT EXISTS ').replace(/^CREATE UNIQUE INDEX /i, 'CREATE UNIQUE INDEX IF NOT EXISTS ') + ';').join('\n\n') + '\n');
  console.log(`\nCanonical bootstrap written: ${dumpPath}`);
}
db.close();
