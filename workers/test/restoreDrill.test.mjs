/* The D1 restore drill (scripts/d1-restore-drill.mjs) is the acceptance
 * evidence that a Nightly D1 Backup artifact is actually restorable. A drill
 * that never fails is worthless, so this locks BOTH directions: a valid dump
 * passes, and corrupt / truncated / tampered dumps fail with a non-zero exit.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const SCRIPT = resolve(import.meta.dirname, '../../scripts/d1-restore-drill.mjs');
const dir = mkdtempSync(join(tmpdir(), 'restore-drill-test-'));

function runDrill(args) {
  try {
    const stdout = execFileSync('node', [SCRIPT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status ?? 1, stdout: (e.stdout || '') + (e.stderr || '') };
  }
}

const VALID_DUMP = [
  'PRAGMA foreign_keys=OFF;',
  'BEGIN TRANSACTION;',
  'CREATE TABLE "users" (id TEXT PRIMARY KEY, email TEXT, tier TEXT);',
  "INSERT INTO \"users\" VALUES ('u1','a@b.com','PRO');",
  "INSERT INTO \"users\" VALUES ('u2','c@d.com','FREE');",
  'CREATE TABLE "subscriptions" (id TEXT PRIMARY KEY, plan TEXT);',
  "INSERT INTO \"subscriptions\" VALUES ('s1','PRO');",
  'COMMIT;',
].join('\n');

describe('d1-restore-drill.mjs', () => {
  it('PASSES on a valid gzipped dump and reports the right row count', () => {
    const gz = gzipSync(Buffer.from(VALID_DUMP));
    const f = join(dir, 'valid.sql.gz');
    writeFileSync(f, gz);
    const sha = createHash('sha256').update(gz).digest('hex');
    const { code, stdout } = runDrill([f, '--expect-sha256', sha, '--min-tables', '2']);
    expect(code).toBe(0);
    expect(stdout).toContain('RESTORE DRILL PASSED');
    expect(stdout).toContain('Restored rows (all tables): 3');
    expect(stdout).toMatch(/RESTORE_DRILL_RESULT \{.*"ok":true.*"tables":2.*\}/);
  });

  it('PASSES on a plain .sql dump (no gzip)', () => {
    const f = join(dir, 'valid.sql');
    writeFileSync(f, VALID_DUMP);
    const { code } = runDrill([f, '--min-tables', '2']);
    expect(code).toBe(0);
  });

  it('FAILS on a SHA-256 mismatch (tamper detection)', () => {
    const f = join(dir, 'tamper.sql.gz');
    writeFileSync(f, gzipSync(Buffer.from(VALID_DUMP)));
    const { code, stdout } = runDrill([f, '--expect-sha256', 'deadbeef']);
    expect(code).not.toBe(0);
    expect(stdout).toContain('SHA-256 mismatch');
  });

  it('FAILS on a truncated dump below --min-tables', () => {
    const f = join(dir, 'trunc.sql');
    writeFileSync(f, 'CREATE TABLE "x" (id INT);');
    const { code, stdout } = runDrill([f, '--min-tables', '10']);
    expect(code).not.toBe(0);
    expect(stdout).toMatch(/only 1 tables restored/);
  });

  it('FAILS on structurally corrupt SQL (reports a restore error, not "no engine")', () => {
    const f = join(dir, 'corrupt.sql');
    writeFileSync(f, 'CREATE TABLE broken (\nINSERT nonsense;\n');
    const { code, stdout } = runDrill([f]);
    expect(code).not.toBe(0);
    expect(stdout).toContain('restore error');
  });

  it('FAILS on a non-existent file', () => {
    const { code, stdout } = runDrill([join(dir, 'nope.sql.gz')]);
    expect(code).not.toBe(0);
    expect(stdout).toContain('file not found');
  });
});
