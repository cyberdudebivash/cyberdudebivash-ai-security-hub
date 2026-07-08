#!/usr/bin/env node
/**
 * Capability Registry — handler/export extraction (CEAP instrument, see
 * docs/capability-registry/SCHEMA.md).
 *
 * Enumerates every file under workers/src/handlers/** and every top-level
 * `export` it defines. This is the STABLE evidence unit for the registry's
 * backend.entry_points field — unlike a route-path string, an exported
 * function name is reliable evidence regardless of which routing idiom
 * dispatches it (the ~700-entry if-chain in workers/src/index.js, a
 * secondary object-literal route table like SYNC_ROUTES, or one of the
 * ~35 prefix/`startsWith` dispatcher handlers whose internal actions are
 * invisible to any index.js-level route scan).
 *
 * This is an ANALYSIS tool, not a registry writer: it produces ground truth
 * an engineer (or an AI session) uses to populate/re-verify
 * docs/capability-registry/domains/*.json accurately. It does not write the
 * registry itself — grouping ~700 routes into ~60-100 customer-recognizable
 * capabilities requires judgment that a mechanical script would flatten.
 *
 * Regex-based, not a real JS parser (no new dependency — this repo's
 * scripts/ directory is deliberately dependency-free, Node 18+ only, see
 * scripts/d1-schema-diff.mjs's own header). Best-effort: catches the
 * dominant `export async function NAME`, `export function NAME`,
 * `export const NAME`, `export class NAME`, and `export { a, b as c }` forms.
 * Does not resolve `export default` to a name when it wraps an anonymous
 * expression — reported as "default (anonymous)" rather than guessed.
 *
 * Usage:
 *   node scripts/registry/extract-handlers.mjs                 # human-readable summary
 *   node scripts/registry/extract-handlers.mjs --json           # full JSON to stdout
 *   node scripts/registry/extract-handlers.mjs --json > out.json
 *
 * Exit codes: 0 always (pure read/report tool — never fails a build).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const REPO_ROOT = process.cwd();
const HANDLERS_DIR = join(REPO_ROOT, 'workers/src/handlers');

const NAMED_EXPORT_RE = /export\s+(?:async\s+function\s*\*?|function\s*\*?|const|let|class)\s+([A-Za-z0-9_$]+)/g;
const EXPORT_LIST_RE = /export\s*\{([^}]+)\}(?!\s*from)/g;
const EXPORT_DEFAULT_NAMED_RE = /export\s+default\s+(?:async\s+)?function\s+([A-Za-z0-9_$]+)/;

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(full));
    else if (entry.endsWith('.js')) out.push(full);
  }
  return out;
}

function extractExports(src) {
  const names = new Set();
  let m;

  NAMED_EXPORT_RE.lastIndex = 0;
  while ((m = NAMED_EXPORT_RE.exec(src)) !== null) names.add(m[1]);

  EXPORT_LIST_RE.lastIndex = 0;
  while ((m = EXPORT_LIST_RE.exec(src)) !== null) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/).pop().trim();
      if (name) names.add(name);
    }
  }

  const def = EXPORT_DEFAULT_NAMED_RE.exec(src);
  if (def) names.add(def[1]);
  else if (/export\s+default\b/.test(src)) names.add('default (anonymous)');

  return [...names].sort();
}

function main() {
  const files = walk(HANDLERS_DIR).sort();
  const report = files.map((absPath) => {
    const relPath = relative(REPO_ROOT, absPath).split(sep).join('/');
    const src = readFileSync(absPath, 'utf8');
    const exportNames = extractExports(src);
    const handleFns = exportNames.filter((n) => /^handle[A-Z]/.test(n));
    return {
      file: relPath,
      lineCount: src.split('\n').length,
      exports: exportNames,
      handlerFunctionCount: handleFns.length,
    };
  });

  const asJson = process.argv.includes('--json');
  if (asJson) {
    process.stdout.write(JSON.stringify({ generated: new Date().toISOString(), fileCount: report.length, files: report }, null, 2) + '\n');
    return;
  }

  const totalExports = report.reduce((s, r) => s + r.exports.length, 0);
  const totalHandleFns = report.reduce((s, r) => s + r.handlerFunctionCount, 0);
  console.log(`Handler files scanned: ${report.length}`);
  console.log(`Total exports found:   ${totalExports}`);
  console.log(`Total handle*() fns:   ${totalHandleFns}`);
  console.log('');
  console.log('Run with --json for the full per-file export list.');
}

main();
