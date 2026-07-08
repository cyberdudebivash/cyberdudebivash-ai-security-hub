#!/usr/bin/env node
/**
 * Capability Registry — frontend/test/nav cross-reference (CEAP instrument,
 * see docs/capability-registry/SCHEMA.md).
 *
 * Given a set of backend route paths, handler function names, and/or
 * frontend page filenames, reports the concrete evidence needed to fill in
 * a registry entry's frontend/test_coverage/navigation fields:
 *
 *   --paths       literal path strings (comma-separated) → greps frontend/*.html
 *                 (top-level only; excludes frontend/cve/** and frontend/blog/**,
 *                 which are ~1,700 auto-generated CVE pages and blog posts, not
 *                 product capability surfaces) for literal references. Best
 *                 effort: a path used only via a template literal with an
 *                 interpolated segment (e.g. `fetch(`/api/jobs/${id}`)`) will
 *                 show as a miss even if the page does call it — spot-check
 *                 those manually, this is a known limitation, not a bug.
 *
 *   --handler-fns exported function names (comma-separated) → greps
 *                 workers/test/**\/*.mjs for a direct import of that name from
 *                 a handlers/*.js path. This is the STRONG test-coverage
 *                 signal in this repo (100/169 handler files matched this
 *                 way) — filename matching between handler and test file is a
 *                 WEAK signal here (only 14/169) and is not used.
 *
 *   --pages       frontend page filenames (comma-separated, e.g.
 *                 user-dashboard.html) → checks whether any OTHER top-level
 *                 frontend/*.html page links to it via an absolute href
 *                 (confirmed reliable: 0 relative .html links exist in this
 *                 codebase, so an absolute-href grep is not an approximation).
 *
 * No dependency (plain Node.js, regex/grep-based) — matches this repo's
 * existing scripts/ convention.
 *
 * Usage:
 *   node scripts/registry/cross-reference.mjs --paths "/api/orgs,/api/orgs/" --handler-fns "handleCreateOrg,handleListOrgs" --pages "partner-portal.html"
 *   node scripts/registry/cross-reference.mjs --json ...   (same flags, JSON output)
 *
 * Exit codes: 0 always (read/report tool only).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const REPO_ROOT = process.cwd();
const FRONTEND_DIR = join(REPO_ROOT, 'frontend');
const TEST_DIR = join(REPO_ROOT, 'workers/test');

function walk(dir, { recursive = true, extFilter = () => true } = {}) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (recursive) out.push(...walk(full, { recursive, extFilter }));
    } else if (extFilter(entry)) out.push(full);
  }
  return out;
}

function topLevelFrontendPages() {
  // Top-level frontend/*.html only — excludes frontend/cve/** (~1,700
  // auto-generated CVE pages) and frontend/blog/** (blog posts), neither of
  // which are product capability surfaces.
  return readdirSync(FRONTEND_DIR)
    .filter((f) => f.endsWith('.html'))
    .map((f) => join(FRONTEND_DIR, f));
}

function grepLiteral(files, needle) {
  const hits = [];
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    const lines = src.split('\n');
    lines.forEach((line, i) => {
      if (line.includes(needle)) {
        hits.push({ file: relative(REPO_ROOT, file).split(sep).join('/'), line: i + 1 });
      }
    });
  }
  return hits;
}

function checkFrontendPaths(paths) {
  const pages = topLevelFrontendPages();
  const result = {};
  for (const p of paths) result[p] = grepLiteral(pages, p);
  return result;
}

function checkHandlerTestImports(handlerFns) {
  const testFiles = walk(TEST_DIR, { extFilter: (n) => n.endsWith('.mjs') || n.endsWith('.test.mjs') });
  const result = {};
  for (const fn of handlerFns) {
    const hits = [];
    for (const file of testFiles) {
      const src = readFileSync(file, 'utf8');
      const lines = src.split('\n');
      lines.forEach((line, i) => {
        // Match: import { ..., fnName, ... } from '...handlers/...';
        if (/^\s*import\s*\{[^}]*\}\s*from\s*['"][^'"]*handlers\//.test(line) || /^\s*import\s*\{/.test(line)) {
          // narrow to lines that actually mention the function name as a whole word
          if (new RegExp(`\\b${fn}\\b`).test(line) && /handlers\//.test(line)) {
            hits.push({ file: relative(REPO_ROOT, file).split(sep).join('/'), line: i + 1 });
          }
        }
      });
    }
    result[fn] = hits;
  }
  return result;
}

function checkNavReachability(pageNames) {
  const pages = topLevelFrontendPages();
  const result = {};
  for (const pageName of pageNames) {
    const hits = [];
    for (const file of pages) {
      const base = relative(REPO_ROOT, file).split(sep).join('/');
      if (base.endsWith('/' + pageName)) continue; // don't count a page linking to itself
      const src = readFileSync(file, 'utf8');
      const lines = src.split('\n');
      lines.forEach((line, i) => {
        if (/href\s*=\s*["'][^"']*\//.test(line) && line.includes(pageName)) {
          hits.push({ file: base, line: i + 1 });
        }
      });
    }
    result[pageName] = { referencedBy: hits, reachable: hits.length > 0 };
  }
  return result;
}

function parseArgs(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const key = argv[i].slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      flags[key] = val;
    }
  }
  return flags;
}

function main() {
  const flags = parseArgs(process.argv.slice(2));
  const paths = flags.paths ? flags.paths.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const handlerFns = flags['handler-fns'] ? flags['handler-fns'].split(',').map((s) => s.trim()).filter(Boolean) : [];
  const pages = flags.pages ? flags.pages.split(',').map((s) => s.trim()).filter(Boolean) : [];

  if (!paths.length && !handlerFns.length && !pages.length) {
    console.error('Usage: node scripts/registry/cross-reference.mjs --paths "/api/x,/api/y" --handler-fns "handleX,handleY" --pages "page.html" [--json]');
    process.exit(0);
    return;
  }

  const result = {
    generated: new Date().toISOString(),
    frontendPathHits: paths.length ? checkFrontendPaths(paths) : undefined,
    testImportHits: handlerFns.length ? checkHandlerTestImports(handlerFns) : undefined,
    navReachability: pages.length ? checkNavReachability(pages) : undefined,
  };

  if (flags.json === 'true' || process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  if (result.frontendPathHits) {
    console.log('── Frontend literal-path references ──');
    for (const [p, hits] of Object.entries(result.frontendPathHits)) {
      console.log(`  ${p}: ${hits.length} hit(s)` + (hits.length ? ` (e.g. ${hits[0].file}:${hits[0].line})` : ' — NOT referenced by any top-level frontend page'));
    }
  }
  if (result.testImportHits) {
    console.log('── Test coverage (direct handler-function imports) ──');
    for (const [fn, hits] of Object.entries(result.testImportHits)) {
      console.log(`  ${fn}: ${hits.length} test file(s)` + (hits.length ? ` (e.g. ${hits[0].file}:${hits[0].line})` : ' — no test imports this function'));
    }
  }
  if (result.navReachability) {
    console.log('── Navigation reachability (absolute-href references from other pages) ──');
    for (const [page, info] of Object.entries(result.navReachability)) {
      console.log(`  ${page}: ${info.reachable ? 'REACHABLE' : 'ORPHAN'} (${info.referencedBy.length} referencing page(s))`);
    }
  }
}

main();
