#!/usr/bin/env node
/**
 * Capability Registry — best-effort route extraction from workers/src/index.js
 * (CEAP instrument, see docs/capability-registry/SCHEMA.md).
 *
 * This repo's router uses AT LEAST THREE distinct idioms in the same file,
 * confirmed by direct inspection:
 *   1. A ~700-entry sequential if-chain:
 *        if (path === '/api/uptime' && method === 'GET') { ... }
 *      (this is the ONLY idiom workers/test/routeLineageGuard.test.mjs's
 *      regex sees — it is a floor, not a ceiling, on the real route count.)
 *   2. Object-literal route tables, e.g. `SYNC_ROUTES`:
 *        'POST /api/generate/compliance': { handler: handleCompliance, ... }
 *   3. Prefix/regex dispatchers, e.g.:
 *        if (path.startsWith('/api/marketplace/')) { return handleMarketplace(...) }
 *        if (path.match(/^\/api\/mssp\/customers\/[^/]+$/)) { ... }
 *      A dispatcher's INTERNAL actions (e.g. sentinelApexMarketplace.js's own
 *      ~12 sub-routes, branched on inside that one function) are invisible to
 *      any index.js-level extraction — this script can only report that the
 *      prefix exists and, best-effort, which handler function picks it up.
 *
 * This script surfaces all three so nobody mistakes idiom #1's count for the
 * whole picture. Every handler reached only via idiom 3 should be marked
 * routes_fully_enumerated: false in its registry entry (see SCHEMA.md §2) —
 * that flag is the honesty mechanism, not a claim this script resolves.
 *
 * No dependency (plain Node.js, regex-based) — matches this repo's existing
 * scripts/ convention (see scripts/d1-schema-diff.mjs's own "no dependencies"
 * header).
 *
 * Usage:
 *   node scripts/registry/extract-routes.mjs           # human-readable summary
 *   node scripts/registry/extract-routes.mjs --json     # full JSON to stdout
 *
 * Exit codes: 0 always (read/report tool only).
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const INDEX_PATH = resolve(process.cwd(), 'workers/src/index.js');
const src = readFileSync(INDEX_PATH, 'utf8');

// ── Idiom 1: sequential if-chain (same regex as routeLineageGuard.test.mjs) ──
function extractIfChainRoutes(text) {
  const RE = /path === '([^']+)'\s*&&\s*method === '([A-Z]+)'/g;
  const routes = [];
  let m;
  while ((m = RE.exec(text)) !== null) {
    routes.push({ path: m[1], method: m[2], evidence: lineOf(text, m.index) });
  }
  return routes;
}

// ── Idiom 2: object-literal route tables (e.g. SYNC_ROUTES) ──
function extractObjectTableRoutes(text) {
  const RE = /'([A-Z]+)\s+(\/[^']+)':\s*\{\s*handler:\s*([A-Za-z0-9_$]+)/g;
  const routes = [];
  let m;
  while ((m = RE.exec(text)) !== null) {
    routes.push({ method: m[1], path: m[2], handlerFn: m[3], evidence: lineOf(text, m.index) });
  }
  return routes;
}

// ── Idiom 3a: path.startsWith('<prefix>') dispatchers ──
function extractPrefixDispatchers(text) {
  const RE = /path\.startsWith\((['"])([^'"]+)\1\)/g;
  const out = [];
  let m;
  while ((m = RE.exec(text)) !== null) {
    out.push({ prefix: m[2], handlerFn: nearbyHandlerCall(text, m.index), evidence: lineOf(text, m.index) });
  }
  return out;
}

// ── Idiom 3b: path.match(/regex/) dispatchers ──
function extractRegexDispatchers(text) {
  const RE = /path\.match\(\s*\/(\^[^/]*(?:\\\/[^/]*)*)\//g;
  const out = [];
  let m;
  while ((m = RE.exec(text)) !== null) {
    out.push({ pattern: m[1], handlerFn: nearbyHandlerCall(text, m.index), evidence: lineOf(text, m.index) });
  }
  return out;
}

function nearbyHandlerCall(text, index, window = 400) {
  const slice = text.slice(index, index + window);
  const m = /\b(handle[A-Za-z0-9_]*)\s*\(/.exec(slice);
  return m ? m[1] : null; // null = could not associate mechanically; needs manual read
}

function lineOf(text, index) {
  const line = text.slice(0, index).split('\n').length;
  return `workers/src/index.js:${line}`;
}

function main() {
  const ifChain = extractIfChainRoutes(src);
  const objectTable = extractObjectTableRoutes(src);
  const prefixDispatch = extractPrefixDispatchers(src);
  const regexDispatch = extractRegexDispatchers(src);

  const result = {
    generated: new Date().toISOString(),
    source: 'workers/src/index.js',
    counts: {
      ifChainRoutes: ifChain.length,
      objectTableRoutes: objectTable.length,
      prefixDispatchers: prefixDispatch.length,
      regexDispatchers: regexDispatch.length,
    },
    note: 'ifChainRoutes + objectTableRoutes are concrete (path,method) pairs. prefixDispatchers/regexDispatchers are ENTRY POINTS ONLY — the routes inside the dispatched handler are not enumerated here; mark routes_fully_enumerated:false for those handlers in the registry.',
    ifChainRoutes: ifChain,
    objectTableRoutes: objectTable,
    prefixDispatchers: prefixDispatch,
    regexDispatchers: regexDispatch,
  };

  if (process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  console.log(`If-chain routes (path === ... && method === ...): ${ifChain.length}`);
  console.log(`Object-literal table routes (e.g. SYNC_ROUTES):    ${objectTable.length}`);
  console.log(`Prefix dispatchers (path.startsWith(...)):         ${prefixDispatch.length}`);
  console.log(`Regex dispatchers (path.match(/.../)):             ${regexDispatch.length}`);
  console.log('');
  console.log(`Total concrete (path,method) pairs found: ${ifChain.length + objectTable.length}`);
  console.log(`Dispatcher entry points found (internal routes NOT enumerated): ${prefixDispatch.length + regexDispatch.length}`);
  const unresolved = [...prefixDispatch, ...regexDispatch].filter((d) => !d.handlerFn).length;
  if (unresolved) console.log(`  ⚠ ${unresolved} dispatcher(s) could not be mechanically associated with a handler function — read the surrounding code manually.`);
  console.log('');
  console.log('Run with --json for the full route/dispatcher list.');
}

main();
