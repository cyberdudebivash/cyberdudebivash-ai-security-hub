#!/usr/bin/env node
/**
 * Capability Registry validator (CEAP instrument, see
 * docs/capability-registry/SCHEMA.md). CI entry point.
 *
 * Checks, in order of severity:
 *   1. Every docs/capability-registry/domains/*.json file parses as JSON and
 *      every entry has the required shape (SCHEMA.md §2) — HARD FAIL.
 *   2. Every capability id is globally unique across all domain files —
 *      HARD FAIL.
 *   3. Every `file:line`-shaped evidence string resolves to a real file (and
 *      the line number is within that file's line count, when given) —
 *      HARD FAIL. Evidence that doesn't parse as `file:line` (free-text
 *      evidence, e.g. "grep returned 0 matches") is skipped, not penalized.
 *   4. The exact conflation that produced the false "Organizations: GA
 *      APPROVED" claim in GENERAL_AVAILABILITY_REPORT.md is now a mechanical
 *      rule, not a matter of trusting prose — HARD FAIL:
 *        a. customer_journey_complete: true requires
 *           verification.method === "dynamic_browser".
 *        b. operational_status: "GA APPROVED" requires frontend.status to be
 *           "exists" (any surface_type), navigation.discoverable === true,
 *           AND customer_journey_complete === true.
 *   5. Staleness: verification.last_verified older than 90 days — WARNING
 *      only (does not fail the build; this is the "caught same day" signal
 *      for a human/CORB review, not an automatic block).
 *
 * This is launched as an ADVISORY CI job (see .github/workflows/ci.yml,
 * `registry-validate`) — matching how `security-scan` started advisory
 * before `dependency-audit` graduated to required. Exit code reflects hard
 * failures only; run with --strict to also exit non-zero on warnings.
 *
 * No dependency (plain Node.js) — matches this repo's zero-dependency
 * scripts/ convention.
 *
 * Usage:
 *   node scripts/registry/validate.mjs             # exits 1 on hard failures only
 *   node scripts/registry/validate.mjs --strict     # exits 1 on warnings too
 *
 * Exit codes: 0 clean · 1 hard failure (or warning, under --strict) · 2 misconfigured (e.g. domains/ dir missing).
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

const REPO_ROOT = process.cwd();
const REGISTRY_DIR = join(REPO_ROOT, 'docs/capability-registry');
const DOMAINS_DIR = join(REGISTRY_DIR, 'domains');

const VALID_BACKEND_STATUS = ['exists', 'partial', 'missing', 'broken', 'deprecated', 'duplicate'];
const VALID_FRONTEND_SURFACE = ['dedicated_page', 'embedded_widget', 'modal', 'none'];
const VALID_FRONTEND_STATUS = ['exists', 'partial', 'missing', 'broken'];
const VALID_OPERATIONAL_STATUS = ['GA APPROVED', 'GA APPROVED WITH DOCUMENTED LIMITATIONS', 'PILOT ONLY', 'NOT READY', 'BLOCKED'];
const VALID_PRIORITY = ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7'];
const VALID_VERIFICATION_METHOD = ['static', 'dynamic_api', 'dynamic_browser'];
const VALID_DOC_TAG = ['canonical', 'audit-history'];
const STALE_DAYS = 90;

const errors = [];
const warnings = [];

function fail(entryId, file, msg) {
  errors.push(`[HARD FAIL] ${file} :: ${entryId || '(no id)'} :: ${msg}`);
}
function warn(entryId, file, msg) {
  warnings.push(`[WARNING] ${file} :: ${entryId || '(no id)'} :: ${msg}`);
}

function loadDomainFiles() {
  if (!existsSync(DOMAINS_DIR)) {
    console.error(`Registry domains directory not found: ${relative(REPO_ROOT, DOMAINS_DIR)}`);
    process.exit(2);
  }
  return readdirSync(DOMAINS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => join(DOMAINS_DIR, f));
}

function validateEntry(entry, relFile) {
  const id = entry && entry.id;
  const req = (cond, msg) => { if (!cond) fail(id, relFile, msg); };

  req(typeof entry.id === 'string' && entry.id.length > 0, 'missing/invalid "id"');
  req(typeof entry.domain === 'string' && entry.domain.length > 0, 'missing/invalid "domain"');
  req(typeof entry.name === 'string' && entry.name.length > 0, 'missing/invalid "name"');
  req(typeof entry.description === 'string' && entry.description.length > 0, 'missing/invalid "description"');

  const b = entry.backend || {};
  req(Array.isArray(b.handlers), 'backend.handlers must be an array');
  req(Array.isArray(b.entry_points), 'backend.entry_points must be an array');
  req(Array.isArray(b.routes_sampled), 'backend.routes_sampled must be an array');
  req(typeof b.routes_fully_enumerated === 'boolean', 'backend.routes_fully_enumerated must be boolean');
  req(VALID_BACKEND_STATUS.includes(b.status), `backend.status "${b.status}" not in ${VALID_BACKEND_STATUS.join('|')}`);

  const f = entry.frontend || {};
  req(VALID_FRONTEND_SURFACE.includes(f.surface_type), `frontend.surface_type "${f.surface_type}" not in ${VALID_FRONTEND_SURFACE.join('|')}`);
  req(Array.isArray(f.pages), 'frontend.pages must be an array');
  req(VALID_FRONTEND_STATUS.includes(f.status), `frontend.status "${f.status}" not in ${VALID_FRONTEND_STATUS.join('|')}`);
  req(typeof f.evidence === 'string' && f.evidence.length > 0, 'frontend.evidence must be a non-empty string');

  const n = entry.navigation || {};
  req(typeof n.discoverable === 'boolean' || n.discoverable === 'unknown', 'navigation.discoverable must be boolean or "unknown"');

  req(typeof entry.auth_enforced === 'boolean' || entry.auth_enforced === 'unknown', 'auth_enforced must be boolean or "unknown"');

  const r = entry.rbac || {};
  req(typeof r.enforced === 'boolean' || r.enforced === 'unknown', 'rbac.enforced must be boolean or "unknown"');
  req(Array.isArray(r.permissions), 'rbac.permissions must be an array');

  req(typeof entry.subscription_gated === 'boolean' || entry.subscription_gated === 'unknown', 'subscription_gated must be boolean or "unknown"');

  const ff = entry.feature_flag || {};
  req(typeof ff.present === 'boolean', 'feature_flag.present must be boolean');
  req(typeof ff.mechanism === 'string', 'feature_flag.mechanism must be a string');

  const tc = entry.test_coverage || {};
  req(typeof tc.has_tests === 'boolean', 'test_coverage.has_tests must be boolean');
  req(typeof tc.evidence === 'string' && tc.evidence.length > 0, 'test_coverage.evidence must be a non-empty string');

  req(Array.isArray(entry.docs), 'docs must be an array');
  for (const d of entry.docs || []) {
    req(typeof d.path === 'string', 'docs[].path must be a string');
    req(VALID_DOC_TAG.includes(d.tag), `docs[].tag "${d.tag}" not in ${VALID_DOC_TAG.join('|')}`);
  }

  req(typeof entry.customer_journey_complete === 'boolean', 'customer_journey_complete must be boolean');
  req(VALID_OPERATIONAL_STATUS.includes(entry.operational_status), `operational_status "${entry.operational_status}" not in fixed vocabulary (docs/ENGINEERING_STANDARDS.md §9)`);
  req(VALID_PRIORITY.includes(entry.priority), `priority "${entry.priority}" not in ${VALID_PRIORITY.join('|')}`);

  const v = entry.verification || {};
  req(VALID_VERIFICATION_METHOD.includes(v.method), `verification.method "${v.method}" not in ${VALID_VERIFICATION_METHOD.join('|')}`);
  req(typeof v.last_verified === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v.last_verified), 'verification.last_verified must be an ISO date (YYYY-MM-DD)');
  req(typeof v.evidence === 'string' && v.evidence.length > 0, 'verification.evidence must be a non-empty string');

  // ── Rule 4a: the Organizations/Auth conflation, made mechanical ──
  if (entry.customer_journey_complete === true && v.method !== 'dynamic_browser') {
    fail(id, relFile, `customer_journey_complete:true requires verification.method:"dynamic_browser" (got "${v.method}") — an API-only or code-read check cannot certify a customer journey`);
  }
  if (entry.operational_status === 'GA APPROVED') {
    if (f.status !== 'exists') fail(id, relFile, `operational_status:"GA APPROVED" requires frontend.status:"exists" (got "${f.status}")`);
    if (n.discoverable !== true) fail(id, relFile, 'operational_status:"GA APPROVED" requires navigation.discoverable:true');
    if (entry.customer_journey_complete !== true) fail(id, relFile, 'operational_status:"GA APPROVED" requires customer_journey_complete:true');
  }

  // ── Evidence resolution (file:line) ──
  const evidenceStrings = [
    f.evidence, n.evidence, tc.evidence, v.evidence,
    ...(b.routes_sampled || []).map((r2) => r2.evidence),
  ].filter(Boolean);
  for (const ev of evidenceStrings) checkEvidenceResolves(id, relFile, ev);

  // ── Staleness (warning only) ──
  if (typeof v.last_verified === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v.last_verified)) {
    const ageDays = (Date.now() - new Date(v.last_verified + 'T00:00:00Z').getTime()) / 86400000;
    if (ageDays > STALE_DAYS) warn(id, relFile, `verification.last_verified is ${Math.floor(ageDays)} days old (> ${STALE_DAYS}) — due for re-verification`);
  }
}

// Longer/more-specific extensions must precede shorter ones that are a
// literal prefix of them (json starts with "js") — regex alternation takes
// the first alternative that matches, so "js" before "json" in the list
// would truncate every ".json" citation to a nonexistent ".js" file.
const FILE_LINE_RE = /([A-Za-z0-9_./-]+\.(?:mjs|json|js|html|md))(?::(\d+))?/g;

function checkEvidenceResolves(id, relFile, evidenceStr) {
  let m;
  FILE_LINE_RE.lastIndex = 0;
  while ((m = FILE_LINE_RE.exec(evidenceStr)) !== null) {
    const cited = m[1];
    const lineNo = m[2] ? parseInt(m[2], 10) : null;
    const abs = resolve(REPO_ROOT, cited);
    if (!existsSync(abs)) {
      fail(id, relFile, `evidence cites "${cited}" which does not exist`);
      continue;
    }
    if (lineNo) {
      const lc = readFileSync(abs, 'utf8').split('\n').length;
      if (lineNo > lc) fail(id, relFile, `evidence cites "${cited}:${lineNo}" but the file only has ${lc} lines`);
    }
  }
}

function main() {
  const strict = process.argv.includes('--strict');
  const files = loadDomainFiles();
  const seenIds = new Map();

  for (const absFile of files) {
    const relFile = relative(REPO_ROOT, absFile).split(sep).join('/');
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(absFile, 'utf8'));
    } catch (e) {
      errors.push(`[HARD FAIL] ${relFile} :: invalid JSON (${e.message})`);
      continue;
    }
    if (!Array.isArray(parsed)) {
      errors.push(`[HARD FAIL] ${relFile} :: root element must be an array of capability entries`);
      continue;
    }
    for (const entry of parsed) {
      validateEntry(entry, relFile);
      if (entry && entry.id) {
        if (seenIds.has(entry.id)) errors.push(`[HARD FAIL] ${relFile} :: duplicate id "${entry.id}" (also in ${seenIds.get(entry.id)})`);
        else seenIds.set(entry.id, relFile);
      }
    }
  }

  console.log(`Capability Registry validation — ${files.length} domain file(s), ${seenIds.size} unique capability id(s)`);
  console.log('');
  if (errors.length) {
    console.log(`❌ ${errors.length} hard failure(s):`);
    errors.forEach((e) => console.log(`  ${e}`));
  } else {
    console.log('✅ No hard failures.');
  }
  console.log('');
  if (warnings.length) {
    console.log(`⚠️  ${warnings.length} warning(s):`);
    warnings.forEach((w) => console.log(`  ${w}`));
  } else {
    console.log('✅ No warnings.');
  }

  if (errors.length > 0 || (strict && warnings.length > 0)) process.exit(1);
  process.exit(0);
}

main();
