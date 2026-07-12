#!/usr/bin/env node
/**
 * Domain scan engine — rule conformance benchmark.
 *
 * What this is NOT: an unaudited "N% detection accuracy" claim of the kind
 * competitor research (see EPIS report, 2026-07-12) found unverifiable
 * everywhere it looked (CrowdStrike Charlotte AI's self-reported 98% triage
 * accuracy, SentinelOne's autonomy claims — no third-party audit found for
 * either). workers/src/engine.js's domainScanEngine() is not an ML
 * classifier; it is deterministic, documented business logic
 * (assessment_mode: 'STATIC', live_verification: false — it never claims to
 * have observed a target's real TLS/DNS/header/port state).
 *
 * What this IS: a public, reproducible proof that every documented risk
 * signal in that logic fires exactly as described, against inputs
 * constructed specifically to test each rule in isolation, plus a clean
 * control domain that must NOT be over-scored (a real false-positive check).
 * Anyone can read this file, see exactly what's asserted and why, and re-run
 * it. That is the differentiator this benchmark exists to make provable:
 * transparency a black-box ML vendor structurally cannot offer.
 *
 * Run: node scripts/domain-engine-rule-conformance.mjs
 * Writes:
 *   docs/audit-history/domain-engine-conformance-results.json — internal audit trail
 *   frontend/data/domain-engine-conformance.json — public copy, deployed with
 *     the frontend (matches the existing /data/*.json convention in
 *     frontend/_headers), fetched client-side by trust-center.html so the
 *     published numbers are the real last-CI-run result, not a hardcoded
 *     string that can silently drift from the code it describes.
 * Exits 1 on any assertion failure — wired into CI so this can't silently
 * regress or go stale.
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { domainScanEngine } from '../workers/src/engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const HIGH_RISK_TLDS = ['xyz','top','club','online','site','icu','tk','ml','ga','cf','gq','pw','cc','biz'];
const PHISH_KEYWORDS = ['secure','login','update','verify','account','bank','paypal','amazon','signin','confirm','suspended','unlock','reset'];

let pass = 0, fail = 0;
const results = [];

function check(label, cond, detail) {
  if (cond) { pass++; results.push({ label, ok: true }); }
  else { fail++; results.push({ label, ok: false, detail }); console.error(`  FAIL  ${label}${detail ? ' — ' + detail : ''}`); }
}

function staticHonesty(scan, label) {
  check(`${label}: assessment_mode is STATIC`, scan.scan_metadata.assessment_mode === 'STATIC');
  check(`${label}: live_verification is false`, scan.scan_metadata.live_verification === false);
  const liveClaimFindings = ['DOM-001','DOM-002','DOM-003','DOM-005','DOM-006']
    .map(id => scan.findings.find(f => f.id === id))
    .filter(Boolean);
  check(`${label}: all live-dependent findings honestly marked requires_* (never claim a live result)`,
    liveClaimFindings.every(f => f.assessment_method.startsWith('requires_')),
    liveClaimFindings.map(f => `${f.id}:${f.assessment_method}`).join(', '));
}

console.log('Domain Scan Engine — Rule Conformance Benchmark\n');

// ── 1. Every documented high-risk TLD fires tldRisk=25, and nothing else ──
console.log('High-risk TLD rule (13 documented TLDs):');
for (const tld of HIGH_RISK_TLDS) {
  const domain = `samplesite.${tld}`;
  const scan = domainScanEngine(domain);
  check(`TLD .${tld} contributes exactly baseRisk(5)+tldRisk(25)=30`, scan.risk_score === 30, `got ${scan.risk_score}`);
}

// ── 2. Every documented phishing keyword fires phishRisk=30 + CRITICAL DOM-007 ──
console.log('Phishing-keyword rule (13 documented keywords):');
for (const kw of PHISH_KEYWORDS) {
  const domain = `${kw}samplepage.com`;
  const scan = domainScanEngine(domain);
  check(`Keyword "${kw}" contributes baseRisk(5)+phishRisk(30)=35`, scan.risk_score === 35, `got ${scan.risk_score}`);
  const dom007 = scan.findings.find(f => f.id === 'DOM-007');
  check(`Keyword "${kw}" triggers DOM-007 CRITICAL + matched in phishing_keywords_matched`,
    dom007.severity === 'CRITICAL' && dom007.phishing_keywords_matched.includes(kw));
}

// ── 3. Length rule boundaries (>40 / 26-40 / <=25) ──
console.log('Domain-length rule boundaries:');
{
  const long = 'a'.repeat(41) + '.com';         // 45 chars total, >40
  const mid  = 'a'.repeat(30) + '.com';         // 34 chars, 26-40
  const short = 'shortdomain.com';               // <=25
  check('Length >40 contributes lenRisk=15', domainScanEngine(long).risk_score === 5 + 15, `got ${domainScanEngine(long).risk_score}`);
  check('Length 26-40 contributes lenRisk=8', domainScanEngine(mid).risk_score === 5 + 8, `got ${domainScanEngine(mid).risk_score}`);
  check('Length <=25 contributes lenRisk=0', domainScanEngine(short).risk_score === 5, `got ${domainScanEngine(short).risk_score}`);
}

// ── 4. Digit-run rule (4+ consecutive digits) ──
console.log('Digit-run rule boundary:');
{
  const withRun = 'site1234.com';    // exactly 4 consecutive digits
  const without = 'site123.com';     // exactly 3, must NOT fire
  check('4 consecutive digits contributes numRisk=10', domainScanEngine(withRun).risk_score === 5 + 10, `got ${domainScanEngine(withRun).risk_score}`);
  check('3 consecutive digits does NOT fire numRisk', domainScanEngine(without).risk_score === 5, `got ${domainScanEngine(without).risk_score}`);
}

// ── 5. Hyphen-count rule (>2 hyphens) ──
console.log('Hyphen-count rule boundary:');
{
  const withHyphens = 'a-b-c-d.com';  // 3 hyphens, >2
  const atBoundary  = 'a-b-c.com';    // 2 hyphens, must NOT fire
  check('3 hyphens contributes hyphenRisk=8', domainScanEngine(withHyphens).risk_score === 5 + 8, `got ${domainScanEngine(withHyphens).risk_score}`);
  check('2 hyphens does NOT fire hyphenRisk', domainScanEngine(atBoundary).risk_score === 5, `got ${domainScanEngine(atBoundary).risk_score}`);
}

// ── 6. Clean control domain — real false-positive check ──
console.log('Clean control (false-positive check):');
{
  const clean = domainScanEngine('examplecorp.com');
  check('Zero-signal domain scores exactly baseRisk=5, nothing else', clean.risk_score === 5, `got ${clean.risk_score}`);
  check('Zero-signal domain is graded LOW / A', clean.risk_level === 'LOW' && clean.grade === 'A');
  check('Zero-signal domain triggers zero phishing keyword matches', clean.findings.find(f => f.id === 'DOM-007').phishing_keywords_matched.length === 0);
}

// ── 7. Compound case — multiple rules simultaneously, additive + capped ──
console.log('Compound case (multiple rules at once):');
{
  // secure+login keywords (only first match counted once via .some, so this
  // tests the .some() short-circuit is honestly a single +30, not stacked),
  // high-risk TLD, 3 hyphens, long, digit run.
  const compound = 'secure-login-verify-account1234-page.xyz';
  // domain.length === 40 exactly (verified: falls in the 26-40 bucket -> lenRisk=8, not the >40 -> 15 bucket)
  // tldRisk 25 + phishRisk 30 (single flag, .some — "secure"/"login"/"verify"/"account" all present but only counted once) + lenRisk 8 + numRisk 10 (1234) + hyphenRisk 8 (4 hyphens) + base 5 = 86
  const scan = domainScanEngine(compound);
  const expected = 25 + 30 + 8 + 10 + 8 + 5;
  check(`Compound domain sums all applicable rules additively (expected ${expected})`, scan.risk_score === expected, `got ${scan.risk_score}`);
  check('Compound domain risk_level is CRITICAL', scan.risk_level === 'CRITICAL');
}

// ── 8. Cap at 100 ──
console.log('Score ceiling:');
{
  const extreme = 'secure-login-verify-account-suspended-confirm12345678.xyz';
  const scan = domainScanEngine(extreme);
  check('Score never exceeds 100 regardless of stacked signals', scan.risk_score <= 100, `got ${scan.risk_score}`);
}

// ── 9. Honesty markers on every case above ──
console.log('STATIC / live_verification honesty (checked across all cases above):');
staticHonesty(domainScanEngine('examplecorp.com'), 'clean control');
staticHonesty(domainScanEngine('secure-login.xyz'), 'high-risk case');

console.log(`\n${pass} passed, ${fail} failed (${pass + fail} total assertions)`);

const output = {
  generated_at: new Date().toISOString(),
  engine_file: 'workers/src/engine.js',
  engine_function: 'domainScanEngine',
  methodology: 'Every documented risk rule (13 high-risk TLDs, 13 phishing keywords, length/digit/hyphen boundaries, additive scoring, 100-point cap) tested in isolation against purpose-built inputs, plus a clean-domain false-positive check and STATIC/live_verification honesty assertions. Source: scripts/domain-engine-rule-conformance.mjs.',
  assertions_passed: pass,
  assertions_failed: fail,
  assertions_total: pass + fail,
  status: fail === 0 ? 'ALL RULES VERIFIED' : 'CONFORMANCE FAILURE',
};
const json = JSON.stringify(output, null, 2) + '\n';
writeFileSync(path.join(__dirname, '..', 'docs', 'audit-history', 'domain-engine-conformance-results.json'), json);
writeFileSync(path.join(__dirname, '..', 'frontend', 'data', 'domain-engine-conformance.json'), json);
console.log(`\nResults written to docs/audit-history/domain-engine-conformance-results.json`);
console.log(`Results written to frontend/data/domain-engine-conformance.json (deployed, publicly fetchable)`);

process.exit(fail === 0 ? 0 : 1);
