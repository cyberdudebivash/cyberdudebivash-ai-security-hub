#!/usr/bin/env node
/**
 * Capability Registry — report generator (CEAP instrument, see
 * docs/capability-registry/SCHEMA.md).
 *
 * Renders docs/capability-registry/PRODUCTION_READINESS_REPORT.md
 * deterministically from docs/capability-registry/domains/*.json. Every
 * number in the output is computed here, from the underlying entries — never
 * hand-typed. This is the fix for the specific failure mode that produced
 * GENERAL_AVAILABILITY_REPORT.md's false "100%"/"GA APPROVED" claims: a
 * generated report cannot silently drift from its source data the way a
 * hand-maintained narrative document did across 4+ prior audits.
 *
 * This file (PRODUCTION_READINESS_REPORT.md) is GENERATED — never hand-edit
 * it. Edit the domains/*.json entries and re-run this script.
 *
 * No dependency (plain Node.js) — matches this repo's zero-dependency
 * scripts/ convention.
 *
 * Usage:
 *   node scripts/registry/generate-report.mjs
 *
 * Exit codes: 0 success · 2 misconfigured (domains/ missing or empty).
 */
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const REPO_ROOT = process.cwd();
const DOMAINS_DIR = join(REPO_ROOT, 'docs/capability-registry/domains');
const OUT_PATH = join(REPO_ROOT, 'docs/capability-registry/PRODUCTION_READINESS_REPORT.md');

function loadAllEntries() {
  if (!existsSync(DOMAINS_DIR)) {
    console.error(`Missing ${relative(REPO_ROOT, DOMAINS_DIR)}`);
    process.exit(2);
  }
  const files = readdirSync(DOMAINS_DIR).filter((f) => f.endsWith('.json'));
  if (!files.length) {
    console.error('No domain files found — nothing to report.');
    process.exit(2);
  }
  const entries = [];
  for (const f of files) {
    const parsed = JSON.parse(readFileSync(join(DOMAINS_DIR, f), 'utf8'));
    for (const e of parsed) entries.push({ ...e, __domainFile: f });
  }
  return entries;
}

function pct(n, d) {
  return d === 0 ? 0 : Math.round((n / d) * 1000) / 10;
}

function scoreOf(status) {
  if (status === 'exists') return 1;
  if (status === 'partial') return 0.5;
  return 0;
}

function computeRollup(entries) {
  const total = entries.length;
  const backendScore = entries.reduce((s, e) => s + scoreOf(e.backend?.status), 0);
  const frontendScore = entries.reduce((s, e) => s + scoreOf(e.frontend?.status), 0);
  const parityCount = entries.filter((e) => e.backend?.status === 'exists' && e.frontend?.status === 'exists').length;
  const journeyCount = entries.filter((e) => e.customer_journey_complete === true).length;

  const priorityCounts = { P1: 0, P2: 0, P3: 0, P4: 0, P5: 0, P6: 0, P7: 0 };
  for (const e of entries) if (priorityCounts[e.priority] !== undefined) priorityCounts[e.priority]++;

  const hiddenFeatures = entries.filter((e) => e.backend?.status === 'exists' && e.navigation?.discoverable === false).length;
  const backendOnly = entries.filter((e) => e.backend?.status === 'exists' && e.frontend?.status === 'missing').length;
  const duplicateSystems = entries.filter((e) => e.backend?.status === 'duplicate').length;
  const brokenJourneys = entries.filter((e) => e.priority === 'P1').length;

  return {
    total,
    backendPct: pct(backendScore, total),
    frontendPct: pct(frontendScore, total),
    parityPct: pct(parityCount, total),
    journeyPct: pct(journeyCount, total),
    priorityCounts,
    critical: priorityCounts.P1,
    high: priorityCounts.P2,
    medium: priorityCounts.P3 + priorityCounts.P4,
    low: priorityCounts.P5 + priorityCounts.P6 + priorityCounts.P7,
    hiddenFeatures,
    backendOnly,
    duplicateSystems,
    brokenJourneys,
  };
}

function verdictOf(rollup) {
  if (rollup.brokenJourneys > 0) return 'NOT READY';
  if (rollup.parityPct < 80) return 'NOT READY';
  if (rollup.parityPct < 95 || rollup.high > 0) return 'GA APPROVED WITH DOCUMENTED LIMITATIONS';
  return 'GA APPROVED';
}

function byDomain(entries) {
  const map = new Map();
  for (const e of entries) {
    const d = e.domain || 'unknown';
    if (!map.has(d)) map.set(d, []);
    map.get(d).push(e);
  }
  return map;
}

function renderDomainTable(domainEntries) {
  const rows = domainEntries.map((e) => {
    const backend = e.backend?.status === 'exists' ? '✓' : e.backend?.status === 'partial' ? '◐' : '✗';
    const frontend = e.frontend?.status === 'exists' ? '✓' : e.frontend?.status === 'partial' ? '◐' : '✗';
    const nav = e.navigation?.discoverable ? '✓' : '✗';
    return `| ${e.id} | ${e.name} | ${backend} | ${frontend} | ${nav} | ${e.operational_status} | ${e.priority} |`;
  });
  return [
    '| ID | Capability | Backend | Frontend | Nav | Status | Priority |',
    '|---|---|---|---|---|---|---|',
    ...rows,
  ].join('\n');
}

function render(entries) {
  const rollup = computeRollup(entries);
  const verdict = verdictOf(rollup);
  const domains = byDomain(entries);
  const generatedAt = new Date().toISOString();

  const domainSections = [...domains.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([domain, list]) => `### ${domain} (${list.length} capabilit${list.length === 1 ? 'y' : 'ies'})\n\n${renderDomainTable(list)}`)
    .join('\n\n');

  return `# Enterprise Production Readiness Report

> **GENERATED FILE — do not hand-edit.** Produced by
> \`scripts/registry/generate-report.mjs\` from
> \`docs/capability-registry/domains/*.json\`. Every number below is computed
> from those entries. To change a number here, correct the underlying
> registry entry (with real evidence) and re-run the generator — never edit
> this file directly. This is the CEAP instrument described in
> \`docs/ENGINEERING_STANDARDS.md\` §10/§12; it does not replace
> \`KPI_DASHBOARD.md\` (the outcome scoreboard) — this report measures
> structural completeness and parity, not customer outcomes.

Generated: ${generatedAt}
Capabilities catalogued: ${rollup.total}

## Overall Completion

| Dimension | % |
|---|---|
| Backend | ${rollup.backendPct}% |
| Frontend | ${rollup.frontendPct}% |
| Parity (backend **and** frontend both exist) | ${rollup.parityPct}% |
| Customer Journeys complete (dynamic_browser-verified) | ${rollup.journeyPct}% |

## Gaps by Priority

| Severity | Priority | Count | Meaning |
|---|---|---|---|
| Critical | P1 | ${rollup.critical} | Broken customer journey |
| High | P2 | ${rollup.priorityCounts.P2} | Backend exists, frontend missing |
| Medium | P3 | ${rollup.priorityCounts.P3} | Backend+frontend exist, navigation missing |
| Medium | P4 | ${rollup.priorityCounts.P4} | RBAC not enforced |
| Low | P5 | ${rollup.priorityCounts.P5} | Subscription gating missing |
| Low | P6 | ${rollup.priorityCounts.P6} | No test coverage |
| Low | P7 | ${rollup.priorityCounts.P7} | Documentation missing |

**Rollup:** Critical ${rollup.critical} · High ${rollup.high} · Medium ${rollup.medium} · Low ${rollup.low}

## Structural Findings

| Metric | Count | Definition |
|---|---|---|
| Hidden features | ${rollup.hiddenFeatures} | Backend exists, but not discoverable via navigation |
| Backend-only features | ${rollup.backendOnly} | Backend exists, zero frontend surface |
| Duplicate systems | ${rollup.duplicateSystems} | Backend marked \`duplicate\` (two implementations of one capability) |
| Broken journeys | ${rollup.brokenJourneys} | Priority P1 |

## Production Readiness Verdict: **${verdict}**

Computed, not asserted: NOT READY if any broken journey (P1) exists or
parity is below 80%; GA APPROVED WITH DOCUMENTED LIMITATIONS if parity is
below 95% or any P2 (backend-only) gaps remain; GA APPROVED otherwise. Uses
the fixed vocabulary from \`docs/ENGINEERING_STANDARDS.md\` §9 — never "100%
complete", "bug free", or "guaranteed".

## Capabilities by Domain

${domainSections}

---
*Regenerate with \`node scripts/registry/generate-report.mjs\` after any
change to \`docs/capability-registry/domains/*.json\`.*
`;
}

function main() {
  const entries = loadAllEntries();
  const md = render(entries);
  writeFileSync(OUT_PATH, md, 'utf8');
  console.log(`Wrote ${relative(REPO_ROOT, OUT_PATH)} (${entries.length} capabilities across ${new Set(entries.map((e) => e.domain)).size} domains)`);
}

main();
