/**
 * Attack Library — live ingestion from the real MITRE ATLAS technique catalog
 *
 * The /attack-library page was wired to D1 in v44, but the table was only
 * ever seeded once with 11 hand-picked techniques and nothing refreshed it —
 * same staleness pattern fixed for /agent-threats via agentThreatIngestion.js.
 * This pulls the real, currently-published ATLAS technique set (170+
 * techniques across 16 tactics as of v6) so the library actually grows.
 *
 * Data format verified directly (2026-06-29) against the live repo:
 * https://github.com/mitre-atlas/atlas-data — dist/ATLAS.yaml is the
 * deprecated legacy export (last content update pre-v6); the canonical,
 * actively-maintained machine-readable export is
 * dist/v6/ATLAS-<version>.yaml, with dist/v6/ATLAS-latest.yaml a git
 * symlink whose raw content IS the target filename (not a redirect) —
 * resolved as a two-step fetch below. v6 techniques carry no per-technique
 * tactic field (confirmed by inspection), so the legacy file's
 * matrices[].techniques[].tactics arrays are used purely as a tactic
 * lookup table for technique IDs that still exist in both — this keeps
 * working even after the legacy file stops being touched, since tactic
 * categorization (unlike technique content) doesn't change after the fact.
 */

import { load } from 'js-yaml';

const V6_BASE     = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/';
const LEGACY_URL  = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml';
const FALLBACK_V6_FILE = 'ATLAS-2026.05.yaml'; // last verified-good snapshot if the latest-pointer ever fails to resolve

// ATLAS tactic ID -> our schema's category enum (see schema_v44b migration).
const TACTIC_CATEGORY = {
  'AML.TA0000': 'model-abuse',          // AI Model Access
  'AML.TA0001': 'ai-attack-staging',    // AI Attack Staging
  'AML.TA0002': 'reconnaissance',
  'AML.TA0003': 'resource-development',
  'AML.TA0004': 'initial-access',
  'AML.TA0005': 'execution',
  'AML.TA0006': 'persistence',
  'AML.TA0007': 'defense-evasion',
  'AML.TA0008': 'discovery',
  'AML.TA0009': 'collection',
  'AML.TA0010': 'data-exfil',           // Exfiltration
  'AML.TA0011': 'impact',
  'AML.TA0012': 'privilege-escalation',
  'AML.TA0013': 'credential-access',
  'AML.TA0014': 'command-and-control',
  'AML.TA0015': 'lateral-movement',
};

// Narrower, attack-pattern-based categories take priority over the tactic
// fallback when the technique name clearly matches one of the page's
// original LLM-specific buckets (verified 2026-06-29 against the real v6
// catalog — e.g. AML.T0051 "LLM Prompt Injection", AML.T0054 "LLM Jailbreak",
// AML.T0070 "RAG Poisoning" all match cleanly).
const KEYWORD_CATEGORY = [
  [/jailbreak/i, 'jailbreak'],
  [/prompt injection/i, 'prompt-injection'],
  [/\brag\b|retrieval/i, 'rag-poisoning'],
  [/exfiltrat/i, 'data-exfil'],
  [/\bagent\b/i, 'agent-takeover'],
];

const SEVERITY_BY_MATURITY = { Realized: 'HIGH', Demonstrated: 'MEDIUM', Feasible: 'LOW' };
const ICON_BY_CATEGORY = {
  'prompt-injection': '💉', jailbreak: '🎭', 'agent-takeover': '🤖',
  'rag-poisoning': '☣️', 'data-exfil': '📤', 'model-abuse': '🧬',
};

function categoryFor(name, tacticIds) {
  for (const [re, cat] of KEYWORD_CATEGORY) if (re.test(name)) return cat;
  for (const tid of tacticIds) if (TACTIC_CATEGORY[tid]) return TACTIC_CATEGORY[tid];
  return 'model-abuse';
}

function cleanDescription(desc) {
  return (desc || '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // markdown links -> plain text
    .trim();
}

async function resolveV6Filename() {
  try {
    const res = await fetch(V6_BASE + 'ATLAS-latest.yaml', { signal: AbortSignal.timeout(10000) });
    if (res.ok) {
      const ptr = (await res.text()).trim();
      if (/^ATLAS-[\d.]+\.yaml$/.test(ptr)) return ptr;
    }
  } catch { /* fall through to fallback */ }
  return FALLBACK_V6_FILE;
}

async function fetchYaml(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return load(await res.text());
}

// Builds technique_id -> [tactic_id, ...] from the legacy export's nested
// matrices[].techniques[] structure, with subtechniques inheriting their
// parent's tactics (standard ATLAS/ATT&CK convention; confirmed 100% v6
// coverage this way on 2026-06-29).
function buildTacticMap(legacyDoc) {
  const map = {};
  for (const matrix of legacyDoc.matrices || []) {
    for (const t of matrix.techniques || []) map[t.id] = t.tactics || [];
  }
  return (id) => {
    if (map[id]?.length) return map[id];
    if (id.includes('.')) {
      const parent = id.split('.').slice(0, 2).join('.');
      if (map[parent]?.length) return map[parent];
    }
    return [];
  };
}

export async function ingestAttackLibraryTechniques(env) {
  if (!env.DB) return { inserted: 0, skipped: 0, errors: ['no DB binding'] };

  let v6doc, legacyDoc;
  try {
    const filename = await resolveV6Filename();
    v6doc = await fetchYaml(V6_BASE + filename);
  } catch (e) {
    return { inserted: 0, skipped: 0, errors: [`ATLAS v6 fetch/parse failed: ${e.message}`] };
  }

  let getTactics = () => [];
  try {
    legacyDoc = await fetchYaml(LEGACY_URL);
    getTactics = buildTacticMap(legacyDoc);
  } catch (e) {
    // Non-fatal — categorization falls back to keyword matching + a generic
    // bucket; the technique data itself (the part that actually matters) is
    // unaffected.
  }

  let inserted = 0;
  let skipped = 0;
  const errors = [];

  for (const [id, t] of Object.entries(v6doc.techniques || {})) {
    try {
      const tactics  = getTactics(id);
      const category = categoryFor(t.name || '', tactics);
      const severity = SEVERITY_BY_MATURITY[t.maturity] || 'MEDIUM';
      const icon     = ICON_BY_CATEGORY[category] || '🎯';
      const tags     = JSON.stringify(['MITRE ATLAS', t.maturity, ...tactics].filter(Boolean));

      const result = await env.DB.prepare(
        `INSERT OR IGNORE INTO attack_library_techniques
          (technique_id, name, category, severity, icon, description, tags,
           mitre_atlas_id, published_at, source)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'mitre_atlas_v6')`
      ).bind(
        id,
        t.name,
        category,
        severity,
        icon,
        cleanDescription(t.description) || t.name,
        tags,
        id,
        t['created-date'] || new Date().toISOString(),
      ).run();

      if (result.meta?.rows_written > 0) inserted += 1;
      else skipped += 1;
    } catch (e) {
      errors.push(`${id}: ${e.message}`);
    }
  }

  return { inserted, skipped, errors, total_in_source: Object.keys(v6doc.techniques || {}).length };
}
