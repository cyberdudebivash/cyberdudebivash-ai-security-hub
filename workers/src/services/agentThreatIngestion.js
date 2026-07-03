/**
 * Agent Threat Advisories — live ingestion from GitHub Security Advisories (GHSA)
 *
 * The /agent-threats page and its API (agentThreatAdvisories.js) were wired to
 * D1 in v43, but the table was only ever seeded once with 5 fixed rows and
 * nothing refreshed it — every visitor saw the same "1y ago" advisories
 * forever. This pulls real, currently-published GHSA records for the tracked
 * agent frameworks so the feed actually grows over time.
 *
 * GitHub's public advisories REST endpoint requires no auth for reads
 * (unauthenticated rate limit: 60 req/hr by IP — fine for a handful of
 * packages on a daily cron).
 */

const TRACKED_PACKAGES = [
  { framework: 'langchain', ecosystem: 'pip', affects: 'langchain' },
  { framework: 'crewai',    ecosystem: 'pip', affects: 'crewai' },
  { framework: 'autogen',   ecosystem: 'pip', affects: 'pyautogen' },
  { framework: 'openai',    ecosystem: 'pip', affects: 'openai-agents' },
  { framework: 'mcp',       ecosystem: 'pip', affects: 'mcp' },
  { framework: 'mcp',       ecosystem: 'npm', affects: '@modelcontextprotocol/sdk' },
  { framework: 'llama_index', ecosystem: 'pip', affects: 'llama-index' },
];

function mapSeverity(ghsaSeverity) {
  const s = (ghsaSeverity || '').toUpperCase();
  return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s) ? s : 'MEDIUM';
}

function mapPatchStatus(vulns) {
  const anyPatched = (vulns || []).some(v => v.first_patched_version?.identifier);
  return anyPatched ? 'patched' : 'no_patch';
}

function firstPatchedVersion(vulns) {
  for (const v of vulns || []) {
    if (v.first_patched_version?.identifier) return v.first_patched_version.identifier;
  }
  return null;
}

function affectedVersionsLabel(vulns) {
  return (vulns || [])
    .map(v => v.vulnerable_version_range)
    .filter(Boolean)
    .join(', ') || null;
}

async function fetchAdvisoriesFor(pkg) {
  const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(pkg.ecosystem)}&affects=${encodeURIComponent(pkg.affects)}&per_page=15`;
  const res = await fetch(url, {
    headers: {
      'User-Agent': 'CyberDudeBivash-AI-Security-Hub',
      Accept: 'application/vnd.github+json',
    },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`GitHub advisories HTTP ${res.status} for ${pkg.affects}`);
  return res.json();
}

// ─── Self-healing schema ──────────────────────────────────────────────────────
// agent_threat_advisories is defined only in schema_v43_agent_threat_advisories.sql,
// which — like schema_master.sql — is applied solely via the manual, gated
// db-migrate.yml workflow_dispatch (typed "APPLY" confirmation required) and
// has zero runs against production. Without this, every INSERT below throws
// "no such table", is swallowed by its own try/catch, and this real, working
// daily GHSA ingestion never actually writes anything.
export async function ensureAgentThreatAdvisoriesTable(db) {
  try {
    await db.prepare(`CREATE TABLE IF NOT EXISTS agent_threat_advisories (
      id                 TEXT    PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
      advisory_id        TEXT    NOT NULL UNIQUE,
      title              TEXT    NOT NULL,
      description        TEXT    NOT NULL,
      framework          TEXT    NOT NULL,
      affected_versions  TEXT,
      affected_products  TEXT,
      severity           TEXT    NOT NULL DEFAULT 'MEDIUM',
      cvss_score         REAL,
      owasp_llm_id       TEXT,
      cwe_id             TEXT,
      mitre_atlas_id     TEXT,
      tags               TEXT    NOT NULL DEFAULT '[]',
      patch_status       TEXT    NOT NULL DEFAULT 'no_patch',
      patch_version      TEXT,
      published_at       TEXT    NOT NULL,
      updated_at         TEXT    NOT NULL DEFAULT (datetime('now')),
      created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
      source             TEXT    NOT NULL DEFAULT 'cyberdudebivash_research',
      is_new             INTEGER NOT NULL DEFAULT 0,
      full_advisory_url  TEXT
    )`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_agt_adv_framework ON agent_threat_advisories(framework)`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_agt_adv_severity ON agent_threat_advisories(severity)`).run();
    await db.prepare(`CREATE INDEX IF NOT EXISTS idx_agt_adv_published ON agent_threat_advisories(published_at DESC)`).run();
  } catch { /* best-effort; INSERT/UPDATE below already catch their own errors */ }
}

export async function ingestAgentThreatAdvisories(env) {
  if (!env.DB) return { inserted: 0, skipped: 0, errors: ['no DB binding'] };
  await ensureAgentThreatAdvisoriesTable(env.DB);

  let inserted = 0;
  let skipped = 0;
  const errors = [];

  for (const pkg of TRACKED_PACKAGES) {
    let advisories;
    try {
      advisories = await fetchAdvisoriesFor(pkg);
    } catch (e) {
      errors.push(`${pkg.affects}: ${e.message}`);
      continue;
    }

    for (const a of advisories || []) {
      try {
        const vulns = a.vulnerabilities || [];
        const cwe_id = (a.cwes || [])[0]?.cwe_id || null;
        const tags = JSON.stringify([pkg.framework, ...(a.cwes || []).map(c => c.cwe_id)].filter(Boolean));

        const result = await env.DB.prepare(
          `INSERT OR IGNORE INTO agent_threat_advisories
            (advisory_id, title, description, framework, affected_versions, affected_products,
             severity, cvss_score, cwe_id, tags, patch_status, patch_version, published_at,
             source, full_advisory_url, is_new)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
        ).bind(
          a.ghsa_id,
          a.summary || a.ghsa_id,
          a.description || a.summary || 'See full advisory for details.',
          pkg.framework,
          affectedVersionsLabel(vulns),
          pkg.affects,
          mapSeverity(a.severity),
          a.cvss?.score ?? null,
          cwe_id,
          tags,
          mapPatchStatus(vulns),
          firstPatchedVersion(vulns),
          a.published_at || new Date().toISOString(),
          'github_advisory',
          a.html_url || null,
        ).run();

        if (result.meta?.rows_written > 0) inserted += 1;
        else skipped += 1;
      } catch (e) {
        errors.push(`${a.ghsa_id || 'unknown'}: ${e.message}`);
      }
    }
  }

  // Advisories older than 14 days are no longer "new" badge material.
  try {
    await env.DB.prepare(
      `UPDATE agent_threat_advisories SET is_new = 0
       WHERE is_new = 1 AND published_at < datetime('now', '-14 days')`
    ).run();
  } catch (e) {
    errors.push(`is_new cleanup: ${e.message}`);
  }

  return { inserted, skipped, errors };
}
