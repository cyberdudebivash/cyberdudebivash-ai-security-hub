/**
 * CYBERDUDEBIVASH AI Security Hub — AI-Specific Threat Intelligence Filter v1.0
 *
 * Does NOT make its own network calls — it runs after the generic CTI pipeline
 * (threatIngestion.js: NVD + CISA KEV + GitHub Advisories) on the same cron
 * invocation, and filters those already-fetched, already-real entries for
 * AI/LLM-ecosystem relevance. This avoids adding new outbound fetches (no extra
 * NVD rate-limit pressure) while giving the AI threat feed live, source-attributed
 * data instead of only the static curated library in handlers/aiThreatIntel.js.
 *
 * Every row written has a real CVE ID or real GHSA URL traceable to NVD, CISA
 * KEV, or the GitHub Advisory Database — no synthetic or invented entries.
 */

// ─── AI/LLM ecosystem keywords — precise product/concept names only ──────────
// Deliberately avoids generic words ("model", "agent", "chat") that would
// misclassify unrelated CVEs. Matched as case-insensitive substrings against
// title + description + affected_products.
const AI_KEYWORDS = [
  'langchain', 'llamaindex', 'llama-index', 'llama index', 'huggingface', 'hugging face',
  'transformers library', 'pytorch', 'tensorflow', 'openai', 'anthropic', 'claude ai',
  'chatgpt', 'gpt-4', 'gpt-3', 'gpt-5', 'gemini ai', 'google gemini', 'mistral ai',
  'microsoft copilot', 'github copilot', 'stable diffusion', 'midjourney', 'ollama',
  'vllm', 'triton inference server', 'onnx runtime', 'mlflow', 'weights & biases', 'wandb',
  'ray serve', 'gradio', 'pinecone', 'weaviate', 'milvus', 'chromadb', 'chroma db',
  'embedchain', 'autogen', 'crewai', 'semantic kernel', 'langgraph', 'large language model',
  'llm agent', 'llm application', 'llm-based', 'vector database', 'retrieval-augmented',
  'rag pipeline', 'prompt injection', 'jailbreak', 'model poisoning', 'model theft',
  'model extraction', 'adversarial example', 'training data poisoning', 'ai model',
  'machine learning model', 'neural network', 'mcp server', 'model context protocol',
];

// ─── OWASP LLM Top 10 (2025) — real published taxonomy ────────────────────────
// Source: https://owasp.org/www-project-top-10-for-large-language-model-applications/
// Heuristic keyword mapping — only applied when confident, left null otherwise.
const OWASP_LLM_MAP = [
  { ref: 'LLM01', terms: ['prompt injection', 'jailbreak', 'indirect injection'] },
  { ref: 'LLM02', terms: ['sensitive information disclosure', 'data leak', 'pii exposure'] },
  { ref: 'LLM03', terms: ['supply chain', 'dependency', 'third-party model', 'malicious model'] },
  { ref: 'LLM04', terms: ['data poisoning', 'model poisoning', 'training data poisoning'] },
  { ref: 'LLM05', terms: ['improper output handling', 'output sanitization', 'unsafe output'] },
  { ref: 'LLM06', terms: ['excessive agency', 'excessive permission', 'tool permission'] },
  { ref: 'LLM07', terms: ['system prompt leak', 'system prompt disclosure'] },
  { ref: 'LLM08', terms: ['embedding', 'vector database', 'vector store weakness'] },
  { ref: 'LLM09', terms: ['misinformation', 'hallucination'] },
  { ref: 'LLM10', terms: ['unbounded consumption', 'resource exhaustion', 'denial of service'] },
];

export function isAIRelated(entry) {
  let affectedProducts = [];
  try {
    const parsed = JSON.parse(entry.affected_products || '[]');
    if (Array.isArray(parsed)) affectedProducts = parsed;
  } catch { /* leave empty */ }

  const haystack = [
    entry.title || '',
    entry.description || '',
    affectedProducts.join(' '),
  ].join(' ').toLowerCase();

  const matched = AI_KEYWORDS.filter(kw => haystack.includes(kw));
  return { matched: matched.length > 0, matchedKeywords: matched, haystack };
}

export function mapToOwaspLLM(haystack) {
  for (const { ref, terms } of OWASP_LLM_MAP) {
    if (terms.some(t => haystack.includes(t))) return ref;
  }
  return null;
}

// ─── MITRE ATLAS — AI/ML-specific extension of ATT&CK (https://atlas.mitre.org) ─
// Only the techniques we have high confidence are stable, published ATLAS IDs are
// included. Heuristic keyword mapping — only applied when confident, left null
// otherwise, same convention as OWASP_LLM_MAP. Should be re-verified against the
// live ATLAS matrix periodically since MITRE revises technique numbering.
const MITRE_ATLAS_MAP = [
  { ref: 'AML.T0051', terms: ['prompt injection', 'indirect injection', 'indirect prompt injection'] },
  { ref: 'AML.T0054', terms: ['jailbreak'] },
  { ref: 'AML.T0057', terms: ['system prompt leak', 'system prompt disclosure', 'sensitive information disclosure', 'data leak', 'pii exposure'] },
  { ref: 'AML.T0018', terms: ['rlhf backdoor', 'trojan model', 'backdoor', 'model poisoning'] },
  { ref: 'AML.T0020', terms: ['training data poisoning', 'data poisoning'] },
  { ref: 'AML.T0010', terms: ['supply chain', 'malicious model', 'third-party model'] },
  { ref: 'AML.T0029', terms: ['denial of service', 'resource exhaustion', 'unbounded consumption'] },
  { ref: 'AML.T0024', terms: ['model extraction', 'model theft', 'inference api'] },
  { ref: 'AML.T0043', terms: ['adversarial example'] },
];

export function mapToMitreAtlas(haystack) {
  for (const { ref, terms } of MITRE_ATLAS_MAP) {
    if (terms.some(t => haystack.includes(t))) return ref;
  }
  return null;
}

// ─── MITRE ATT&CK Enterprise — general (non-AI-specific) tactics/techniques ───
// (https://attack.mitre.org). Deliberately a small, conservative list: most
// entries here are AI/LLM-specific and already covered by MITRE ATLAS above;
// this only fires for the subset of entries that also describe general
// infrastructure-level attack behavior alongside the AI angle.
const MITRE_ATTACK_MAP = [
  { ref: 'T1071', terms: ['command and control', 'botnet'] },
  { ref: 'T1059', terms: ['arbitrary code execution', 'remote code execution', 'code execution'] },
  { ref: 'T1190', terms: ['ssrf', 'server-side request forgery'] },
  { ref: 'T1499', terms: ['denial of service'] },
  { ref: 'T1078', terms: ['account takeover', 'unauthorized access'] },
];

export function mapToMitreAttack(haystack) {
  for (const { ref, terms } of MITRE_ATTACK_MAP) {
    if (terms.some(t => haystack.includes(t))) return ref;
  }
  return null;
}

// ─── feed_type classification — matches the enum documented in schema_master.sql
// (vulnerability | attack_pattern | malware | prompt_attack | agent_threat | advisory)
// and the public `type` query param exposed by handlers/aiThreatIntel.js, so rows
// land in the bucket the API/frontend actually filter by.
const PROMPT_ATTACK_TERMS = ['prompt injection', 'jailbreak', 'indirect injection'];
const AGENT_THREAT_TERMS = [
  'llm agent', 'llm application', 'mcp server', 'model context protocol',
  'autogen', 'crewai', 'semantic kernel', 'langgraph', 'excessive agency', 'tool permission',
];

export function classifyFeedType(haystack, isCve) {
  if (PROMPT_ATTACK_TERMS.some(t => haystack.includes(t))) return 'prompt_attack';
  if (AGENT_THREAT_TERMS.some(t => haystack.includes(t))) return 'agent_threat';
  return isCve ? 'vulnerability' : 'advisory';
}

function toUnixEpoch(dateStr) {
  if (!dateStr) return Math.floor(Date.now() / 1000);
  const t = Date.parse(dateStr);
  return Number.isNaN(t) ? Math.floor(Date.now() / 1000) : Math.floor(t / 1000);
}

// ─── Self-healing table guard — converges schema if schema_v28 wasn't applied ─
export async function ensureAIThreatFeedTable(db) {
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS ai_threat_feed (
        id              TEXT PRIMARY KEY,
        feed_type       TEXT NOT NULL DEFAULT 'vulnerability',
        title           TEXT NOT NULL DEFAULT '',
        description     TEXT NOT NULL DEFAULT '',
        severity        TEXT NOT NULL DEFAULT 'MEDIUM',
        cve_id          TEXT,
        affected_models TEXT DEFAULT '[]',
        affected_frameworks TEXT DEFAULT '[]',
        iocs            TEXT DEFAULT '[]',
        mitigations     TEXT DEFAULT '[]',
        owasp_ref       TEXT,
        source_url      TEXT,
        published_at    INTEGER NOT NULL DEFAULT (unixepoch()),
        created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
        metadata        TEXT DEFAULT '{}'
      )
    `).run();
  } catch { /* already exists */ }
  // Additive columns for tables created before MITRE ATT&CK/ATLAS mapping shipped.
  for (const col of ['attack_ref TEXT', 'atlas_ref TEXT']) {
    try { await db.prepare(`ALTER TABLE ai_threat_feed ADD COLUMN ${col}`).run(); } catch { /* already exists */ }
  }
}

// ─── Filter already-fetched CTI entries for AI relevance, upsert matches ─────
export async function runAIThreatIngestion(env, candidateEntries = []) {
  const db = env?.DB;
  const result = { matched: 0, inserted: 0, errors: [] };
  if (!db || !candidateEntries.length) return result;

  await ensureAIThreatFeedTable(db);

  const matches = [];
  for (const entry of candidateEntries) {
    let check;
    try {
      check = isAIRelated(entry);
    } catch {
      continue;
    }
    if (!check.matched || !entry.id) continue;

    const owaspRef = mapToOwaspLLM(check.haystack);
    const attackRef = mapToMitreAttack(check.haystack);
    const atlasRef = mapToMitreAtlas(check.haystack);
    const isCve = /^CVE-\d{4}-\d{4,}$/.test(entry.id);

    matches.push({
      id: `ai_${entry.id}`,
      feed_type: classifyFeedType(check.haystack, isCve),
      title: (entry.title || entry.id || '').slice(0, 200),
      description: (entry.description || '').slice(0, 500),
      severity: entry.severity || 'MEDIUM',
      cve_id: isCve ? entry.id : null,
      affected_frameworks: JSON.stringify(check.matchedKeywords),
      iocs: typeof entry.iocs === 'string' ? entry.iocs : JSON.stringify(entry.iocs || []),
      mitigations: entry.required_action ? JSON.stringify([entry.required_action]) : '[]',
      owasp_ref: owaspRef,
      attack_ref: attackRef,
      atlas_ref: atlasRef,
      source_url: entry.source_url || null,
      published_at: toUnixEpoch(entry.published_at),
      metadata: JSON.stringify({ ingested_from: 'cti_pipeline_filter', source: entry.source || null, matched_keywords: check.matchedKeywords }),
    });
  }

  result.matched = matches.length;
  if (!matches.length) return result;

  const upsertResult = await upsertAIThreatFeedRows(db, matches);
  result.inserted = upsertResult.inserted;
  result.errors.push(...upsertResult.errors);
  return result;
}

// ─── Shared batch upsert — used by the passive CTI-filter pipeline above AND
// by the dedicated AI Threat Radar (services/aiThreatRadar.js), so both
// ingestion paths converge on one write path/schema/conflict-resolution rule. ─
export async function upsertAIThreatFeedRows(db, matches = []) {
  const result = { inserted: 0, errors: [] };
  if (!db || !matches.length) return result;

  const upsertSql = `
    INSERT INTO ai_threat_feed
      (id, feed_type, title, description, severity, cve_id, affected_frameworks,
       iocs, mitigations, owasp_ref, attack_ref, atlas_ref, source_url, published_at, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      severity    = CASE WHEN excluded.severity = 'CRITICAL' THEN 'CRITICAL' ELSE ai_threat_feed.severity END,
      owasp_ref   = COALESCE(excluded.owasp_ref, ai_threat_feed.owasp_ref),
      attack_ref  = COALESCE(excluded.attack_ref, ai_threat_feed.attack_ref),
      atlas_ref   = COALESCE(excluded.atlas_ref, ai_threat_feed.atlas_ref),
      source_url  = COALESCE(excluded.source_url, ai_threat_feed.source_url),
      metadata    = excluded.metadata
  `;
  const bindArgs = (m) => [
    m.id, m.feed_type, m.title, m.description, m.severity, m.cve_id,
    m.affected_frameworks, m.iocs, m.mitigations, m.owasp_ref, m.attack_ref, m.atlas_ref,
    m.source_url, m.published_at, m.metadata,
  ];

  const BATCH = 25;
  for (let i = 0; i < matches.length; i += BATCH) {
    const batch = matches.slice(i, i + BATCH);
    const stmts = batch.map(m => db.prepare(upsertSql).bind(...bindArgs(m)));
    try {
      await db.batch(stmts);
      result.inserted += batch.length;
    } catch (e) {
      result.errors.push(`Batch ${i / BATCH}: ${e.message}`);
      // Fallback: same data, one row at a time, so one bad row doesn't drop
      // the other 24 — mirrors the resilience tier already used in storeInD1.
      for (const m of batch) {
        try {
          await db.prepare(upsertSql).bind(...bindArgs(m)).run();
          result.inserted += 1;
        } catch (e2) {
          result.errors.push(`Entry ${m.id}: ${e2.message}`);
        }
      }
    }
  }

  return result;
}
